import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import gateway.channel_directory as channel_directory
import gateway.run as gateway_run
from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms.base import BasePlatformAdapter
from gateway.run import GatewayRunner


PHOTON = Platform("photon")


class _FakePhotonAdapter(BasePlatformAdapter):
    def __init__(self, config: PlatformConfig | None = None):
        super().__init__(config or PlatformConfig(enabled=True), PHOTON)
        self.connected = False
        self.disconnected = False

    async def connect(self) -> bool:
        self.connected = True
        self._mark_connected()
        return True

    async def disconnect(self) -> None:
        self.disconnected = True
        self._mark_disconnected()

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        raise NotImplementedError

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}


def _make_reload_runner() -> GatewayRunner:
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(platforms={PHOTON: PlatformConfig(enabled=True)})
    runner.adapters = {}
    runner.delivery_router = SimpleNamespace(config=runner.config, adapters=runner.adapters)
    runner._failed_platforms = {}
    runner._platform_reload_locks = {}
    runner.session_store = object()
    runner._busy_text_mode = "interrupt"
    runner._update_platform_runtime_status = lambda *args, **kwargs: None
    runner._sync_voice_mode_state_to_adapter = lambda adapter: None
    return runner


@pytest.mark.asyncio
async def test_reload_photon_replaces_adapter_and_reloads_env(monkeypatch):
    runner = _make_reload_runner()
    old_adapter = _FakePhotonAdapter()
    new_config = PlatformConfig(enabled=True, extra={"project_id": "new-project"})
    new_adapter = _FakePhotonAdapter(new_config)
    runner.adapters[PHOTON] = old_adapter
    runner.delivery_router.adapters = runner.adapters
    runner._failed_platforms[PHOTON] = {"config": new_config, "attempts": 1, "next_retry": 0}
    statuses = []
    runner._update_platform_runtime_status = (
        lambda platform, **kwargs: statuses.append((platform, kwargs))
    )
    monkeypatch.setenv("PHOTON_PROJECT_SECRET", "stale-secret")

    def fake_env_reload():
        assert "PHOTON_PROJECT_SECRET" not in os.environ
        os.environ["PHOTON_PROJECT_SECRET"] = "fresh-secret"

    async def fake_connect(adapter, platform):
        return await adapter.connect()

    monkeypatch.setattr(gateway_run, "_reload_runtime_env_preserving_config_authority", fake_env_reload)
    monkeypatch.setattr(gateway_run, "_drop_absent_platform_managed_photon_env", lambda: None)
    monkeypatch.setattr(
        gateway_run,
        "load_gateway_config",
        lambda: GatewayConfig(platforms={PHOTON: new_config}),
    )
    monkeypatch.setattr(runner, "_create_adapter", lambda platform, config: new_adapter)
    monkeypatch.setattr(runner, "_connect_adapter_with_timeout", fake_connect)
    rebuild = AsyncMock(return_value={})
    monkeypatch.setattr(channel_directory, "build_channel_directory", rebuild)

    result = await runner.reload_photon_platform()

    assert result == {"platform": "photon", "state": "connected", "connected": True}
    assert old_adapter.disconnected is True
    assert new_adapter.connected is True
    assert runner.adapters[PHOTON] is new_adapter
    assert runner.delivery_router.adapters is runner.adapters
    assert PHOTON not in runner._failed_platforms
    assert os.environ["PHOTON_PROJECT_SECRET"] == "fresh-secret"
    assert ("photon", {"platform_state": "connected", "error_code": None, "error_message": None}) in statuses
    rebuild.assert_awaited_once_with(runner.adapters)


@pytest.mark.asyncio
async def test_reload_photon_disconnects_when_removed_from_config(monkeypatch):
    runner = _make_reload_runner()
    old_adapter = _FakePhotonAdapter()
    runner.adapters[PHOTON] = old_adapter
    runner.delivery_router.adapters = runner.adapters
    statuses = []
    runner._update_platform_runtime_status = (
        lambda platform, **kwargs: statuses.append((platform, kwargs))
    )
    monkeypatch.setattr(gateway_run, "_reload_runtime_env_preserving_config_authority", lambda: None)
    monkeypatch.setattr(gateway_run, "load_gateway_config", lambda: GatewayConfig(platforms={}))
    rebuild = AsyncMock(return_value={})
    monkeypatch.setattr(channel_directory, "build_channel_directory", rebuild)

    result = await runner.reload_photon_platform()

    assert result == {"platform": "photon", "state": "disabled", "connected": False}
    assert old_adapter.disconnected is True
    assert PHOTON not in runner.adapters
    assert PHOTON not in runner.config.platforms
    assert ("photon", {"platform_state": "disabled", "error_code": None, "error_message": None}) in statuses
    rebuild.assert_awaited_once_with(runner.adapters)


def _internal_reload_app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app["api_server_adapter"] = adapter
    app.router.add_post(
        "/internal/platforms/photon/reload",
        adapter._handle_internal_photon_reload,
    )
    return app


@pytest.mark.asyncio
async def test_internal_photon_reload_endpoint_calls_runner_with_valid_key():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-secret"}))
    adapter.gateway_runner = SimpleNamespace(
        reload_photon_platform=AsyncMock(
            return_value={"platform": "photon", "state": "connected", "connected": True}
        )
    )

    async with TestClient(TestServer(_internal_reload_app(adapter))) as client:
        response = await client.post(
            "/internal/platforms/photon/reload",
            headers={"Authorization": "Bearer sk-secret"},
            json={},
        )
        payload = await response.json()

    assert response.status == 200
    assert payload["ok"] is True
    assert payload["data"]["state"] == "connected"
    adapter.gateway_runner.reload_photon_platform.assert_awaited_once()


@pytest.mark.asyncio
async def test_internal_photon_reload_endpoint_requires_api_key():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-secret"}))
    adapter.gateway_runner = SimpleNamespace(reload_photon_platform=AsyncMock())

    async with TestClient(TestServer(_internal_reload_app(adapter))) as client:
        response = await client.post("/internal/platforms/photon/reload", json={})

    assert response.status == 401
    adapter.gateway_runner.reload_photon_platform.assert_not_called()
