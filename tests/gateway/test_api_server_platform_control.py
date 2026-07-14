"""Tests for Hermes API server internal platform-control endpoints."""

from __future__ import annotations

import threading
from collections import OrderedDict

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import Platform, PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


def _make_app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_get("/internal/platform/gateway/status", adapter._handle_internal_gateway_status)
    app.router.add_post("/internal/platform/runtime-sync", adapter._handle_internal_runtime_sync)
    app.router.add_get(
        "/internal/platform/telegram/approved-users",
        adapter._handle_internal_telegram_approved_users,
    )
    app.router.add_post(
        "/internal/platform/telegram/approved-users",
        adapter._handle_internal_telegram_approved_users,
    )
    app.router.add_post(
        "/internal/platform/gateway/prewarm-session",
        adapter._handle_internal_gateway_prewarm_session,
    )
    app.router.add_post("/internal/platform/gateway/reload", adapter._handle_internal_gateway_reload)
    return app


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer sk-test"}


def test_api_server_adapter_gets_gateway_runner_backref():
    from gateway.config import GatewayConfig
    from gateway.run import GatewayRunner

    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    adapter = GatewayRunner._create_adapter(
        runner,
        Platform.API_SERVER,
        PlatformConfig(enabled=True, extra={"key": "sk-test"}),
    )

    assert adapter is not None
    assert adapter.gateway_runner is runner


@pytest.mark.asyncio
async def test_internal_platform_routes_require_api_key():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-test"}))
    app = _make_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        unauthorized = await cli.get("/internal/platform/gateway/status")
        assert unauthorized.status == 401

        ok = await cli.get("/internal/platform/gateway/status", headers=_auth())
        assert ok.status == 200
        data = await ok.json()

    assert data["ok"] is True
    assert data["platform"] == "hermes-agent"
    assert data["processMarker"]


@pytest.mark.asyncio
async def test_internal_telegram_approved_users_replaces_pairing_store(tmp_path, monkeypatch):
    import gateway.pairing as pairing

    monkeypatch.setattr(pairing, "PAIRING_DIR", tmp_path / "platforms" / "pairing")
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-test"}))
    app = _make_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        first = await cli.post(
            "/internal/platform/telegram/approved-users",
            headers=_auth(),
            json={"users": ["42", {"userId": "84", "userName": "Lin"}]},
        )
        assert first.status == 200
        first_data = await first.json()
        assert [user["user_id"] for user in first_data["users"]] == ["42", "84"]

        second = await cli.post(
            "/internal/platform/telegram/approved-users",
            headers=_auth(),
            json={"userIds": ["84"]},
        )
        assert second.status == 200

        listed = await cli.get("/internal/platform/telegram/approved-users", headers=_auth())
        assert listed.status == 200
        listed_data = await listed.json()

    assert [user["user_id"] for user in listed_data["users"]] == ["84"]
    assert listed_data["users"][0]["user_name"] == "Lin"


@pytest.mark.asyncio
async def test_internal_runtime_sync_writes_managed_files(tmp_path, monkeypatch):
    home = tmp_path / "home"
    managed = tmp_path / "managed"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("PLATFORM_MANAGED_DIR", str(managed))

    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-test"}))
    app = _make_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/internal/platform/runtime-sync",
            headers=_auth(),
            json={
                "files": {
                    "config.yaml": "model: test-model\n",
                    ".env": "API_SERVER_KEY=sk-test\n",
                    "SOUL.md": "You are Purr-Fect Claw.\n",
                    "platform-builtin-skills.env": "PLATFORM_BUILTIN_SKILL_SLUGS='instance-billing'\n",
                }
            },
        )
        assert resp.status == 200
        data = await resp.json()

    assert data["ok"] is True
    assert set(data["written"]) == {
        "config.yaml",
        ".env",
        "SOUL.md",
        "platform-builtin-skills.env",
    }
    assert data["reloadRecommended"] is True
    assert (managed / "config.yaml").read_text(encoding="utf-8") == "model: test-model\n"
    assert (home / ".env").read_text(encoding="utf-8") == "API_SERVER_KEY=sk-test\n"
    assert (home / "SOUL.md").read_text(encoding="utf-8") == "You are Purr-Fect Claw.\n"
    assert (
        home / "platform-builtin-skills.env"
    ).read_text(encoding="utf-8") == "PLATFORM_BUILTIN_SKILL_SLUGS='instance-billing'\n"


@pytest.mark.asyncio
async def test_internal_runtime_sync_rejects_unknown_files_before_writing(tmp_path, monkeypatch):
    home = tmp_path / "home"
    managed = tmp_path / "managed"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("PLATFORM_MANAGED_DIR", str(managed))

    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-test"}))
    app = _make_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/internal/platform/runtime-sync",
            headers=_auth(),
            json={
                "files": {
                    "config.yaml": "model: test-model\n",
                    "../nope": "must not be written",
                }
            },
        )
        assert resp.status == 400

    assert not (managed / "config.yaml").exists()


@pytest.mark.asyncio
async def test_internal_prewarm_session_populates_gateway_agent_cache(monkeypatch):
    created: list[dict] = []

    class FakeSessionEntry:
        session_key = "agent:main:telegram:dm:42"
        session_id = "session-real-1"

    class FakeSessionStore:
        def __init__(self):
            self.sources = []

        def get_or_create_session(self, source):
            self.sources.append(source)
            return FakeSessionEntry()

    class FakeAgent:
        def __init__(self, **kwargs):
            created.append(kwargs)
            self.tools = [{"function": {"name": "memory"}}]
            self._cached_system_prompt = None
            self.session_id = kwargs.get("session_id")

        def _build_system_prompt(self, system_message=None):
            return "warm system prompt"

    class FakeRunner:
        def __init__(self):
            self._agent_cache = OrderedDict()
            self._agent_cache_lock = threading.Lock()
            self._provider_routing = {}
            self._session_db = None
            self._prefill_messages = None
            self._service_tier = None
            self.session_store = FakeSessionStore()
            self.enforced = False

        def _session_key_for_source(self, source):
            return f"agent:main:{source.platform.value}:{source.chat_type}:{source.chat_id}"

        def _get_system_prompt_for_channel(self, *args, **kwargs):
            return ""

        def _resolve_session_agent_runtime(self, **kwargs):
            return "test-model", {
                "provider": "custom",
                "api_key": "sk-provider",
                "base_url": "https://llm.example/v1",
                "api_mode": "chat_completions",
            }

        def _resolve_session_reasoning_config(self, **kwargs):
            return {"enabled": False}

        def _load_service_tier(self):
            return None

        def _resolve_turn_agent_config(self, prompt, model, runtime):
            return {"model": model, "runtime": runtime, "request_overrides": {}}

        def _agent_config_signature(self, *args, **kwargs):
            return "sig"

        def _extract_cache_busting_config(self, user_config):
            return {}

        def _refresh_fallback_model(self):
            return None

        def _enforce_agent_cache_cap(self):
            self.enforced = True

        def _release_evicted_agent_soft(self, agent):
            agent.released = True

    monkeypatch.setattr("run_agent.AIAgent", FakeAgent)
    monkeypatch.setattr("gateway.run._load_gateway_config", lambda: {"agent": {}})
    monkeypatch.setattr("gateway.run._current_max_iterations", lambda: 12)
    monkeypatch.setattr("hermes_cli.tools_config._get_platform_tools", lambda cfg, platform: {"memory"})

    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "sk-test"}))
    runner = FakeRunner()
    adapter.gateway_runner = runner
    app = _make_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        first = await cli.post(
            "/internal/platform/gateway/prewarm-session",
            headers=_auth(),
            json={"platform": "telegram", "userId": "42"},
        )
        assert first.status == 200
        first_data = await first.json()

        second = await cli.post(
            "/internal/platform/gateway/prewarm-session",
            headers=_auth(),
            json={"platform": "telegram", "userId": "42"},
        )
        assert second.status == 200
        second_data = await second.json()

    assert first_data["ok"] is True
    assert first_data["cached"] is True
    assert first_data["cacheHit"] is False
    assert first_data["sessionKey"] == "agent:main:telegram:dm:42"
    assert first_data["sessionId"] == "session-real-1"
    assert first_data["systemPromptWarmed"] is True
    assert second_data["cacheHit"] is True
    assert second_data["cached"] is True
    assert len(created) == 1
    assert created[0]["session_id"] == "session-real-1"
    assert created[0]["platform"] == "telegram"
    assert created[0]["gateway_session_key"] == "agent:main:telegram:dm:42"
    assert runner._agent_cache["agent:main:telegram:dm:42"][3] == "session-real-1"
    assert runner._agent_cache["agent:main:telegram:dm:42"][4] == {
        "platform_prewarm_template": True,
        "template_kind": "telegram_dm_threadless",
        "prompt_template_signature": "sig",
    }
    assert runner.enforced is True
