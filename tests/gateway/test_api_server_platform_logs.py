"""Bounded native gateway log reads preserve byte cursors and detect rotation."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


@pytest.mark.asyncio
async def test_gateway_log_tail_and_rotation(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("API_SERVER_KEY", "log-contract-key")
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "log-contract-key"}))
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    log = tmp_path / "logs" / "gateway.log"
    log.parent.mkdir(exist_ok=True)
    log.write_text("first\nsecond\npartial")
    path = "/internal/platform/logs/tail"
    headers = {"Authorization": "Bearer log-contract-key"}
    async with TestClient(TestServer(app)) as client:
        assert (await client.post(path, json={"limit": 1})).status == 401
        first = await client.post(path, headers=headers, json={"limit": 1})
        assert first.status == 200
        data = await first.json()
        assert data["lines"] == ["second"]
        log.write_text("first\nsecond\npartial finished\n")
        second = await client.post(path, headers=headers, json={"cursor": data["cursor"]})
        data = await second.json()
        assert data["lines"] == ["partial finished"]
        log.rename(log.with_suffix(".old"))
        log.write_text("rotated\n")
        rotated = await client.post(path, headers=headers, json={"cursor": data["cursor"]})
        assert (await rotated.json())["lines"] == ["rotated"]
        assert (await client.post(path, headers=headers, json={"path": "/etc/passwd"})).status == 400
        assert (await client.post(path, headers=headers, json={"limit": 5001})).status == 400
        log.unlink()
        log.symlink_to(log.with_suffix(".old"))
        assert (await client.post(path, headers=headers, json={"limit": 1})).status == 503
