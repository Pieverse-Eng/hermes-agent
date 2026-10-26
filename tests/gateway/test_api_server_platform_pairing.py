"""Native pairing control through the production HTTP table, without shell access."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", ["telegram", "line"])
async def test_native_pairing_approval_and_scoped_revocation(platform, tmp_path, monkeypatch):
    import gateway.pairing as pairing
    monkeypatch.setattr(pairing, "PAIRING_DIR", tmp_path / "platforms" / "pairing")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("API_SERVER_KEY", "pairing-contract-key")
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "pairing-contract-key"}))
    store = adapter._platform_pairing_store()
    code = store.generate_code(platform, "42", "Private name")
    other = "line" if platform == "telegram" else "telegram"
    store.generate_code(other, "84", "Other private name")
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    headers = {"Authorization": "Bearer pairing-contract-key"}
    async with TestClient(TestServer(app)) as client:
        path = "/internal/platform/pairing/approve"
        assert (await client.post(path, json={"channel": platform, "code": code})).status == 401
        response = await client.post(path, headers=headers, json={"channel": platform, "code": code})
        assert response.status == 200
        assert await response.json() == {"status": "approved", "allowFrom": ["42"]}
        assert store.is_approved(platform, "42")
        assert len(store.list_pending(other)) == 1
        assert (await client.post(path, headers=headers, json={"channel": "../../bad", "code": code})).status == 400
        assert (await client.post(path, headers=headers, json={"channel": platform, "code": code, "path": "/tmp"})).status == 400
        missing = await client.post(path, headers=headers, json={"channel": platform, "code": code})
        assert await missing.json() == {"status": "not_found"}
        store.generate_code(platform, "99")
        pending_only = await client.post("/internal/platform/pairing/revoke", headers=headers,
            json={"channel": platform, "mode": "entry", "entry": "99"})
        assert await pending_only.json() == {"changed": True, "removedAllowFromCount": 0,
                                            "removedRequestCount": 1, "allowFrom": ["42"]}
        store.generate_code(platform, "100")
        revoked = await client.post("/internal/platform/pairing/revoke", headers=headers,
                                    json={"channel": platform, "mode": "account"})
        assert revoked.status == 200
        assert await revoked.json() == {"changed": True, "removedAllowFromCount": 1,
                                         "removedRequestCount": 1, "allowFrom": []}
        assert not store.is_approved(platform, "42")
        assert store.list_pending(platform) == []
        assert len(store.list_pending(other)) == 1


@pytest.mark.asyncio
async def test_pairing_control_requires_configured_key(tmp_path, monkeypatch):
    import gateway.pairing as pairing
    monkeypatch.setattr(pairing, "PAIRING_DIR", tmp_path / "platforms" / "pairing")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("API_SERVER_KEY", raising=False)
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    async with TestClient(TestServer(app)) as client:
        assert (await client.post("/internal/platform/pairing/allow-from", json={"channel": "telegram"})).status == 401


@pytest.mark.asyncio
async def test_approval_partial_write_is_explicitly_unknown(tmp_path, monkeypatch):
    import gateway.pairing as pairing
    monkeypatch.setattr(pairing, "PAIRING_DIR", tmp_path / "platforms" / "pairing")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "pairing-contract-key"}))
    store = adapter._platform_pairing_store()
    code = store.generate_code("telegram", "42")
    original = store.approve_code
    def partial(channel, code):
        original(channel, code)
        raise OSError("mirror failed")
    monkeypatch.setattr(store, "approve_code", partial)
    monkeypatch.setattr(adapter, "_platform_pairing_store", lambda: store)
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    async with TestClient(TestServer(app)) as client:
        response = await client.post("/internal/platform/pairing/approve",
            headers={"Authorization": "Bearer pairing-contract-key"}, json={"channel": "telegram", "code": code})
        assert await response.json() == {"status": "incomplete"}
        assert store.is_approved("telegram", "42")
        recovered = await client.post("/internal/platform/pairing/allow-from",
            headers={"Authorization": "Bearer pairing-contract-key"}, json={"channel": "telegram"})
        assert await recovered.json() == {"allowFrom": ["42"]}
