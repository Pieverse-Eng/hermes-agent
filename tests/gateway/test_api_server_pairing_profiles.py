"""Pairing control must use the same profile as HTTP authentication and authz."""

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent import secret_scope
from gateway import pairing
from gateway.config import GatewayConfig, PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    worker_home = home / "profiles" / "worker"
    worker_home.mkdir(parents=True)
    keys = {"default": "default-profile-owner-key", "worker": "worker-profile-owner-key"}
    for name, directory in (("default", home), ("worker", worker_home)):
        (directory / ".env").write_text(f"API_SERVER_KEY={keys[name]}\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("API_SERVER_KEY", keys["default"])
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    monkeypatch.delenv("LINE_ALLOWED_USERS", raising=False)
    monkeypatch.setattr(pairing, "PAIRING_DIR", home / "platforms" / "pairing")
    monkeypatch.setattr(pairing, "get_default_hermes_root", lambda: home)
    monkeypatch.setattr(secret_scope, "_MULTIPLEX_ACTIVE", True)
    monkeypatch.setattr(
        "hermes_cli.profiles.profiles_to_serve",
        lambda **kwargs: [("default", home), ("worker", worker_home)],
    )
    monkeypatch.setattr(
        "hermes_cli.profiles.get_profile_dir",
        lambda name: home if name == "default" else worker_home,
    )
    stores = {"default": pairing.PairingStore(), "worker": pairing.PairingStore(profile="worker")}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": keys["default"]}))
    adapter.gateway_runner = SimpleNamespace(
        config=GatewayConfig(multiplex_profiles=True), pairing_store=stores["default"],
        pairing_stores=dict(stores),
    )
    app = web.Application(middlewares=[adapter._make_profile_prefix_middleware()])
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
        app.router.add_route(method, "/p/{profile}" + path, handler)
    yield SimpleNamespace(app=app, adapter=adapter, stores=stores, keys=keys)
    adapter._run_idempotency_store.close()


def auth(profiles, name="worker"):
    return {"Authorization": "Bearer " + profiles.keys[name]}


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["telegram", "line"])
@pytest.mark.parametrize("missing_cached_store", [False, True])
async def test_pairing_reads_only_the_authenticated_profile(profiles, channel, missing_cached_store):
    profiles.stores["default"].replace_approved(channel, ["default-user"])
    profiles.stores["worker"].replace_approved(channel, ["worker-user"])
    if missing_cached_store:
        profiles.adapter.gateway_runner.pairing_stores.pop("worker")
    async with TestClient(TestServer(profiles.app)) as client:
        path = "/p/worker/internal/platform/pairing/allow-from"
        wrong_key = await client.post(path, headers=auth(profiles, "default"), json={"channel": channel})
        assert wrong_key.status == 401
        response = await client.post(path, headers=auth(profiles), json={"channel": channel})
        assert response.status == 200
        assert await response.json() == {"allowFrom": ["worker-user"]}
        for prefix in ("", "/p/default"):
            response = await client.post(
                prefix + "/internal/platform/pairing/allow-from",
                headers=auth(profiles, "default"), json={"channel": channel},
            )
            assert response.status == 200
            assert await response.json() == {"allowFrom": ["default-user"]}
        unknown = await client.post(
            "/p/unknown/internal/platform/pairing/allow-from",
            headers=auth(profiles), json={"channel": channel},
        )
        assert unknown.status == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["telegram", "line"])
async def test_pairing_approval_changes_only_the_authenticated_profile(profiles, channel):
    root, worker = profiles.stores["default"], profiles.stores["worker"]
    root.generate_code(channel, "default-pending")
    code = worker.generate_code(channel, "worker-pending")
    async with TestClient(TestServer(profiles.app)) as client:
        response = await client.post(
            "/p/worker/internal/platform/pairing/approve", headers=auth(profiles),
            json={"channel": channel, "code": code},
        )
        assert response.status == 200
        assert await response.json() == {"status": "approved", "allowFrom": ["worker-pending"]}
    assert worker.is_approved(channel, "worker-pending")
    assert worker.list_pending(channel) == []
    assert root.list_approved(channel) == []
    assert [entry["user_id"] for entry in root.list_pending(channel)] == ["default-pending"]


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_profile", ["default", "worker"])
async def test_explicit_primary_profile_approval_reuses_the_primary_store_lock(
    profiles, monkeypatch, primary_profile,
):
    primary = profiles.stores[primary_profile]
    profiles.adapter.gateway_runner.pairing_store = primary
    profiles.adapter.gateway_runner.pairing_stores.pop(primary_profile)
    monkeypatch.setenv("HERMES_HOME", str(primary._home))
    code = primary.generate_code("line", "pending-user")
    lock = primary._lock
    loop = asyncio.get_running_loop()
    lock_held = asyncio.Event()
    lock_attempted = asyncio.Event()
    release_lock = threading.Event()

    class ObservedLock:
        def __enter__(self):
            loop.call_soon_threadsafe(lock_attempted.set)
            return lock.__enter__()

        def __exit__(self, *args):
            return lock.__exit__(*args)

    monkeypatch.setattr(primary, "_lock", ObservedLock())

    def hold_primary_lock():
        with lock:
            loop.call_soon_threadsafe(lock_held.set)
            release_lock.wait(10)  # Safety bound; the test releases by event.

    holder = threading.Thread(target=hold_primary_lock)
    holder.start()
    tasks = []
    try:
        await asyncio.wait_for(lock_held.wait(), timeout=10)
        async with TestClient(TestServer(profiles.app)) as client:
            async def approve():
                response = await client.post(
                    f"/p/{primary_profile}/internal/platform/pairing/approve",
                    headers=auth(profiles, primary_profile),
                    json={"channel": "line", "code": code},
                )
                return response.status, await response.json()

            approval = asyncio.create_task(approve())
            attempted = asyncio.create_task(lock_attempted.wait())
            tasks = [approval, attempted]
            try:
                done, _ = await asyncio.wait_for(
                    asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED),
                    timeout=10,
                )
                # The request must reach the existing store's lock before it
                # can finish. A second store bypasses the held lock entirely.
                assert attempted in done, "Approval bypassed the primary store lock"
                assert not approval.done()
                release_lock.set()
                assert await asyncio.wait_for(approval, timeout=10) == (
                    200, {"status": "approved", "allowFrom": ["pending-user"]},
                )
            finally:
                release_lock.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        release_lock.set()
        await asyncio.to_thread(holder.join, 10)


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["telegram", "line"])
@pytest.mark.parametrize("mode", ["entry", "account", "requests"])
async def test_pairing_revocation_changes_only_the_authenticated_profile(profiles, channel, mode):
    root, worker = profiles.stores["default"], profiles.stores["worker"]
    for store in (root, worker):
        store.replace_approved(channel, ["shared-user"])
        store.generate_code(channel, "shared-user")
    body = {"channel": channel, "mode": mode}
    if mode == "entry":
        body["entry"] = "shared-user"
    async with TestClient(TestServer(profiles.app)) as client:
        response = await client.post(
            "/p/worker/internal/platform/pairing/revoke", headers=auth(profiles), json=body,
        )
        assert response.status == 200
        assert await response.json() == {
            "changed": True,
            "removedAllowFromCount": 0 if mode == "requests" else 1,
            "removedRequestCount": 1,
            "allowFrom": ["shared-user"] if mode == "requests" else [],
        }
    assert worker.is_approved(channel, "shared-user") == (mode == "requests")
    assert worker.list_pending(channel) == []
    assert root.is_approved(channel, "shared-user")
    assert len(root.list_pending(channel)) == 1


@pytest.mark.asyncio
async def test_legacy_telegram_projection_uses_the_same_profile_store(profiles):
    root, worker = profiles.stores["default"], profiles.stores["worker"]
    root.replace_approved("telegram", ["default-user"])
    worker.replace_approved("telegram", ["worker-user"])
    async with TestClient(TestServer(profiles.app)) as client:
        path = "/p/worker/internal/platform/telegram/approved-users"
        response = await client.get(path, headers=auth(profiles))
        assert response.status == 200
        assert [user["user_id"] for user in (await response.json())["users"]] == ["worker-user"]
        response = await client.post(path, headers=auth(profiles), json={"users": ["replacement"]})
        assert response.status == 200
        assert [user["user_id"] for user in (await response.json())["users"]] == ["replacement"]
    assert worker.is_approved("telegram", "replacement")
    assert root.is_approved("telegram", "default-user")
