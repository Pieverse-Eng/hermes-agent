"""Authenticated run recovery through the production HTTP route table."""
import asyncio
import os
import sqlite3
import threading
import time
from unittest.mock import patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway.test_api_server_runs import _make_adapter
from tests.gateway.test_api_server_native_runs import RecordingAgent, settle


def app_for(adapter):
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    return app


@pytest.mark.asyncio
async def test_lookup_recovers_native_identity_without_replaying_content(tmp_path):
    path = str(tmp_path / "runs.db")
    adapter = _make_adapter(api_key="owner-key")
    adapter._run_idempotency_store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(path)
    agent = RecordingAgent()
    auth = {"Authorization": "Bearer owner-key"}
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(app_for(adapter))) as client:
            response = await client.post("/v1/runs", headers={**auth, "Idempotency-Key": "platform-run"},
                                         json={"input": "private message"})
            assert response.status == 202
            native = (await response.json())["run_id"]
            await settle(adapter, native)
    adapter._run_idempotency_store.close()
    recovered = _make_adapter(api_key="owner-key")
    recovered._run_idempotency_store.close()
    recovered._run_idempotency_store = RunIdempotencyStore(path)
    try:
        async with TestClient(TestServer(app_for(recovered))) as client:
            response = await client.post("/v1/runs/lookup", headers=auth,
                                         json={"idempotency_key": "platform-run"})
            assert response.status == 200
            assert await response.json() == {"run_id": native, "status": "completed"}
            assert len(agent.histories) == 1
            assert (await client.post("/v1/runs/lookup", json={"idempotency_key": "platform-run"})).status == 401
            assert (await client.post("/v1/runs/lookup", headers=auth, json={"idempotency_key": "missing"})).status == 404
            assert (await client.post("/v1/runs/lookup", headers=auth, json={"idempotency_key": []})).status == 400
        with patch.object(recovered, "_expected_api_key", return_value="another-owner"):
            async with TestClient(TestServer(app_for(recovered))) as client:
                response = await client.post("/v1/runs/lookup", headers={"Authorization": "Bearer another-owner"},
                                             json={"idempotency_key": "platform-run"})
                assert response.status == 404
    finally:
        recovered._run_idempotency_store.close()


@pytest.mark.parametrize(
    ("status", "age", "retention_delta", "acknowledged_age", "available"),
    [
        ("completed", 10, None, None, True),
        ("completed", 172800, None, None, False),
        ("failed", 172800, None, None, False),
        ("cancelled", 172800, None, None, False),
        ("interrupted", 172800, None, None, False),
        ("running", 172800, None, None, True),
        ("completed", 172800, 3600, None, True),
        ("completed", 10, -3600, None, False),
        ("completed", 10, 3600, 172800, False),
        ("running", 172800, -3600, 172800, True),
        ("completed", RunIdempotencyStore.RETENTION_SECONDS, None, None, True),
        ("completed", 10, 0, None, False),
        ("completed", 10, None, RunIdempotencyStore.ACKNOWLEDGED_RETENTION_SECONDS, False),
    ],
)
def test_lookup_is_read_only_and_preserves_retention_rules(
    tmp_path, monkeypatch, status, age, retention_delta, acknowledged_age, available,
):
    store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    now = time.time()
    monkeypatch.setattr("gateway.platforms.api_server_run_idempotency.time.time", lambda: now)
    run_id = "run_" + "a" * 32
    try:
        store.reserve("scope", "key", "fingerprint", run_id, {"status": status})
        store._conn.execute(
            "UPDATE run_idempotency SET updated_at=?, retention_until=?, acknowledged_at=?",
            (
                now - age,
                now + retention_delta if retention_delta is not None else 0,
                now - acknowledged_age if acknowledged_age is not None else None,
            ),
        )
        store._conn.commit()
        before = store._conn.execute("SELECT * FROM run_idempotency").fetchall()
        # Recovery must work on a read-only connection and must neither prune
        # another caller's rows nor change this caller's retention deadline.
        store._conn.execute("PRAGMA query_only=ON")
        assert store.run_for_key("scope", "key") == (run_id if available else None)
        assert store.run_for_key("other-scope", "key") is None
        assert store._conn.execute("SELECT * FROM run_idempotency").fetchall() == before
        # The same expiration rule must still govern physical cleanup and
        # key reuse when an actual submission performs a write transaction.
        store._conn.execute("PRAGMA query_only=OFF")
        replacement_id = "run_" + "c" * 32
        outcome, record = store.reserve(
            "scope", "key", "fingerprint", replacement_id, {"status": "queued"},
        )
        assert outcome == ("reused" if available else "created")
        assert record["run_id"] == (run_id if available else replacement_id)
    finally:
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_operation", ["lookup", "owner_reconciliation"])
async def test_lookup_services_the_event_loop_while_sqlite_is_locked(
    tmp_path, monkeypatch, blocked_operation,
):
    adapter = _make_adapter(api_key="owner-key")
    adapter._run_idempotency_store.close()
    path = str(tmp_path / "runs.db")
    store = adapter._run_idempotency_store = RunIdempotencyStore(path)
    store._conn.execute("PRAGMA busy_timeout=5000")
    run_id = "run_" + "b" * 32
    store.reserve(
        adapter._run_idempotency_scope(None), "key", "fingerprint", run_id,
        {"run_id": run_id, "status": "running" if blocked_operation == "owner_reconciliation" else "completed"},
        owner_pid=0,
    )
    if blocked_operation == "lookup":
        # Rollback-journal mode is an existing supported WAL fallback. An
        # exclusive writer then blocks even the recovery SELECT itself.
        store._conn.execute("PRAGMA journal_mode=DELETE")
    writer = sqlite3.connect(path, check_same_thread=False)
    writer.execute("BEGIN EXCLUSIVE" if blocked_operation == "lookup" else "BEGIN IMMEDIATE")
    release_writer = threading.Event()
    entered_storage = asyncio.Event()
    observed_order = []
    loop = asyncio.get_running_loop()
    method = "run_for_key" if blocked_operation == "lookup" else "interrupt_if_unsettled"
    original = getattr(store, method)

    def observed_storage(*args, **kwargs):
        loop.call_soon_threadsafe(entered_storage.set)
        try:
            return original(*args, **kwargs)
        finally:
            observed_order.append("storage-returned")

    monkeypatch.setattr(store, method, observed_storage)

    def unlock_database():
        # Safety timeout only: the event loop below is responsible for
        # releasing the real writer, so correctness depends on event order.
        release_writer.wait(10)
        writer.rollback()

    unlock_thread = threading.Thread(target=unlock_database)
    unlock_thread.start()

    async def release_from_event_loop():
        await entered_storage.wait()
        observed_order.append("event-loop-serviced")
        release_writer.set()

    release_task = asyncio.create_task(release_from_event_loop())
    try:
        async with TestClient(TestServer(app_for(adapter))) as client:
            response = await client.post(
                "/v1/runs/lookup", headers={"Authorization": "Bearer owner-key"},
                json={"idempotency_key": "key"},
            )
            assert response.status == 200
            assert await response.json() == {
                "run_id": run_id,
                "status": "interrupted" if blocked_operation == "owner_reconciliation" else "completed",
            }
            await asyncio.wait_for(release_task, timeout=10)
            assert observed_order == ["event-loop-serviced", "storage-returned"]
    finally:
        release_writer.set()
        release_task.cancel()
        await asyncio.gather(release_task, return_exceptions=True)
        await asyncio.to_thread(unlock_thread.join, 10)
        writer.close()
        store.close()


@pytest.mark.asyncio
async def test_lookup_does_not_overwrite_completion_with_an_in_flight_snapshot(tmp_path, monkeypatch):
    adapter = _make_adapter(api_key="owner-key")
    adapter._run_idempotency_store.close()
    store = adapter._run_idempotency_store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    run_id = "run_" + "d" * 32
    scope = adapter._run_idempotency_scope(None)
    store.reserve(
        scope, "key", "fingerprint", run_id,
        {"run_id": run_id, "status": "running"}, owner_pid=os.getpid(),
    )
    adapter._run_owners[run_id] = scope
    adapter._run_idempotency_ids.add(run_id)
    snapshot_loaded = asyncio.Event()
    release_snapshot = threading.Event()
    loop = asyncio.get_running_loop()
    original = store.status_for_run

    def delayed_snapshot(*args, **kwargs):
        record = original(*args, **kwargs)
        loop.call_soon_threadsafe(snapshot_loaded.set)
        if not release_snapshot.wait(10):
            raise TimeoutError("Event loop did not accept run completion")
        return record

    monkeypatch.setattr(store, "status_for_run", delayed_snapshot)

    async def complete_after_snapshot():
        await snapshot_loaded.wait()
        adapter._set_run_status(run_id, "completed", output="finished")
        release_snapshot.set()

    completion = asyncio.create_task(complete_after_snapshot())
    try:
        async with TestClient(TestServer(app_for(adapter))) as client:
            response = await client.post(
                "/v1/runs/lookup", headers={"Authorization": "Bearer owner-key"},
                json={"idempotency_key": "key"},
            )
            assert response.status == 200
            assert await response.json() == {"run_id": run_id, "status": "completed"}
            await asyncio.wait_for(completion, timeout=10)
            assert adapter._run_statuses[run_id]["status"] == "completed"
            assert adapter._run_statuses[run_id]["output"] == "finished"
    finally:
        release_snapshot.set()
        completion.cancel()
        await asyncio.gather(completion, return_exceptions=True)
        store.close()
