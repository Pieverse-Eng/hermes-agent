"""Hosted Hermes platform run-lease client behaviour."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from gateway.platform_activity import PlatformActivityClient, PlatformActivityError


@pytest.fixture
def activity_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    socket_path = tmp_path / "activity.sock"
    monkeypatch.setenv("TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED", "true")
    monkeypatch.setenv("TENANT_RUNTIME_ACTIVITY_SOCKET", str(socket_path))
    return socket_path


async def _start_server(path: Path, seen: list[dict]):
    handles: set[str] = set()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while raw := await reader.readline():
                request = json.loads(raw)
                seen.append(request)
                if request["operation"] == "start":
                    handle = f"handle-{len(handles) + 1}"
                    handles.add(handle)
                    response = {
                        "version": 1,
                        "ok": True,
                        "operation": "start",
                        "requestId": request["requestId"],
                        "activityHandle": handle,
                    }
                elif request["activityHandle"] in handles:
                    handles.remove(request["activityHandle"])
                    response = {
                        "version": 1,
                        "ok": True,
                        "operation": "finish",
                        "requestId": request["requestId"],
                    }
                else:
                    response = {
                        "version": 1,
                        "ok": False,
                        "requestId": request["requestId"],
                        "error": "unknown handle",
                    }
                writer.write((json.dumps(response) + "\n").encode())
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    return await asyncio.start_unix_server(handler, path=str(path))


@pytest.mark.asyncio
async def test_shares_one_stream_and_finishes_every_live_handle(activity_env: Path):
    seen: list[dict] = []
    server = await _start_server(activity_env, seen)
    client = PlatformActivityClient()
    try:
        first, second = await asyncio.gather(client.start(), client.start())
        assert first.active and second.active
        await first.finish()
        await second.finish()
        assert [request["operation"] for request in seen] == ["start", "start", "finish", "finish"]
        assert len({request["requestId"] for request in seen}) == 4
        assert len({request["admissionId"] for request in seen[:2]}) == 2
    finally:
        await client.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_refuses_work_when_the_hosted_socket_is_unavailable(activity_env: Path):
    client = PlatformActivityClient()
    with pytest.raises(PlatformActivityError, match="socket unavailable"):
        await client.start()


@pytest.mark.asyncio
async def test_ordinary_runtime_is_an_inert_noop(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED", raising=False)
    monkeypatch.delenv("TENANT_RUNTIME_ACTIVITY_SOCKET", raising=False)
    lease = await PlatformActivityClient().start()
    assert lease.active is False
    await lease.finish()


@pytest.mark.asyncio
async def test_cancelled_start_closes_ambiguous_activity_stream(activity_env: Path):
    """A cancelled start cannot leave an unowned lease renewing forever."""
    accepted = asyncio.Event()
    release_ack = asyncio.Event()
    disconnected = asyncio.Event()
    active_handles: set[str] = set()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while raw := await reader.readline():
                request = json.loads(raw)
                if request["operation"] == "start":
                    handle = request["admissionId"]
                    active_handles.add(handle)
                    accepted.set()
                    await release_ack.wait()
                    response = {
                        "version": 1,
                        "ok": True,
                        "operation": "start",
                        "requestId": request["requestId"],
                        "activityHandle": handle,
                    }
                else:
                    active_handles.remove(request["activityHandle"])
                    response = {
                        "version": 1,
                        "ok": True,
                        "operation": "finish",
                        "requestId": request["requestId"],
                    }
                writer.write((json.dumps(response) + "\n").encode("utf-8"))
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError):
            pass
        finally:
            disconnected.set()
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_unix_server(handler, str(activity_env))
    client = PlatformActivityClient()
    task = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(accepted.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert client._writer is None
        assert client._reader_task is None
        release_ack.set()
        await asyncio.wait_for(disconnected.wait(), timeout=2)
        assert active_handles
    finally:
        release_ack.set()
        await client.close()
        server.close()
        await server.wait_closed()
