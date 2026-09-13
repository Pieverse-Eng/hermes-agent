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
async def test_cancelled_start_finishes_only_its_lease_on_shared_stream(activity_env: Path):
    """Cancelling one admission must preserve every sibling lease on the stream."""
    accepted = asyncio.Event()
    release_ack = asyncio.Event()
    disconnected = asyncio.Event()
    active_handles: set[str] = set()
    operations: list[tuple[str, str]] = []
    start_count = 0

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal start_count
        try:
            while raw := await reader.readline():
                request = json.loads(raw)
                operations.append((request["operation"], request.get("activityHandle", "")))
                if request["operation"] == "start":
                    start_count += 1
                    handle = request["admissionId"]
                    active_handles.add(handle)
                    if start_count == 2:
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
    first = await client.start()
    task = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(accepted.wait(), timeout=2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert client._writer is not None

        release_ack.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)

        assert first.active
        await first.finish()
        assert active_handles == set()
        assert [operation for operation, _ in operations] == [
            "start",
            "start",
            "finish",
            "finish",
        ]
        assert client._writer is not None
    finally:
        release_ack.set()
        await client.close()
        await asyncio.wait_for(disconnected.wait(), timeout=2)
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['start', 'finish'])
@pytest.mark.parametrize('cancelled', [False, True])
async def test_ack_timeout_replays_same_request_without_abandoning_siblings(activity_env, monkeypatch, operation, cancelled):
    """A lost response is resolved using the supervisor's existing replay key."""
    dropped = asyncio.Event()
    expire = asyncio.Event()
    active = set()
    replays = {}
    seen = []
    committed = []
    should_drop = False
    real_wait_for = asyncio.wait_for

    async def handler(reader, writer):
        try:
            while raw := await reader.readline():
                request = json.loads(raw)
                seen.append(request)
                request_id = request['requestId']
                if request_id not in replays:
                    committed.append(request['operation'])
                    response = {'version': 1, 'ok': True, 'operation': request['operation'],
                                'requestId': request_id}
                    if request['operation'] == 'start':
                        response['activityHandle'] = request['admissionId']
                        active.add(response['activityHandle'])
                    else:
                        active.remove(request['activityHandle'])
                    replays[request_id] = response
                    if should_drop and request['operation'] == operation and not dropped.is_set():
                        dropped.set()
                        continue
                writer.write((json.dumps(replays[request_id]) + '\n').encode())
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(handler, str(activity_env))
    client = PlatformActivityClient()
    try:
        sibling = await client.start()
        target = await client.start() if operation == 'finish' else None
        original_writer = client._writer
        should_drop = True
        injected = False

        async def expire_once(awaitable, timeout):
            nonlocal injected
            if not injected and isinstance(awaitable, asyncio.Future):
                injected = True
                await dropped.wait()
                await expire.wait()
                awaitable.cancel()  # cancel only the shield, as wait_for does
                raise asyncio.TimeoutError
            return await real_wait_for(awaitable, timeout)

        monkeypatch.setattr(asyncio, 'wait_for', expire_once)
        task = asyncio.create_task(client.start() if operation == 'start' else target.finish())
        await dropped.wait()
        if cancelled:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
        expire.set()
        if cancelled:
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            if operation == 'start':
                target = result
        assert injected
        assert client._writer is original_writer
        assert sibling._handle in active
        duplicates = [request for request in seen if sum(
            other['requestId'] == request['requestId'] for other in seen
        ) > 1]
        assert len(duplicates) == 2
        assert duplicates[0] == duplicates[1]
        if target is not None:
            await target.finish()
        await sibling.finish()
        assert active == set()
        assert committed.count('start') == committed.count('finish') == 2
    finally:
        await client.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_stream_loss_with_live_handles_fails_closed(activity_env, monkeypatch):
    """A broken producer cannot reconnect and continue work without protection."""
    sever = asyncio.Event()
    terminated = asyncio.Event()
    exit_codes = []

    def terminate(code):
        exit_codes.append(code)
        terminated.set()

    monkeypatch.setattr('gateway.platform_activity.os._exit', terminate)

    async def handler(reader, writer):
        request = json.loads(await reader.readline())
        writer.write((json.dumps({'version': 1, 'ok': True, 'operation': 'start',
                                 'requestId': request['requestId'], 'activityHandle': 'live'}) + '\n').encode())
        await writer.drain()
        await sever.wait()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(handler, str(activity_env))
    client = PlatformActivityClient()
    try:
        lease = await client.start()
        assert lease.active
        sever.set()
        await asyncio.wait_for(terminated.wait(), 2)
        assert exit_codes == [1]
        with pytest.raises(PlatformActivityError, match='producer has failed'):
            await client.start()
    finally:
        sever.set()
        await client.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_idle_stream_loss_reconnects_after_all_requests_settle(activity_env):
    """A fully idle producer can establish a new supervisor stream safely."""
    disconnect = asyncio.Event()
    connected = 0

    async def handler(reader, writer):
        nonlocal connected
        connected += 1
        connection = connected
        try:
            while raw := await reader.readline():
                request = json.loads(raw)
                response = {
                    'version': 1,
                    'ok': True,
                    'operation': request['operation'],
                    'requestId': request['requestId'],
                }
                if request['operation'] == 'start':
                    response['activityHandle'] = request['admissionId']
                writer.write((json.dumps(response) + '\n').encode())
                await writer.drain()
                if connection == 1 and request['operation'] == 'finish':
                    await disconnect.wait()
                    writer.close()
                    await writer.wait_closed()
                    return
        finally:
            writer.close()

    server = await asyncio.start_unix_server(handler, str(activity_env))
    client = PlatformActivityClient()
    try:
        first = await client.start()
        await first.finish()
        disconnect.set()
        await asyncio.wait_for(client._reader_task, 2)

        second = await client.start()
        assert second.active
        await second.finish()
        assert connected == 2
    finally:
        disconnect.set()
        await client.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid', [
    {'version': 2}, {'operation': 'finish'}, {'activityHandle': ''},
])
async def test_invalid_admission_ack_closes_unusable_producer(activity_env, invalid, monkeypatch):
    disconnected = asyncio.Event()
    exit_codes = []
    monkeypatch.setattr('gateway.platform_activity.os._exit', exit_codes.append)

    async def handler(reader, writer):
        request = json.loads(await reader.readline())
        response = {'version': 1, 'ok': True, 'operation': 'start',
                    'requestId': request['requestId'], 'activityHandle': 'accepted'}
        response.update(invalid)
        writer.write((json.dumps(response) + '\n').encode())
        await writer.drain()
        try:
            assert await reader.read() == b''
            disconnected.set()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(handler, str(activity_env))
    client = PlatformActivityClient()
    try:
        with pytest.raises(PlatformActivityError):
            await client.start()
        await asyncio.wait_for(disconnected.wait(), 2)
        assert exit_codes == [1]
        with pytest.raises(PlatformActivityError, match='producer has failed'):
            await client.start()
    finally:
        await client.close()
        server.close()
        await server.wait_closed()
