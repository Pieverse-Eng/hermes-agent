"""Platform run-lease client for hosted Hermes workloads.

The lifecycle supervisor is the only principal that can mutate the platform
lease table.  A hosted Hermes process therefore uses its already-mounted Unix
socket and waits for ``start`` to succeed *before* it begins agent work.  The
supervisor owns heartbeats; Hermes only brackets real work with start/finish.

This is deliberately inert outside the explicit hosted contract.  Ordinary
Deployments and local installs do not set both environment variables and keep
their existing behaviour.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass
from typing import Any, Optional

_LOG = logging.getLogger(__name__)
_PROTOCOL_VERSION = 1
_SOCKET_TIMEOUT_SECONDS = 5.0


class PlatformActivityError(RuntimeError):
    """The hosted runtime could not obtain or finish its platform lease."""


async def _await_task_through_cancellation(task: asyncio.Task[Any]) -> tuple[Any, bool]:
    """Wait for an owned protocol task despite repeated caller cancellation."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
    return task.result(), cancelled


def platform_activity_enabled() -> bool:
    return (
        os.environ.get("TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED") == "true"
        and bool(os.environ.get("TENANT_RUNTIME_ACTIVITY_SOCKET", "").strip())
    )


@dataclass
class PlatformActivityLease:
    """One platform-authorized unit of interactive/API work."""

    _client: "PlatformActivityClient"
    _handle: Optional[str]

    @property
    def active(self) -> bool:
        return self._handle is not None

    async def finish(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            await self._client.finish(handle)


class PlatformActivityClient:
    """One persistent, multiplexed activity stream for a gateway process.

    The supervisor deliberately treats stream closure as loss of the producer
    session.  Opening one connection per turn would stop heartbeats for other
    live handles, so all concurrent work shares this connection and each
    request is correlated by an unguessable UUID.
    """

    def __init__(self, socket_path: Optional[str] = None) -> None:
        self._socket_path = socket_path or os.environ.get("TENANT_RUNTIME_ACTIVITY_SOCKET", "").strip()
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connect_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: Optional[asyncio.Task[None]] = None

    @property
    def enabled(self) -> bool:
        return platform_activity_enabled() and bool(self._socket_path)

    async def start(self) -> PlatformActivityLease:
        if not self.enabled:
            return PlatformActivityLease(self, None)
        # The supervisor writes the supported drain marker before it starts
        # waiting for active handles. Checking it at this exact lease-admission
        # boundary closes the watcher race: work without a lease cannot enter
        # after a drain begins.
        from gateway.drain_control import drain_requested

        if drain_requested():
            raise PlatformActivityError("platform drain is active")
        request_id = str(uuid.uuid4())
        request_task = asyncio.create_task(
            self._request({
                "version": _PROTOCOL_VERSION,
                "operation": "start",
                "requestId": request_id,
                "admissionId": str(uuid.uuid4()),
            })
        )
        payload, cancelled = await _await_task_through_cancellation(request_task)
        handle = payload.get("activityHandle")
        if not isinstance(handle, str) or not handle:
            raise PlatformActivityError("platform activity start returned no handle")
        if cancelled:
            # The supervisor accepted this exact admission while its caller was
            # being cancelled. Finish only that handle on the existing shared
            # stream; closing the stream would abandon unrelated live workers.
            finish_task = asyncio.create_task(self.finish(handle))
            await _await_task_through_cancellation(finish_task)
            raise asyncio.CancelledError
        return PlatformActivityLease(self, handle)

    async def finish(self, handle: str) -> None:
        if not self.enabled:
            return
        request_task = asyncio.create_task(
            self._request({
                "version": _PROTOCOL_VERSION,
                "operation": "finish",
                "requestId": str(uuid.uuid4()),
                "activityHandle": handle,
            })
        )
        _, cancelled = await _await_task_through_cancellation(request_task)
        if cancelled:
            raise asyncio.CancelledError

    async def close(self) -> None:
        writer, self._writer = self._writer, None
        self._reader = None
        task, self._reader_task = self._reader_task, None
        if task is not None:
            task.cancel()
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        self._fail_pending(PlatformActivityError("platform activity stream closed"))

    async def _request(self, request: dict[str, Any]) -> dict[str, Any]:
        await self._ensure_connected()
        request_id = str(request["requestId"])
        loop = asyncio.get_running_loop()
        response: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[request_id] = response
        transmission_started = False
        try:
            async with self._write_lock:
                writer = self._writer
                if writer is None or writer.is_closing():
                    raise PlatformActivityError("platform activity stream is unavailable")
                # From this point onward a failed or cancelled wait has an
                # ambiguous server-side outcome. The supervisor may have
                # created a lease even when its acknowledgement never reaches
                # this caller.
                transmission_started = True
                writer.write((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
                await writer.drain()
            return await asyncio.wait_for(response, timeout=_SOCKET_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            if transmission_started:
                await self.close()
            raise
        except PlatformActivityError:
            raise
        except Exception as exc:
            if transmission_started:
                await self.close()
            raise PlatformActivityError(f"platform activity request failed: {exc}") from exc
        finally:
            self._pending.pop(request_id, None)

    async def _ensure_connected(self) -> None:
        if self._writer is not None and not self._writer.is_closing():
            return
        async with self._connect_lock:
            if self._writer is not None and not self._writer.is_closing():
                return
            if not self._socket_path:
                raise PlatformActivityError("platform activity socket is not configured")
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(self._socket_path), timeout=_SOCKET_TIMEOUT_SECONDS
                )
            except Exception as exc:
                raise PlatformActivityError(f"platform activity socket unavailable: {exc}") from exc
            self._reader, self._writer = reader, writer
            self._reader_task = asyncio.create_task(self._read_responses(reader, writer))

    async def _read_responses(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        failure: Exception = PlatformActivityError("platform activity stream closed")
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                try:
                    payload = json.loads(raw)
                except Exception as exc:
                    raise PlatformActivityError("platform activity response is invalid") from exc
                request_id = payload.get("requestId") if isinstance(payload, dict) else None
                future = self._pending.get(request_id) if isinstance(request_id, str) else None
                if future is None or future.done():
                    continue
                if payload.get("ok") is not True:
                    future.set_exception(PlatformActivityError(str(payload.get("error") or "platform activity refused")))
                else:
                    future.set_result(payload)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure = exc if isinstance(exc, PlatformActivityError) else PlatformActivityError(str(exc))
            _LOG.warning("platform activity stream failed: %s", failure)
        finally:
            if self._writer is writer:
                self._writer = None
                self._reader = None
            self._fail_pending(failure)

    def _fail_pending(self, error: Exception) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(error)


_client: Optional[PlatformActivityClient] = None


def platform_activity_client() -> PlatformActivityClient:
    global _client
    if _client is None:
        _client = PlatformActivityClient()
    return _client


async def begin_platform_activity() -> PlatformActivityLease:
    """Acquire a lease before beginning a hosted agent turn."""
    return await platform_activity_client().start()
