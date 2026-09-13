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
import threading
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

_LOG = logging.getLogger(__name__)
_PROTOCOL_VERSION = 1
_SOCKET_TIMEOUT_SECONDS = 5.0
_current_lease: ContextVar[Optional["PlatformActivityLease"]] = ContextVar(
    "platform_activity_lease", default=None
)

# These commands settle or inspect work that is already admitted, so they must
# remain reachable while a hosted drain has paused new activity. Keep this set
# deliberately narrow: every other slash command, including unknown plugin and
# quick-command names, fails closed.
_HOSTED_DRAIN_CONTROL_COMMANDS = frozenset({
    "approve",
    "deny",
    "status",
    "stop",
})


class PlatformActivityError(RuntimeError):
    """The hosted runtime could not obtain or finish its platform lease."""


async def await_platform_activity_task(task: asyncio.Task[Any]) -> tuple[Any, bool]:
    """Wait for an owned protocol task despite repeated caller cancellation."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
        except Exception:
            if cancelled:
                raise asyncio.CancelledError from None
            raise
    return task.result(), cancelled


def platform_activity_enabled() -> bool:
    return (
        os.environ.get("TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED") == "true"
        and bool(os.environ.get("TENANT_RUNTIME_ACTIVITY_SOCKET", "").strip())
    )


def current_platform_activity_lease() -> Optional["PlatformActivityLease"]:
    """Return the activity lease already owning the current dispatch, if any."""
    return _current_lease.get()


def gateway_command_requires_platform_activity(command: Optional[str]) -> bool:
    """Classify a gateway command at the common admission boundary."""
    if not command:
        return False
    from hermes_cli.commands import resolve_command

    definition = resolve_command(command)
    canonical = definition.name if definition else command
    return canonical not in _HOSTED_DRAIN_CONTROL_COMMANDS


@dataclass
class PlatformActivityLease:
    """One platform-authorized unit of interactive/API work."""

    _client: "PlatformActivityClient"
    _handle: Optional[str]
    _workers: set[asyncio.Future[Any]] = field(default_factory=set)
    _finish_task: Optional[asyncio.Task[None]] = None
    _was_admitted: bool = field(init=False)
    _loop: asyncio.AbstractEventLoop = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._was_admitted = self._handle is not None
        self._loop = asyncio.get_running_loop()

    @property
    def active(self) -> bool:
        return self._handle is not None

    @property
    def reusable(self) -> bool:
        """Whether nested work can safely join this still-owned admission."""
        return not self._was_admitted or (
            self.active and self._finish_task is None
        )

    @property
    def stale(self) -> bool:
        """Whether a formerly admitted lease can no longer authorize work."""
        return not self.reusable

    async def finish(self) -> None:
        if self._handle is None:
            return
        if self._finish_task is None:
            self._finish_task = asyncio.create_task(self._finish_when_idle())
        _, cancelled = await await_platform_activity_task(self._finish_task)
        if cancelled:
            raise asyncio.CancelledError

    async def _finish_when_idle(self) -> None:
        # Executor wrappers can time out or be cancelled without stopping their
        # threads. A live worker can also retain a detached child immediately
        # before it exits, so re-read the set until no registered work remains.
        while pending := [worker for worker in self._workers if not worker.done()]:
            await asyncio.gather(*pending, return_exceptions=True)
        if self._handle is not None:
            await self._client.finish(self._handle)
            self._handle = None

    def reserve(self) -> Callable[[], None]:
        """Retain this lease for detached work registered from a worker thread."""
        if not self._was_admitted:
            return lambda: None

        registered = threading.Event()
        holder: dict[str, Any] = {}

        def register() -> None:
            if self.stale:
                holder["error"] = PlatformActivityError(
                    "platform activity is already finishing or finished"
                )
            else:
                future = self._loop.create_future()
                self._workers.add(future)
                holder["future"] = future
            registered.set()

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is self._loop:
            register()
        else:
            self._loop.call_soon_threadsafe(register)
            if not registered.wait(timeout=5):
                raise PlatformActivityError(
                    "timed out registering detached platform activity"
                )

        error = holder.get("error")
        if error is not None:
            raise error
        future = holder["future"]
        release_lock = threading.Lock()
        released = False

        def release() -> None:
            nonlocal released
            with release_lock:
                if released:
                    return
                released = True

            def settle() -> None:
                if not future.done():
                    future.set_result(None)

            try:
                self._loop.call_soon_threadsafe(settle)
            except RuntimeError:
                pass

        return release


@contextmanager
def platform_activity_scope(lease: Optional[PlatformActivityLease]):
    """Set or explicitly clear the admission inherited by child tasks."""
    token = _current_lease.set(lease)
    try:
        yield
    finally:
        _current_lease.reset(token)


def platform_run_in_executor(executor, func, *args) -> asyncio.Future[Any]:
    """Submit work under the current lease without cancelling its real future."""
    lease = _current_lease.get()
    if lease is not None and lease.stale:
        raise PlatformActivityError("platform activity is already finishing or finished")
    future = asyncio.get_running_loop().run_in_executor(executor, func, *args)
    if lease is not None and lease.active:
        lease._workers.add(future)
        return asyncio.shield(future)
    return future


async def platform_to_thread(func, /, *args, **kwargs) -> Any:
    """Run blocking turn work while retaining its real worker for residency."""
    lease = _current_lease.get()
    if lease is not None and lease.stale:
        raise PlatformActivityError("platform activity is already finishing or finished")
    worker = asyncio.create_task(asyncio.to_thread(func, *args, **kwargs))
    if lease is not None and lease.active:
        lease._workers.add(worker)
        return await asyncio.shield(worker)
    return await worker


def reserve_platform_activity() -> Callable[[], None]:
    """Reserve the current lease until a detached operation calls the result."""
    lease = _current_lease.get()
    if lease is None or not lease.active:
        return lambda: None
    return lease.reserve()


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
        self._requests: dict[str, dict[str, Any]] = {}
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._active_handles: set[str] = set()
        self._closing = False
        self._failed = False

    @property
    def enabled(self) -> bool:
        return platform_activity_enabled() and bool(self._socket_path)

    async def start(self) -> PlatformActivityLease:
        if not self.enabled:
            return PlatformActivityLease(self, None)
        if self._failed:
            raise PlatformActivityError("platform activity producer has failed")
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
        payload, cancelled = await await_platform_activity_task(request_task)
        handle = payload.get("activityHandle")
        if not isinstance(handle, str) or not handle:
            raise PlatformActivityError("platform activity start returned no handle")
        if cancelled:
            # The supervisor accepted this exact admission while its caller was
            # being cancelled. Finish only that handle on the existing shared
            # stream; closing the stream would abandon unrelated live workers.
            finish_task = asyncio.create_task(self.finish(handle))
            await await_platform_activity_task(finish_task)
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
        _, cancelled = await await_platform_activity_task(request_task)
        if cancelled:
            raise asyncio.CancelledError

    async def close(self) -> None:
        self._closing = True
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
        self._requests[request_id] = request
        try:
            wire = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
            while True:
                async with self._write_lock:
                    writer = self._writer
                    if writer is None or writer.is_closing():
                        raise PlatformActivityError("platform activity stream is unavailable")
                    writer.write(wire)
                    await writer.drain()
                try:
                    # A deadline is not a negative acknowledgement. Keep the
                    # correlation future alive and replay identical bytes on the
                    # same stream; the supervisor deduplicates this request ID.
                    return await asyncio.wait_for(
                        asyncio.shield(response), timeout=_SOCKET_TIMEOUT_SECONDS
                    )
                except asyncio.TimeoutError:
                    continue
        except PlatformActivityError:
            raise
        except Exception as exc:
            self._fail_producer(exc)
            raise PlatformActivityError(f"platform activity request failed: {exc}") from exc
        finally:
            self._pending.pop(request_id, None)
            self._requests.pop(request_id, None)

    async def _ensure_connected(self) -> None:
        if self._failed or self._closing:
            raise PlatformActivityError("platform activity producer is closed")
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
                request = self._requests[request_id]
                if (payload.get("version") != _PROTOCOL_VERSION
                        or payload.get("operation") != request["operation"]):
                    raise PlatformActivityError("platform activity response does not match request")
                if payload.get("ok") is not True:
                    future.set_exception(PlatformActivityError(str(payload.get("error") or "platform activity refused")))
                else:
                    if payload.get("operation") == "start":
                        handle = payload.get("activityHandle")
                        if not isinstance(handle, str) or not handle:
                            raise PlatformActivityError("platform activity start returned no handle")
                        self._active_handles.add(handle)
                    elif payload.get("operation") == "finish":
                        self._active_handles.discard(request["activityHandle"])
                    future.set_result(payload)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure = exc if isinstance(exc, PlatformActivityError) else PlatformActivityError(str(exc))
            _LOG.warning("platform activity stream failed: %s", failure)
        finally:
            writer.close()
            if self._writer is writer:
                self._writer = None
                self._reader = None
            self._fail_pending(failure)
            if not self._closing:
                self._fail_producer(failure)

    def _fail_producer(self, error: Exception) -> None:
        if self._failed:
            return
        if not self._active_handles and not self._pending:
            # A fully settled producer owns no supervisor state. Its successor
            # stream can safely establish a fresh session after an idle EOF.
            return
        self._failed = True
        if self._writer is not None:
            self._writer.close()
        if self._active_handles or self._pending:
            # Stream loss stops supervisor heartbeats. Python cancellation cannot
            # stop executor threads, and an unresolved request may have committed
            # without its acknowledgement reaching us. The hosted process cannot
            # safely continue after losing that ownership information.
            _LOG.critical("Hosted activity protection lost; terminating runtime: %s", error)
            os._exit(1)

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
