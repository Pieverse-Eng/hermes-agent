"""Generic current-Run host proxy. It never executes native tool handlers."""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import threading
import time
from uuid import uuid4
from gateway.publication_receipts import PUBLICATION_OPERATION, PUBLICATION_REQUEST_BYTES


def _encoded(value, limit):
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError("Host tool payload is too large")
    return encoded


def _error(code, call_id=None):
    return {"status": "error", "error": {"code": code},
            **({"callId": call_id} if call_id else {})}


class HostCallInactive(LookupError):
    """Known authenticated call finished; a late result must not reenter the model."""


class HostToolBroker:
    def __init__(self, run_id, names, publish, *, serial_tools=(), timeout=15):
        self.run_id = run_id
        self.names = frozenset(names)
        self.serial_tools = frozenset(serial_tools)
        if not self.serial_tools <= self.names or not 0 < timeout <= 15:
            raise ValueError("Invalid host tool policy")
        self.publish = publish
        self.timeout = timeout
        self._lock = threading.Lock()
        self._reads = threading.BoundedSemaphore(2)
        self._serial = threading.BoundedSemaphore(1)
        self._pending = {}
        self._settled = {}
        self._closed = False

    def call(self, name, arguments):
        if name not in self.names:
            return _error("HOST_TOOL_UNAVAILABLE")
        try:
            encoded = _encoded(arguments, PUBLICATION_REQUEST_BYTES if name == PUBLICATION_OPERATION else 8192)
        except (ValueError, TypeError, RecursionError):
            return _error("HOST_REQUEST_INVALID")
        call_id = uuid4().hex
        request_hash = hashlib.sha256((name + "\n" + encoded).encode("utf-8")).hexdigest()
        started = time.monotonic()
        slot = self._serial if name in self.serial_tools else self._reads
        if not slot.acquire(timeout=self.timeout):
            return _error("HOST_CALL_NOT_STARTED", call_id)
        entry = {"event": threading.Event(), "hash": request_hash, "reply": None}
        try:
            with self._lock:
                if self._closed:
                    return _error("HOST_CALL_CANCELLED", call_id)
                if len(self._settled) >= 64:
                    return _error("HOST_CALL_LIMIT", call_id)
                self._pending[call_id] = entry
            remaining = max(0, self.timeout - (time.monotonic() - started))
            try:
                self.publish({
                    "event": "host_tool.request", "run_id": self.run_id,
                    "callId": call_id, "name": name, "arguments": json.loads(encoded),
                    "argumentsJson": encoded,
                    "requestHash": request_hash, "deadline": time.time() + remaining,
                })
            except Exception:
                return _error("HOST_CALL_UNKNOWN", call_id)
            entry["event"].wait(timeout=max(0, self.timeout - (time.monotonic() - started)))
            with self._lock:
                if entry["reply"] is None:
                    entry["inactive"] = True
                    self._settled[call_id] = {"hash": request_hash, "reply": None, "inactive": True}
                    return _error("HOST_CALL_UNKNOWN", call_id)
                return deepcopy(entry["reply"])
        finally:
            with self._lock:
                self._pending.pop(call_id, None)
                self._settled.setdefault(call_id, {"hash": request_hash, "reply": entry["reply"],
                                                   "inactive": entry.get("inactive", False)})
            slot.release()

    def resolve(self, call_id, request_hash, reply):
        encoded = _encoded(reply, 32768)
        if reply.get("callId", call_id) != call_id:
            raise ValueError("Wrong call result")
        normalized = {**json.loads(encoded), "callId": call_id}
        with self._lock:
            entry = self._pending.get(call_id)
            settled = self._settled.get(call_id)
            if entry is None:
                if not settled:
                    raise LookupError("Host call is not pending")
                if settled["hash"] != request_hash:
                    raise ValueError("Conflicting host result")
                if settled["reply"] is None or settled.get("inactive", False):
                    raise HostCallInactive("Host call is no longer active")
                if settled["reply"] != normalized:
                    raise ValueError("Conflicting host result")
                return False
            if entry["hash"] != request_hash:
                raise ValueError("Invalid host call result")
            if self._closed or entry.get("inactive", False):
                raise HostCallInactive("Host call is no longer active")
            if entry["reply"] is not None and entry["reply"] != normalized:
                raise ValueError("Conflicting host result")
            entry["reply"] = normalized
            entry["event"].set()
            return True

    def close(self):
        with self._lock:
            self._closed = True
            for call_id, entry in self._pending.items():
                if entry["reply"] is None:
                    entry["reply"] = _error("HOST_CALL_CANCELLED", call_id)
                    entry["inactive"] = True
                entry["event"].set()


_current = ContextVar("current_host_tool_broker", default=None)


@contextmanager
def host_tool_scope(broker):
    token = _current.set(broker)
    try:
        yield
    finally:
        _current.reset(token)


def call_current_host_tool(name, arguments):
    broker = _current.get()
    if broker is None:
        return _error("HOST_TOOL_UNAVAILABLE")
    return broker.call(name, arguments)


