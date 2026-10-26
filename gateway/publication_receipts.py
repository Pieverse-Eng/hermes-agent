"""Run-local, host-acknowledged publication; never an advertised model tool."""
from copy import deepcopy
import hashlib
import json
import threading
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

PUBLICATION_OPERATION = "__publish_current_message"
PUBLICATION_REQUEST_BYTES = 65536


class CorrectionField(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: str = Field(max_length=120)
    code: str = Field(pattern=r"^[a-z_]{1,64}$")
    message: str | None = Field(default=None, max_length=240)
    allowedValues: list[Annotated[str, Field(max_length=80)]] | None = Field(default=None, max_length=30)
    unknownKeys: list[Annotated[str, Field(max_length=80)]] | None = Field(default=None, max_length=20)


class Correction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    category: str = Field(pattern=r"^[a-z_]{1,64}$")
    recovery: str = Field(pattern=r"^[a-z_]{1,64}$")
    fields: list[CorrectionField] = Field(default_factory=list, max_length=20)
    retrySameInput: bool


def _public_correction(raw):
    try:
        return Correction.model_validate(raw).model_dump(exclude_none=True)
    except (ValueError, TypeError):
        return None


class Registration(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status: Literal["registered"]
    messageId: str = Field(min_length=1, max_length=200)
    runId: UUID
    sessionId: UUID
    hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class AcknowledgedPublisher:
    """One instance per native Run. Retries preserve identity, never prepare orders.

    Structured messages are deduplicated only within this Run. Unknown delivery
    retains its identity so a later retry can restore the original publication.
    The broker keeps its existing request-size, deadline and Stop boundaries.
    """

    def __init__(self, broker, deliver):
        self._broker = broker
        self._deliver = deliver
        self._lock = threading.Lock()
        self._messages = {}

    def __call__(self, message, message_id, context, metadata=None):
        structured = metadata is not None or "reply_markup" in message
        key = hashlib.sha256(json.dumps(
            {"message": message, "metadata": metadata}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode()).hexdigest()
        key = ("structured:" if structured else "plain:") + key
        # Serializes a repeated publication even when parallel tool workers share
        # this Run. The host broker bounds the wait; other Runs use another lock.
        with self._lock:
            entry = self._messages.get(key)
            if entry is None:
                if len(self._messages) >= 64:
                    return {"success": False, "error": "PUBLICATION_LIMIT", "retrySameInput": False}
                entry = self._messages[key] = {"id": message_id}
            message_id = entry["id"]
            if "delivered" in entry:
                return {**deepcopy(entry["delivered"]), "duplicate": True}
            if "rejected" in entry:
                return deepcopy(entry["rejected"])
            payload = {"success": True, "message_id": message_id, "message": message,
                       **({"metadata": metadata} if metadata is not None else {})}
            if "registration" not in entry:
                result = self._broker.call(PUBLICATION_OPERATION, payload)
                try:
                    registration = Registration.model_validate(result.get("publication"))
                    if result.get("status") != "ready" or registration.messageId != message_id:
                        raise ValueError("Mismatched registration")
                    registered = result.get('registered', {})
                    if not isinstance(registered, dict):
                        raise ValueError('Invalid registered resources')
                    encoded = json.dumps(registered, allow_nan=False, ensure_ascii=False)
                    if len(encoded.encode('utf-8')) > 32768:
                        raise ValueError('Registered resources too large')
                except (ValueError, TypeError):
                    error = result.get("error") or {}
                    reason = result.get("reason") or (error.get("code") if isinstance(error, dict) else None)
                    failed = {"success": False, "message_id": message_id,
                              "error": reason or "PUBLICATION_UNCONFIRMED",
                              "publication": {"status": "rejected" if result.get("status") == "blocked" else "unknown"},
                              **({"callId": result["callId"]} if result.get("callId") else {}),
                              "retrySameInput": result.get("retrySameInput", reason not in {
                                  "HOST_REQUEST_INVALID", "HOST_CALL_LIMIT", "HOST_TOOL_UNAVAILABLE",
                                  "HOST_CALL_CANCELLED"})}
                    correction = _public_correction(result.get("failure"))
                    if correction is not None:
                        failed["failure"] = correction
                    if failed["retrySameInput"] is False:
                        entry["rejected"] = failed
                    return deepcopy(failed)
                entry["registration"] = registration.model_dump(mode="json")
                # Opaque, bounded host acknowledgement (not model metadata).
                # Follow-up operations need its original resource identities.
                entry['registered'] = json.loads(encoded)
                # Older hosts may omit registered entirely. They still confirm
                # publication, but never register the original Run context.
                entry["presentation"] = {"context": None}
                entry["presentation"].update({
                    key: deepcopy(entry["registered"][key])
                    for key in ("context", "coachCard", "callbackScope")
                    if key in entry["registered"]
                })
            receipt = deepcopy(entry["registration"])
            try:
                self._deliver(message, message_id, context, metadata,
                              presentation=deepcopy(entry["presentation"]))
            except Exception:
                return {"success": False, "message_id": message_id,
                        "error": "CURRENT_MESSAGE_DELIVERY_UNKNOWN", "publication": receipt,
                        "retrySameInput": True}
            # The tool result keeps both: the presented card, callback scope and
            # context at top level, and the whole acknowledgement as `registered`.
            delivered = {"success": True, "message_id": message_id, "publication": receipt,
                         **deepcopy(entry["presentation"])}
            if entry.get('registered'):
                delivered['registered'] = deepcopy(entry['registered'])
            if structured:
                entry["delivered"] = delivered
            else:
                # Retain uncertain plain messages, but a successful repeated
                # sentence may be an intentional second message.
                self._messages.pop(key, None)
            return deepcopy(delivered)
