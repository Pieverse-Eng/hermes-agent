"""Redact client-visible tool payloads without changing durable/model transcripts."""
import json
import re

from agent.redact import redact_sensitive_text

from agent.credential_persistence import _is_secret_payload_key, _normalize_key
from agent.redact import _JSON_KEY_NAMES, _SENSITIVE_BODY_KEYS

json_secret_key = re.compile(_JSON_KEY_NAMES, re.IGNORECASE)
json_field = re.compile(r'("(?:\\.|[^"\\])*")\s*:\s*')
json_fragment = re.compile(r'(?<!\\)["\[{]')
json_decoder = json.JSONDecoder()
# Tool events carry public market identifiers and wallet public keys.
# Only these known API fields override the credential pool's broad
# *_key suffix rule; other keys still use its secret classification.
public_identity_fields = frozenset({"market_key", "public_key"})

def _credential_field(key):
    normalized = _normalize_key(key)
    if normalized in public_identity_fields:
        return False
    return (_is_secret_payload_key(key)
            or normalized in _SENSITIVE_BODY_KEYS
            or json_secret_key.fullmatch(normalized) is not None)

public_cursor_fields = frozenset({"cursor", "next_cursor", "next_review_cursor", "next_spot_review_cursor"})
not_public = object()

def _unique_cursor_object(pairs):
    decoded = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError("Duplicate cursor field")
        decoded[key] = value
    return decoded

def _public_receipt_value(key, value):
    normalized = _normalize_key(key)
    if normalized == "command_key":
        # Empty or structured idempotency references cannot be keys.
        if value is None or (isinstance(value, str) and re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_-]{0,31}:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}:[1-9][0-9]{0,9}", value)):
            return value
    if normalized == "scope_key" and isinstance(value, str) and re.fullmatch(
            r"(?:wallet:[A-Z][A-Z0-9]{0,15}|[a-z][a-z0-9_-]{0,31}:(?:spot|perp):[A-Za-z0-9@._-]{1,64}(?::[A-Za-z0-9_.-]{1,128})?)", value):
        if redact_sensitive_text(value, force=True, redact_url_credentials=True) == value:
            return value
    if normalized not in public_cursor_fields or not isinstance(value, str) or len(value) > 2048:
        return not_public
    # Keyset and Paper fact-query cursors are base64 JSON, not single-
    # segment JWTs. Only their bounded, noncredential schemas bypass it.
    import base64
    try:
        payload = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        # Python's decoder ignores whitespace and trailing bytes after padding.
        # Only exempt the exact complete encoding, never an accepted prefix.
        encoded = base64.urlsafe_b64encode(payload).decode("ascii")
        if value not in (encoded, encoded.rstrip("=")):
            return not_public
        decoded = json.loads(payload, object_pairs_hook=_unique_cursor_object)
    except (ValueError, TypeError):
        return not_public
    if isinstance(decoded, dict) and set(decoded) == {"hash", "at", "id"}:
        # Paper facts bind pagination to a SHA-256 query digest and one
        # closed cycle. Keep its exact cursor in both SSE and history;
        # shortening it breaks pagination and broker receipt confirmation.
        if (isinstance(decoded["hash"], str) and re.fullmatch(r"[0-9a-f]{64}", decoded["hash"])
                and isinstance(decoded["at"], str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", decoded["at"])
                and isinstance(decoded["id"], str) and re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", decoded["id"])):
            return value
        return not_public
    if (not isinstance(decoded, dict) or set(decoded) != {"v", "at", "id", "q"}
            or not isinstance(decoded["v"], str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,64}", decoded["v"])
            or not isinstance(decoded["at"], str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", decoded["at"])
            or not isinstance(decoded["id"], str) or not re.fullmatch(r"(?:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|[1-9][0-9]{0,18})", decoded["id"])
            or not isinstance(decoded["q"], list) or len(decoded["q"]) > 20):
        return not_public
    if redact_sensitive_text(decoded["v"], force=True, redact_url_credentials=True) != decoded["v"]:
        return not_public
    import math
    for item in decoded["q"]:
        if isinstance(item, float) and not math.isfinite(item):
            return not_public
        if item is not None and not isinstance(item, (str, int, float, bool)):
            return not_public
        if isinstance(item, str) and (len(item) > 512 or redact_sensitive_text(item, force=True, redact_url_credentials=True) != item):
            return not_public
    return value

def _safe_tool_text(value):
    value = _safe_tool_loose_text(value, redact_text=False)
    # Keep complete JSON fragments structured. Redacting the serialized
    # result again would mask validated public cursors a second time.
    parts = []
    copied_through = search_from = 0
    while match := json_fragment.search(value, search_from):
        search_from = match.end()
        try:
            item, value_end = json_decoder.raw_decode(value, match.start())
        except json.JSONDecodeError:
            continue
        safe = safe_tool_value(item)
        parts.extend((_safe_tool_loose_text(value[copied_through:match.start()]),
                      json.dumps(safe) if safe != item else value[match.start():value_end]))
        copied_through = search_from = value_end
    parts.append(_safe_tool_loose_text(value[copied_through:]))
    return "".join(parts)

def _safe_tool_loose_text(value, *, redact_text=True):
    # Stdout can prefix/suffix JSON fragments with ordinary text. Match
    # field keys, then let the JSON decoder find the complete value
    # boundary (including escaped quotes, arrays and objects).
    parts = []
    copied_through = search_from = 0
    while match := json_field.search(value, search_from):
        search_from = match.end()
        try:
            key = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        try:
            item, value_end = json_decoder.raw_decode(value, search_from)
        except json.JSONDecodeError:
            continue
        # A normal field can contain objects, arrays or JSON-encoded
        # strings with credentials several layers below it. Reuse the
        # same recursive sanitizer rather than skipping its value.
        public = _public_receipt_value(key, item)
        safe = public if public is not not_public else "***" if _credential_field(key) else safe_tool_value(item)
        if safe != item:
            parts.extend((value[copied_through:search_from], json.dumps(safe)))
            copied_through = value_end
        search_from = value_end
    parts.append(value[copied_through:])
    text = "".join(parts)
    return redact_sensitive_text(text, force=True, redact_url_credentials=True) if redact_text else text

def safe_tool_value(value):
    if isinstance(value, str):
        # Some tools embed a JSON object inside an argument/result
        # string. Parse valid structured data before applying key
        # redaction, without changing unaffected strings or their type.
        try:
            structured = json.loads(value)
        except json.JSONDecodeError:
            structured = None
        # JSON strings can contain another encoded JSON string. Each
        # decoded layer is shorter; recurse and restore every original
        # string layer when masking changes its contents.
        if isinstance(structured, (dict, list, str)):
            safe = safe_tool_value(structured)
            return json.dumps(safe) if safe != structured else value
        return _safe_tool_text(value)
    if isinstance(value, (list, tuple)):
        return [safe_tool_value(item) for item in value]
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            # Mask the whole credential value, including numbers,
            # arrays and objects. Never rewrite serialized JSON with a
            # text regex: quoted/newline values can corrupt its syntax.
            public = _public_receipt_value(key, item)
            safe[key] = public if public is not not_public else "***" if _credential_field(key) else safe_tool_value(item)
        return safe
    return value
