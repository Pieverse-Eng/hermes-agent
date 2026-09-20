"""Native Message App adaptive-model resolution.

The module deliberately owns transport and validation only.  Model scoring and
the allowed candidate set remain in the Pieverse AI Gateway.
"""

from __future__ import annotations

import json
import http.client
import logging
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable


_METADATA_KEY = "adaptive_model_task"
_ADAPTIVE_MODELS = frozenset({"auto/adaptive", "pieverse/auto/adaptive"})
_TIERS = frozenset({"light", "normal", "strong", "fallback"})
_REASONS = frozenset({"scored", "disabled", "classifier_unavailable"})
_LOCAL_FALLBACK_MODEL = "auto/paid"
logger = logging.getLogger(__name__)


class AdaptiveResolutionError(RuntimeError):
    """Adaptive routing failed before any model invocation."""


class AdaptiveScoringUnavailable(AdaptiveResolutionError):
    """The scoring service is transiently unavailable for this native task."""


@dataclass(frozen=True)
class AdaptiveSelection:
    model: str
    decision: dict[str, Any]


def is_adaptive_model(model: Any) -> bool:
    return isinstance(model, str) and model.strip().lower() in _ADAPTIVE_MODELS


def _is_auto_alias(model: str) -> bool:
    normalized = model.strip().lower()
    return normalized in {"auto", "adaptive"} or normalized.startswith(
        ("auto/", "pieverse/auto/")
    )


def adaptive_observability_headers(decision: dict[str, Any] | None) -> dict[str, str]:
    """Map the latched native identity onto existing AI Gateway headers."""
    if not decision:
        return {}
    return {
        "x-pieverse-turn-id": str(decision["taskId"]),
        "x-pieverse-chat-id": str(decision["sessionId"]),
    }


def _task_id(ctx: Any) -> str:
    session_id = str(ctx.session_id or ctx.session_key or "unknown-session")
    inbound_id = ctx.inbound_message_id
    if not inbound_id:
        # Generations are process-local and shared by completed queued turns.
        # Latch a fresh identity for this turn; the request is persisted before
        # scoring so explicit recovery can replay it after a restart.
        inbound_id = f"synthetic-{uuid.uuid4().hex}"
        ctx.inbound_message_id = inbound_id
    task_id = f"hermes:{session_id}:{inbound_id}"
    if len(task_id) > 256:
        # Keep long native IDs distinct instead of truncating their suffixes.
        task_id = f"hermes:{uuid.uuid5(uuid.NAMESPACE_URL, task_id).hex}"
    return task_id


def _semantic_text(content: Any) -> str | None:
    if isinstance(content, str):
        return content[:8000]
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") in {
                "text",
                "input_text",
                "output_text",
            }:
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)[:8000] or None
    return None


def build_adaptive_request(ctx: Any, *, max_output_tokens: int) -> dict[str, Any]:
    history = []
    for item in ctx.history or []:
        if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"}:
            continue
        content = _semantic_text(item.get("content"))
        if content:
            history.append({"role": item["role"], "content": content})
    history = history[-12:]
    goal = str(ctx.message or "").strip()
    if not goal and ctx.adaptive_resume_pending:
        # The native runner validates the live recovery marker before setting
        # this flag. Empty user input alone never identifies a resumed task.
        goal = next(
            (m["content"] for m in reversed(history) if m["role"] == "user"), ""
        )
    if not goal and "image" in (ctx.native_modalities or ()):
        # Pixels are attached after routing. Describe this new input without
        # borrowing an unrelated previous user goal or inventing image content.
        goal = "The user sent an image without a caption."
    if not goal:
        raise AdaptiveResolutionError("adaptive routing requires a non-empty task goal")
    goal = goal[:32000]
    modalities = list(dict.fromkeys(ctx.native_modalities or ("text",)))
    if "text" not in modalities:
        modalities.insert(0, "text")
    # UTF-8 bytes / 3 is intentionally conservative for ordinary prose.  Add
    # the fixed reserve afterwards because it is already expressed in tokens;
    # it accounts for native system/context instructions and tool schemas that
    # are not all materialized until AIAgent construction.
    input_text = "\n".join(
        [goal, str(ctx.context_prompt or ""), str(ctx.channel_prompt or "")]
        + [str(x) for x in (ctx.enabled_toolsets or [])]
    )
    try:
        full_history_bytes = len(
            json.dumps(ctx.history or [], ensure_ascii=False, default=str).encode("utf-8")
        )
    except Exception:
        full_history_bytes = len(str(ctx.history or []).encode("utf-8"))
    estimated_input_bytes = len(input_text.encode("utf-8")) + full_history_bytes
    estimated_input_tokens = (estimated_input_bytes + 2) // 3
    context_tokens = min(2_000_000, max(1, estimated_input_tokens + 32768))
    return {
        "taskId": _task_id(ctx),
        "sessionId": str(ctx.session_id or ctx.session_key or "unknown-session")[:256],
        "runtime": "hermes",
        "goal": goal,
        "history": history,
        "contextTokens": context_tokens,
        "maxOutputTokens": max(1, min(2_000_000, int(max_output_tokens))),
        "modalities": modalities[:4],
        "requiresTools": True,
    }


def _adaptive_url(base_url: str) -> str:
    base = str(base_url or "").rstrip("/")
    if not base:
        raise AdaptiveResolutionError(
            "adaptive routing requires the Pieverse AI Gateway base URL"
        )
    try:
        parsed = urllib.parse.urlsplit(base)
        port = parsed.port
    except ValueError as exc:
        raise AdaptiveResolutionError("invalid Pieverse AI Gateway URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise AdaptiveResolutionError("invalid Pieverse AI Gateway URL")
    if base.endswith("/v1"):
        return f"{base}/adaptive/resolve"
    return f"{base}/v1/adaptive/resolve"


def _post_json(url: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw_body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 429 or exc.code >= 500:
            raise AdaptiveScoringUnavailable(f"http_{exc.code}") from exc
        raise AdaptiveResolutionError(
            f"adaptive model resolution failed with HTTP {exc.code}"
        ) from exc
    except (OSError, http.client.IncompleteRead) as exc:
        raise AdaptiveScoringUnavailable("network") from exc
    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AdaptiveResolutionError(
            "adaptive model resolution returned invalid JSON"
        ) from exc
    if not isinstance(body, dict):
        raise AdaptiveResolutionError(
            "adaptive model resolution returned a non-object response"
        )
    return body


def _validate_decision(
    decision: Any,
    request: dict[str, Any],
    *,
    allow_local_fallback: bool = False,
) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise AdaptiveResolutionError(
            "adaptive model resolution returned an invalid decision"
        )
    if (
        decision.get("taskId") != request["taskId"]
        or decision.get("sessionId") != request["sessionId"]
    ):
        raise AdaptiveResolutionError(
            "adaptive model resolution returned the wrong task identity"
        )
    if decision.get("provider") != "pieverse":
        raise AdaptiveResolutionError(
            "adaptive model resolution returned an unexpected provider"
        )
    if not isinstance(decision.get("model"), str) or not decision["model"].strip():
        raise AdaptiveResolutionError(
            "adaptive model resolution returned no concrete model"
        )
    local_fallback = (
        allow_local_fallback
        and decision.get("localFallback") == "scoring_unavailable"
        and decision["model"] == _LOCAL_FALLBACK_MODEL
    )
    if _is_auto_alias(decision["model"]) and not local_fallback:
        raise AdaptiveResolutionError(
            "adaptive model resolution returned an auto alias, not a concrete model"
        )
    if local_fallback:
        return dict(decision)
    if decision.get("tier") not in _TIERS or decision.get("reason") not in _REASONS:
        raise AdaptiveResolutionError(
            "adaptive model resolution returned an unknown policy result"
        )
    for key in ("policyVersion", "rubricVersion"):
        if not isinstance(decision.get(key), (int, float)):
            raise AdaptiveResolutionError(f"adaptive model resolution omitted {key}")
    if not isinstance(decision.get("decidedAt"), str) or not decision["decidedAt"]:
        raise AdaptiveResolutionError("adaptive model resolution omitted decidedAt")
    return dict(decision)


def resolve_adaptive_model(
    *,
    ctx: Any,
    session_store: Any,
    base_url: str,
    api_key: str,
    max_output_tokens: int,
    post_json: Callable[[str, str, dict[str, Any]], dict[str, Any]] = _post_json,
) -> AdaptiveSelection:
    if not isinstance(api_key, str) or not api_key.startswith("sk-pv-"):
        raise AdaptiveResolutionError(
            "adaptive routing requires the current Pieverse API key"
        )
    # Validate that the current runtime still points at a concrete endpoint,
    # even when a restored decision means this invocation will not issue I/O.
    _adaptive_url(base_url)
    stored = (
        session_store.get_session_metadata(ctx.session_key, _METADATA_KEY, {}) or {}
    )
    # Startup restoration and real messages continue a saved task only when
    # the native runner has validated its explicit resume-pending marker.
    # Captionless media are new tasks, even though their text is also empty.
    if (
        ctx.adaptive_resume_pending
        and stored.get("request", {}).get("sessionId")
        == str(ctx.session_id or ctx.session_key or "unknown-session")[:256]
    ):
        request = stored["request"]
        if stored.get("decision") is not None:
            decision = _validate_decision(
                stored["decision"], request, allow_local_fallback=True
            )
            return AdaptiveSelection(model=decision["model"], decision=decision)
    else:
        request = build_adaptive_request(ctx, max_output_tokens=max_output_tokens)
    if stored.get("request", {}).get("taskId") == request["taskId"]:
        request = stored["request"]
        if stored.get("decision") is not None:
            decision = _validate_decision(
                stored["decision"], request, allow_local_fallback=True
            )
            return AdaptiveSelection(model=decision["model"], decision=decision)
    # Persist before network I/O so either a concrete decision or the local
    # scoring-unavailable fallback remains bound to the original task identity.
    persisted = session_store.set_session_metadata(
        ctx.session_key, _METADATA_KEY, {"request": request}, require_primary=True
    )
    if not persisted:
        raise AdaptiveResolutionError(
            "adaptive routing could not persist the task before resolution"
        )
    local_fallback = False
    try:
        decision = _validate_decision(
            post_json(_adaptive_url(base_url), api_key, request), request
        )
    except AdaptiveScoringUnavailable:
        local_fallback = True
        decision = {
            "taskId": request["taskId"],
            "sessionId": request["sessionId"],
            "model": _LOCAL_FALLBACK_MODEL,
            "provider": "pieverse",
            "localFallback": "scoring_unavailable",
        }
    persisted = session_store.set_session_metadata(
        ctx.session_key,
        _METADATA_KEY,
        {"request": request, "decision": decision},
        require_primary=True,
    )
    if not persisted:
        raise AdaptiveResolutionError("adaptive routing could not persist the decision")
    if local_fallback:
        logger.warning(
            "Adaptive scoring unavailable; using auto/paid",
            extra={
                "adaptive_reason": "scoring_unavailable",
                "task_id": request["taskId"],
                "session_id": request["sessionId"],
            },
        )
    return AdaptiveSelection(model=decision["model"], decision=decision)
