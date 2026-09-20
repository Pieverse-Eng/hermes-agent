"""Native Message App adaptive-model resolution.

The module deliberately owns transport and validation only.  Model scoring and
the allowed candidate set remain in the Pieverse AI Gateway.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


_METADATA_KEY = "adaptive_model_task"
_ADAPTIVE_MODELS = frozenset({"auto/adaptive", "pieverse/auto/adaptive"})
_TIERS = frozenset({"light", "normal", "strong", "fallback"})
_REASONS = frozenset({"scored", "disabled", "classifier_unavailable"})


class AdaptiveResolutionError(RuntimeError):
    """Adaptive routing failed before any model invocation."""


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
    inbound_id = ctx.event_message_id
    if not inbound_id:
        inbound_id = (
            "restore"
            if not str(ctx.message or "").strip()
            else f"run-{ctx.run_generation}"
        )
    inbound_id = str(inbound_id)
    return f"hermes:{session_id}:{inbound_id}"[:256]


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
    if not goal:
        # Native startup restoration has no new inbound text.  Preserve the last
        # semantic user goal without inventing a lifecycle inference.
        goal = next(
            (m["content"] for m in reversed(history) if m["role"] == "user"), ""
        )
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
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        raise AdaptiveResolutionError(
            f"adaptive model resolution failed: {exc}"
        ) from exc
    if not isinstance(body, dict):
        raise AdaptiveResolutionError(
            "adaptive model resolution returned a non-object response"
        )
    return body


def _validate_decision(decision: Any, request: dict[str, Any]) -> dict[str, Any]:
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
    if _is_auto_alias(decision["model"]):
        raise AdaptiveResolutionError(
            "adaptive model resolution returned an auto alias, not a concrete model"
        )
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
    # Startup auto-resume has no inbound event/message of its own.  It is the
    # same native task, so replay the exact persisted request identity rather
    # than synthesizing a generic "restore" task.
    if not str(ctx.message or "").strip() and stored.get("request"):
        request = stored["request"]
        if stored.get("decision") is not None:
            decision = _validate_decision(stored["decision"], request)
            return AdaptiveSelection(model=decision["model"], decision=decision)
    else:
        request = build_adaptive_request(ctx, max_output_tokens=max_output_tokens)
    if stored.get("request", {}).get("taskId") == request["taskId"]:
        request = stored["request"]
        if stored.get("decision") is not None:
            decision = _validate_decision(stored["decision"], request)
            return AdaptiveSelection(model=decision["model"], decision=decision)
    # Persist before network I/O.  An uncertain response can therefore retry
    # the identical request and identity, never minting a replacement task.
    persisted = session_store.set_session_metadata(
        ctx.session_key, _METADATA_KEY, {"request": request}
    )
    if not persisted:
        raise AdaptiveResolutionError(
            "adaptive routing could not persist the task before resolution"
        )
    decision = _validate_decision(
        post_json(_adaptive_url(base_url), api_key, request), request
    )
    persisted = session_store.set_session_metadata(
        ctx.session_key,
        _METADATA_KEY,
        {"request": request, "decision": decision},
    )
    if not persisted:
        raise AdaptiveResolutionError("adaptive routing could not persist the decision")
    return AdaptiveSelection(model=decision["model"], decision=decision)
