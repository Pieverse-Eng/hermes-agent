"""Pieverse AI Gateway BYOK command.

This plugin intentionally runs outside the agent path: users can replace the
tenant AI Gateway key with /pieverse-byok even when their current model has no
credit.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PIEVERSE_KEY_RE = re.compile(r"\bsk-pv-[0-9a-f]{48}\b")
COMMAND_NAME = "pieverse-byok"
INTENT_CUES = (
    "pieai",
    "pie ai",
    "pieverse",
    "pieverse byok",
    "pieverse-byok",
    "ai gateway",
    "api key",
    "apikey",
    "byok",
    "key",
)


def _extract_keys(text: str) -> list[str]:
    return PIEVERSE_KEY_RE.findall(text or "")


def _extract_single_key(text: str) -> str | None:
    keys = list(dict.fromkeys(_extract_keys(text)))
    if len(keys) != 1:
        return None
    return keys[0]


def _mask_key(key: str) -> str:
    return f"{key[:10]}...{key[-4:]}"


def _should_rewrite_to_command(text: str) -> str | None:
    stripped = (text or "").strip()
    if not stripped or stripped.startswith("/"):
        return None

    key = _extract_single_key(stripped)
    if not key:
        return None

    remainder = PIEVERSE_KEY_RE.sub("", stripped).strip()
    if not remainder:
        return key

    lowered = stripped.lower()
    if any(cue in lowered for cue in INTENT_CUES):
        return key
    return None


def _platform_url(instance_id: str) -> str:
    base = os.environ.get("WALLET_API_URL") or os.environ.get("PIEVERSE_CP_URL")
    if not base:
        raise RuntimeError("WALLET_API_URL is not configured")
    encoded_id = urllib.parse.quote(instance_id, safe="")
    return f"{base.rstrip('/')}/v1/instances/{encoded_id}/ai-gateway-key"


def _platform_token() -> str:
    token = os.environ.get("WALLET_API_TOKEN") or os.environ.get("PIEVERSE_API_KEY")
    if not token:
        raise RuntimeError("WALLET_API_TOKEN is not configured")
    return token


def _parse_json_body(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _save_key(api_key: str) -> dict[str, Any]:
    instance_id = os.environ.get("INSTANCE_ID")
    if not instance_id:
        raise RuntimeError("INSTANCE_ID is not configured")

    payload = json.dumps({"apiKey": api_key}).encode("utf-8")
    req = urllib.request.Request(
        _platform_url(instance_id),
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {_platform_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return _parse_json_body(resp.read())
    except urllib.error.HTTPError as exc:
        body = _parse_json_body(exc.read())
        message = body.get("error") if isinstance(body.get("error"), str) else None
        code = body.get("code") if isinstance(body.get("code"), str) else None
        return {
            "ok": False,
            "error": message or f"Platform API returned HTTP {exc.code}",
            "code": code,
        }


def _gateway_pid_file() -> Path:
    return Path(os.environ.get("HERMES_HOME") or "/opt/data") / "gateway.pid"


def _restart_gateway_from_pid_file() -> None:
    try:
        raw = _gateway_pid_file().read_text(encoding="utf-8")
        pid = json.loads(raw).get("pid")
        sigusr1 = getattr(signal, "SIGUSR1", None)
        if isinstance(pid, int) and pid > 0 and sigusr1 is not None:
            os.kill(pid, sigusr1)
    except Exception:
        return


def _schedule_gateway_restart(delay_seconds: float = 5.0) -> None:
    timer = threading.Timer(delay_seconds, _restart_gateway_from_pid_file)
    timer.daemon = True
    timer.start()


def _handle_pieverse_byok_sync(raw_args: str) -> str:
    api_key = _extract_single_key(raw_args.strip())
    if not api_key:
        return f"Usage: /{COMMAND_NAME} sk-pv-<48 lowercase hex characters>"

    try:
        result = _save_key(api_key)
    except Exception as exc:
        return f"Could not save your Pieverse AI Gateway key: {exc}"

    if not result.get("ok"):
        error = result.get("error")
        message = error if isinstance(error, str) else "Platform API rejected the key"
        return f"Could not save your Pieverse AI Gateway key: {message}"

    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    masked = data.get("key") if isinstance(data.get("key"), str) else _mask_key(api_key)
    if data.get("runtimeSyncPending"):
        return (
            f"Saved your Pieverse AI Gateway key ({masked}). "
            "Hermes will use it after the next runtime refresh."
        )
    if data.get("restartRequired"):
        _schedule_gateway_restart()
        return (
            f"Saved your Pieverse AI Gateway key ({masked}). "
            "Hermes is refreshing now and will use your key next."
        )
    return (
        f"Saved your Pieverse AI Gateway key ({masked}). Hermes will use your key next."
    )


async def _handle_pieverse_byok(raw_args: str) -> str:
    return await asyncio.to_thread(_handle_pieverse_byok_sync, raw_args)


def _pre_gateway_dispatch(**kwargs: Any) -> dict[str, str] | None:
    event = kwargs.get("event")
    text = getattr(event, "text", "") if event is not None else ""
    key = _should_rewrite_to_command(text)
    if not key:
        return None
    return {"action": "rewrite", "text": f"/{COMMAND_NAME} {key}"}


def register(ctx) -> None:
    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch)
    ctx.register_command(
        COMMAND_NAME,
        handler=_handle_pieverse_byok,
        description="Set the Pieverse AI Gateway key for this Hermes tenant.",
        args_hint="[sk-pv-key]",
        platforms=("telegram", "line", "slack"),
    )
