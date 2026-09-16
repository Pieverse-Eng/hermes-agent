"""Session-independent Skill Store activation using the native skill catalog."""

from __future__ import annotations

import asyncio
import inspect
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class SkillActivationError(ValueError):
    """The requested skill could not be activated safely."""


def _reload_catalog(skill: str | None) -> dict[str, Any]:
    from agent.skill_commands import (
        reload_skills,
        snapshot_skill_commands,
        unregister_skill_commands_for_security,
    )
    from tools.skill_security_gate import ensure_skill_certik_allowed_for_session_load

    if skill is not None:
        from tools.skills_tool import _skills_dir

        directory = _skills_dir() / skill
        if not (directory / "SKILL.md").is_file():
            raise SkillActivationError("Installed skill is unavailable")
        try:
            allowed = ensure_skill_certik_allowed_for_session_load(directory).allowed
        except Exception:
            allowed = False
        if not allowed:
            raise SkillActivationError(
                "Installed skill is rejected by the security gate"
            )

    result = reload_skills()
    rejected = set()
    for command, info in snapshot_skill_commands().items():
        directory = Path(info["skill_dir"])
        try:
            allowed = ensure_skill_certik_allowed_for_session_load(directory).allowed
        except Exception:
            allowed = False
        if not allowed:
            rejected.update((command, info.get("name", ""), directory.name))
    blocked = unregister_skill_commands_for_security(rejected)
    return {
        "added": sum(
            item.get("name") not in {entry["command"].lstrip("/") for entry in blocked}
            for item in result["added"]
        ),
        "removed": len(result["removed"]),
        "total": len(snapshot_skill_commands()),
        "blocked": len(blocked),
        "existingSessionCachesInvalidated": False,
    }


async def reload_platform_skills(
    runner: Any, skill: str | None = None
) -> dict[str, Any]:
    """Refresh catalogs while leaving active turns and cached prompts intact.

    Existing agents discover skills through the live skills_list/skill_view
    tools. Cached gateway conversations also receive the same next-turn hint
    used by /reload-skills; no synthetic event or transcript write is emitted.
    Invocation keeps the normal CertiK gate, including content revalidation.
    """
    from gateway.platform_activity import (
        await_platform_activity_task,
        platform_to_thread,
    )

    lock = getattr(runner, "_platform_skills_reload_lock", None)
    if lock is None:
        lock = runner._platform_skills_reload_lock = asyncio.Lock()
    async with lock:
        # Keep serialization until the actual executor exits, even if the HTTP
        # request is cancelled. Shielding only the worker releases the lock early.
        task = asyncio.create_task(platform_to_thread(_reload_catalog, skill))
        result, cancelled = await await_platform_activity_task(task)
        result["adapterRefreshFailures"] = 0
        for adapter in list(runner.adapters.values()):
            refresh = getattr(adapter, "refresh_skill_group", None)
            if callable(refresh):
                try:
                    pending = refresh()
                    if inspect.isawaitable(pending):
                        await pending
                except Exception:
                    result["adapterRefreshFailures"] += 1
                    logger.warning("Skill adapter refresh failed", exc_info=True)
        # Snapshot only the in-memory session keys. Never rebuild a cached agent
        # or mutate the transcript while its current turn is executing.
        cache_lock = getattr(runner, "_agent_cache_lock", None)
        if cache_lock is not None:
            with cache_lock:
                keys = set(getattr(runner, "_agent_cache", {}))
        else:
            keys = set(getattr(runner, "_agent_cache", {}))
        keys.update(getattr(runner, "_running_agents", {}))
        notes = getattr(runner, "_pending_skills_reload_notes", None)
        if notes is None:
            notes = runner._pending_skills_reload_notes = {}
        for key in keys:
            notes[key] = (
                "[Skills were refreshed. Use skills_list to see the updated catalog.]"
            )
        if cancelled:
            raise asyncio.CancelledError
        return result
