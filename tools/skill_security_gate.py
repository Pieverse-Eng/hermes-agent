"""Load-time CertiK gate for Hermes skills.

This module is intentionally fail-closed: a skill is allowed into the session
prompt only when the current directory fingerprint has a CertiK ``allow`` stamp.
Missing credentials, scanner retry responses, and scanner errors all block load.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from hermes_constants import get_skills_dir
from utils import atomic_json_write

from tools.skill_security_certik import (
    SkillSecurityArchive,
    SkillSecurityScanError,
    build_skill_security_archive,
    scan_skill_dir_with_platform,
)

_INDEX_VERSION = 2
_INDEX_LOCK = threading.Lock()
_WARNINGS_LOCK = threading.Lock()
_WARNINGS: list[str] = []
_SLUG_RE = re.compile(r"[^a-z0-9-]+")


@dataclass(frozen=True)
class SkillFingerprint:
    value: str
    file_count: int
    byte_count: int


@dataclass(frozen=True)
class SkillSecurityDecision:
    allowed: bool
    reason: str
    fingerprint: str
    scan_id: str | None = None
    source: str = "certik"
    archive: SkillSecurityArchive | None = None


class SkillFingerprintError(RuntimeError):
    """Raised when a skill directory cannot be fingerprinted safely."""


def drain_skill_security_warnings() -> list[str]:
    with _WARNINGS_LOCK:
        out = list(_WARNINGS)
        _WARNINGS.clear()
    return out


def _record_warning(message: str) -> None:
    with _WARNINGS_LOCK:
        if message not in _WARNINGS:
            _WARNINGS.append(message)


def security_index_path() -> Path:
    return get_skills_dir() / ".hub" / "security-index.json"


def _read_index() -> dict[str, Any]:
    path = security_index_path()
    if not path.exists():
        return {"version": _INDEX_VERSION, "skills": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": _INDEX_VERSION, "skills": {}}
    if not isinstance(data, dict):
        return {"version": _INDEX_VERSION, "skills": {}}
    skills = data.get("skills")
    if not isinstance(skills, dict):
        skills = {}
    return {"version": _INDEX_VERSION, "skills": skills}


def _write_index(data: dict[str, Any]) -> None:
    data["version"] = _INDEX_VERSION
    data.setdefault("skills", {})
    atomic_json_write(security_index_path(), data, mode=0o600)


def _record_outcome(key: str, record: dict[str, Any]) -> None:
    with _INDEX_LOCK:
        data = _read_index()
        skills = data.setdefault("skills", {})
        skills[key] = record
        _write_index(data)


def _skill_key(skill_dir: Path) -> str:
    resolved = skill_dir.resolve()
    local_root = get_skills_dir().resolve()
    try:
        rel = resolved.relative_to(local_root)
        return f"local:{rel.as_posix()}"
    except ValueError:
        return "path:" + sha256(str(resolved).encode("utf-8")).hexdigest()


def _skill_slug(skill_dir: Path) -> str:
    raw = skill_dir.name.strip().lower().replace("_", "-")
    slug = _SLUG_RE.sub("-", raw).strip("-")
    if not slug or not slug[0].isalnum():
        slug = "skill"
    return slug[:128]


def fingerprint_skill_dir(skill_dir: Path) -> SkillFingerprint:
    try:
        archive = build_skill_security_archive(skill_dir)
    except SkillSecurityScanError as exc:
        raise SkillFingerprintError(str(exc)) from exc
    return SkillFingerprint(
        value=archive.fingerprint,
        file_count=archive.file_count,
        byte_count=archive.byte_count,
    )


def _allow_record_matches(record: Any, fingerprint: str) -> bool:
    return (
        isinstance(record, dict)
        and record.get("provider") == "certik"
        and record.get("decision") == "allow"
        and record.get("fingerprint") == fingerprint
    )


def ensure_skill_certik_allowed_for_session_load(
    skill_dir: Path,
    *,
    archive: SkillSecurityArchive | None = None,
) -> SkillSecurityDecision:
    """Return whether *skill_dir* may be included in a freshly loaded session."""
    skill_dir = skill_dir.resolve()
    key = _skill_key(skill_dir)
    try:
        scan_archive = archive or build_skill_security_archive(skill_dir)
    except SkillSecurityScanError as exc:
        reason = str(exc)
        _record_warning(f'Skill "{skill_dir.name}" was not loaded: {reason}')
        return SkillSecurityDecision(False, reason, fingerprint="")
    fp = SkillFingerprint(
        value=scan_archive.fingerprint,
        file_count=scan_archive.file_count,
        byte_count=scan_archive.byte_count,
    )

    with _INDEX_LOCK:
        record = _read_index().get("skills", {}).get(key)
    if _allow_record_matches(record, fp.value):
        return SkillSecurityDecision(
            True,
            "Previously verified by CertiK",
            fingerprint=fp.value,
            scan_id=record.get("scanId") if isinstance(record, dict) else None,
            archive=scan_archive,
        )

    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        scan = scan_skill_dir_with_platform(
            skill_dir,
            skill_slug=_skill_slug(skill_dir),
            archive=scan_archive,
        )
    except SkillSecurityScanError as exc:
        reason = f"CertiK security verification could not run: {exc}"
        _record_outcome(
            key,
            {
                "provider": "certik",
                "decision": "retry",
                "fingerprint": fp.value,
                "checkedAt": checked_at,
                "reason": reason,
                "fileCount": fp.file_count,
                "byteCount": fp.byte_count,
            },
        )
        _record_warning(f'Skill "{skill_dir.name}" was not loaded: {reason}')
        return SkillSecurityDecision(
            False,
            reason,
            fingerprint=fp.value,
            archive=scan_archive,
        )

    allowed = scan.decision == "allow"
    record = {
        "provider": "certik",
        "decision": scan.decision,
        "fingerprint": fp.value,
        "checkedAt": checked_at,
        "reason": scan.reason,
        "scanId": scan.scan_id,
        "archiveSha256": scan.archive_sha256,
        "executionStatus": scan.execution_status,
        "overallVerdict": scan.overall_verdict,
        "fileCount": fp.file_count,
        "byteCount": fp.byte_count,
    }
    _record_outcome(key, record)
    if allowed:
        return SkillSecurityDecision(
            True,
            scan.reason or "Verified by CertiK",
            fingerprint=fp.value,
            scan_id=scan.scan_id,
            archive=scan_archive,
        )

    reason = scan.reason or "CertiK security verification did not allow this skill"
    _record_warning(f'Skill "{skill_dir.name}" was not loaded: {reason}')
    return SkillSecurityDecision(
        False,
        reason,
        fingerprint=fp.value,
        scan_id=scan.scan_id,
        archive=scan_archive,
    )
