"""Load-time CertiK gate for Hermes skills.

This module is intentionally fail-closed: a skill is allowed into the session
prompt only when the current directory fingerprint has a CertiK ``allow`` stamp.
Missing credentials, scanner retry responses, and scanner errors all block load.
"""

from __future__ import annotations

import json
import re
import threading
import contextvars
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

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
_SCAN_REPORTS: "contextvars.ContextVar[list[SkillSecurityScanReport] | None]" = (
    contextvars.ContextVar("skill_security_scan_reports", default=None)
)
_SLUG_RE = re.compile(r"[^a-z0-9-]+")
_PLATFORM_MANAGED_SKILLS_DIR = Path("/usr/local/lib/hermes-skills")


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


@dataclass(frozen=True)
class SkillSecurityScanReport:
    skill_name: str
    decision: str
    reason: str
    fingerprint: str
    scan_id: str | None = None


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


def drain_skill_security_scan_reports() -> list[SkillSecurityScanReport]:
    reports = _SCAN_REPORTS.get()
    if not reports:
        return []
    _SCAN_REPORTS.set([])
    return list(reports)


def _record_scan_report(
    skill_dir: Path,
    *,
    decision: str,
    reason: str,
    fingerprint: str,
    scan_id: str | None = None,
) -> None:
    reports = _SCAN_REPORTS.get()
    if reports is None:
        reports = []
        _SCAN_REPORTS.set(reports)
    report = SkillSecurityScanReport(
        skill_name=skill_dir.name,
        decision=decision,
        reason=reason,
        fingerprint=fingerprint,
        scan_id=scan_id,
    )
    for index, existing in enumerate(reports):
        if existing.skill_name == report.skill_name and existing.fingerprint == report.fingerprint:
            reports[index] = report
            return
    reports.append(report)


def _short_reason(reason: str) -> str:
    text = " ".join(str(reason or "").split())
    if len(text) <= 180:
        return text
    return text[:177].rstrip() + "..."


def format_skill_security_scan_report(reports: list[SkillSecurityScanReport]) -> str:
    if not reports:
        return ""

    allowed = [r for r in reports if r.decision == "allow"]
    blocked = [r for r in reports if r.decision == "block"]
    failed = [r for r in reports if r.decision not in {"allow", "block"}]
    skill_label = "skill" if len(reports) == 1 else "skills"
    target_label = "it" if len(reports) == 1 else "them"

    lines = [
        f"🐾 Found {len(reports)} new or updated {skill_label}.",
        f"🛡️ CertiK scanned {target_label}: "
        f"{len(allowed)} passed, {len(blocked) + len(failed)} did not pass.",
    ]
    if allowed:
        lines.append("Passed: " + ", ".join(sorted(r.skill_name for r in allowed)) + ".")
    if blocked:
        lines.append(
            "Blocked: "
            + "; ".join(
                f"{r.skill_name} ({_short_reason(r.reason)})"
                for r in sorted(blocked, key=lambda item: item.skill_name)
            )
            + "."
        )
    if failed:
        lines.append(
            "Failed: "
            + "; ".join(
                f"{r.skill_name} ({_short_reason(r.reason)})"
                for r in sorted(failed, key=lambda item: item.skill_name)
            )
            + "."
        )
    return "\n".join(lines)


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


def _managed_skill_files_hash(files: Mapping[str, bytes]) -> str:
    hasher = sha256()
    for rel in sorted(files):
        data = files[rel]
        rel_bytes = str(rel).encode("utf-8")
        hasher.update(str(len(rel_bytes)).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(rel_bytes)
        hasher.update(b"\0")
        hasher.update(str(len(data)).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(data)
        hasher.update(b"\0")
    return hasher.hexdigest()


def _managed_skill_content_hash(skill_dir: Path) -> str | None:
    try:
        files: dict[str, bytes] = {}
        for path in sorted(skill_dir.rglob("*")):
            if path.is_symlink():
                return None
            if path.is_file():
                rel = path.relative_to(skill_dir).as_posix()
                files[rel] = path.read_bytes()
    except OSError:
        return None
    return _managed_skill_files_hash(files)


def _bundled_skills_source_dir(skills_root: Path) -> Path | None:
    candidate = Path(__file__).parent.parent / "skills"
    try:
        resolved = candidate.resolve()
        live_root = skills_root.resolve()
        hermes_root = skills_root.parent.resolve()
    except OSError:
        return None
    if resolved == live_root:
        return None
    try:
        resolved.relative_to(hermes_root)
        return None
    except ValueError:
        pass
    return resolved if resolved.is_dir() else None


def _managed_skill_reason(
    skill_dir: Path,
    archive: SkillSecurityArchive | None = None,
) -> tuple[str, str] | None:
    current_hash = (
        _managed_skill_files_hash(archive.files)
        if archive is not None
        else _managed_skill_content_hash(skill_dir)
    )
    if not current_hash:
        return None

    skills_root = get_skills_dir()
    try:
        rel = skill_dir.relative_to(skills_root.resolve())
    except ValueError:
        return None

    bundled_source_root = _bundled_skills_source_dir(skills_root)
    if bundled_source_root is not None:
        bundled_source = bundled_source_root / rel
        if bundled_source.is_dir():
            source_hash = _managed_skill_content_hash(bundled_source)
            if source_hash and source_hash == current_hash:
                return "Hermes bundled skill", current_hash

    platform_source = _PLATFORM_MANAGED_SKILLS_DIR / rel
    if platform_source.is_dir():
        source_hash = _managed_skill_content_hash(platform_source)
        if source_hash and source_hash == current_hash:
            return "Platform-managed skill", current_hash
    return None


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


def _blocked_record_matches(record: Any, fingerprint: str) -> bool:
    return (
        isinstance(record, dict)
        and record.get("provider") == "certik"
        and record.get("decision") == "block"
        and record.get("fingerprint") == fingerprint
    )


def ensure_skill_certik_allowed_for_session_load(
    skill_dir: Path,
    *,
    archive: SkillSecurityArchive | None = None,
) -> SkillSecurityDecision:
    """Return whether *skill_dir* may be included in a freshly loaded session."""
    skill_dir = skill_dir.resolve()
    managed = _managed_skill_reason(skill_dir, archive=archive)
    if managed is not None:
        source_label, content_hash = managed
        return SkillSecurityDecision(
            True,
            f"{source_label}; CertiK scan not required",
            fingerprint=f"managed-sha256:{content_hash}",
            source="managed",
            archive=archive,
        )

    key = _skill_key(skill_dir)
    try:
        scan_archive = archive or build_skill_security_archive(skill_dir)
    except SkillSecurityScanError as exc:
        reason = str(exc)
        _record_warning(f'Skill "{skill_dir.name}" was not loaded: {reason}')
        _record_scan_report(
            skill_dir,
            decision="error",
            reason=reason,
            fingerprint="",
        )
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
    if _blocked_record_matches(record, fp.value):
        reason = (
            record.get("reason")
            if isinstance(record, dict) and isinstance(record.get("reason"), str)
            else "CertiK security verification did not allow this skill"
        )
        return SkillSecurityDecision(
            False,
            reason,
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
        _record_scan_report(
            skill_dir,
            decision="retry",
            reason=reason,
            fingerprint=fp.value,
        )
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
    _record_scan_report(
        skill_dir,
        decision=scan.decision,
        reason=scan.reason,
        fingerprint=fp.value,
        scan_id=scan.scan_id,
    )
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
