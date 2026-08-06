"""CertiK skill-security scan client for hosted Hermes instances.

Hermes does not hold the CertiK API key. It packages the candidate skill and
asks the platform API to run the existing instance-scoped security check.
"""

from __future__ import annotations

import base64
import errno
import gzip
import io
import json
import os
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

SCAN_TIMEOUT_SECONDS = 120
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_FILE_COUNT = 500


@dataclass(frozen=True)
class SkillSecurityArchive:
    archive: bytes
    fingerprint: str
    archive_sha256: str
    file_count: int
    byte_count: int
    files: Mapping[str, bytes]

    def read_text(self, rel_path: str) -> str:
        return self.files[rel_path].decode("utf-8")

    def get_bytes(self, rel_path: str) -> bytes | None:
        return self.files.get(rel_path)


@dataclass(frozen=True)
class SkillSecurityScanResult:
    decision: str
    reason: str
    scan_id: str | None = None
    archive_sha256: str | None = None
    execution_status: str | None = None
    overall_verdict: str | None = None
    raw: dict[str, Any] | None = None


class SkillSecurityScanError(RuntimeError):
    """Raised when the scan request could not be completed."""


@dataclass(frozen=True)
class _ArchivedFile:
    rel: str
    data: bytes
    mode: int


def _platform_token() -> str:
    token = os.environ.get("WALLET_API_TOKEN") or os.environ.get("PIEVERSE_API_KEY")
    if not token:
        raise SkillSecurityScanError("WALLET_API_TOKEN is not configured")
    return token


def _scan_url(instance_id: str) -> str:
    base = os.environ.get("WALLET_API_URL") or os.environ.get("PIEVERSE_CP_URL")
    if not base:
        raise SkillSecurityScanError("WALLET_API_URL is not configured")
    encoded_id = urllib.parse.quote(instance_id, safe="")
    return f"{base.rstrip('/')}/v1/instances/{encoded_id}/skill-security/scan"


def _read_regular_file(path: Path, rel: str) -> tuple[bytes, int] | None:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise SkillSecurityScanError(
            f"Skill file disappeared while preparing security scan: {rel}"
        ) from exc
    if stat.S_ISLNK(before.st_mode):
        raise SkillSecurityScanError(
            f"Skill contains symlink that may escape the skill boundary: {rel}"
        )
    if not stat.S_ISREG(before.st_mode):
        return None

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise SkillSecurityScanError(
                f"Skill contains symlink that may escape the skill boundary: {rel}"
            ) from exc
        if exc.errno == errno.ENOENT:
            raise SkillSecurityScanError(
                f"Skill file disappeared while preparing security scan: {rel}"
            ) from exc
        raise SkillSecurityScanError(f"Could not read skill file {rel}: {exc}") from exc

    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode):
            return None
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise SkillSecurityScanError(
                f"Skill file changed while preparing security scan: {rel}"
            )
        if current.st_size > MAX_ARCHIVE_FILE_BYTES:
            raise SkillSecurityScanError(
                "Skill file is too large for security scanning: "
                f"{rel} ({current.st_size} bytes, max {MAX_ARCHIVE_FILE_BYTES} bytes)"
            )
        mode = stat.S_IMODE(current.st_mode)
        try:
            with os.fdopen(fd, "rb") as f:
                fd = -1
                data = f.read(MAX_ARCHIVE_FILE_BYTES + 1)
                if len(data) > MAX_ARCHIVE_FILE_BYTES:
                    raise SkillSecurityScanError(
                        "Skill file grew too large while preparing security scan: "
                        f"{rel} (max {MAX_ARCHIVE_FILE_BYTES} bytes)"
                    )
                after = os.fstat(f.fileno())
                if (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
                    raise SkillSecurityScanError(
                        f"Skill file changed while preparing security scan: {rel}"
                    )
                if after.st_size != len(data):
                    raise SkillSecurityScanError(
                        f"Skill file changed while preparing security scan: {rel}"
                    )
                return data, mode
        except OSError as exc:
            raise SkillSecurityScanError(f"Could not read skill file {rel}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _snapshot_archive_files(skill_dir: Path) -> list[_ArchivedFile]:
    files: list[_ArchivedFile] = []
    total_bytes = 0
    for root, dirs, names in os.walk(skill_dir, followlinks=False):
        root_path = Path(root)
        safe_dirs = []
        for dirname in sorted(dirs):
            path = root_path / dirname
            rel = path.relative_to(skill_dir).as_posix()
            if path.is_symlink():
                raise SkillSecurityScanError(
                    f"Skill contains symlink that may escape the skill boundary: {rel}"
                )
            safe_dirs.append(dirname)
        dirs[:] = safe_dirs
        for name in sorted(names):
            path = root_path / name
            rel = path.relative_to(skill_dir).as_posix()
            if path.is_symlink():
                raise SkillSecurityScanError(
                    f"Skill contains symlink that may escape the skill boundary: {rel}"
                )
            file_data = _read_regular_file(path, rel)
            if file_data is not None:
                data, mode = file_data
                if len(files) + 1 > MAX_ARCHIVE_FILE_COUNT:
                    raise SkillSecurityScanError(
                        "Skill has too many files for security scanning "
                        f"(max {MAX_ARCHIVE_FILE_COUNT})"
                    )
                total_bytes += len(data)
                if total_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    raise SkillSecurityScanError(
                        "Skill is too large for security scanning before compression "
                        f"({total_bytes} bytes, max {MAX_ARCHIVE_UNCOMPRESSED_BYTES} bytes)"
                    )
                files.append(_ArchivedFile(rel=rel, data=data, mode=mode))
    return sorted(files, key=lambda item: item.rel)


def _build_tar_gz(files: list[_ArchivedFile]) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for item in files:
                info = tarfile.TarInfo(item.rel)
                info.size = len(item.data)
                info.mode = item.mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                tf.addfile(info, io.BytesIO(item.data))
    return buf.getvalue()


def build_skill_security_archive(skill_dir: Path) -> SkillSecurityArchive:
    """Return one deterministic scan artifact for fingerprinting and upload."""
    skill_dir = skill_dir.resolve()
    if not (skill_dir / "SKILL.md").is_file():
        raise SkillSecurityScanError(f"Skill directory has no SKILL.md: {skill_dir}")

    files = _snapshot_archive_files(skill_dir)
    if not any(item.rel == "SKILL.md" for item in files):
        raise SkillSecurityScanError(f"Skill directory has no SKILL.md: {skill_dir}")

    archive = _build_tar_gz(files)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise SkillSecurityScanError(
            f"Skill archive is too large for security scanning ({len(archive)} bytes)"
        )
    archive_sha = sha256(archive).hexdigest()
    files_by_rel = {item.rel: item.data for item in files}
    return SkillSecurityArchive(
        archive=archive,
        fingerprint=f"archive-sha256:{archive_sha}",
        archive_sha256=archive_sha,
        file_count=len(files),
        byte_count=sum(len(item.data) for item in files),
        files=MappingProxyType(files_by_rel),
    )


def _tar_skill_dir(skill_dir: Path) -> tuple[bytes, str]:
    """Return a deterministic tar.gz archive and its SHA-256 digest."""
    scan_archive = build_skill_security_archive(skill_dir)
    return scan_archive.archive, scan_archive.archive_sha256


def _parse_json_body(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _normalize_result(body: dict[str, Any]) -> SkillSecurityScanResult:
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    if not isinstance(data, dict):
        return SkillSecurityScanResult(
            decision="retry",
            reason="Platform security scan returned an invalid response",
            raw=body,
        )

    decision = str(data.get("decision") or body.get("decision") or "retry")
    decision = decision.strip().lower() or "retry"
    reason = str(
        data.get("reason")
        or body.get("error")
        or "Security scan did not allow this skill"
    )
    overall = data.get("overall") if isinstance(data.get("overall"), dict) else {}
    return SkillSecurityScanResult(
        decision=decision,
        reason=reason,
        scan_id=data.get("scanId") or data.get("scan_id"),
        archive_sha256=data.get("archiveSha256") or data.get("archive_sha256"),
        execution_status=data.get("executionStatus") or data.get("execution_status"),
        overall_verdict=overall.get("verdict") if isinstance(overall, dict) else None,
        raw=data,
    )


def scan_skill_dir_with_platform(
    skill_dir: Path,
    *,
    skill_slug: str,
    archive: SkillSecurityArchive | None = None,
) -> SkillSecurityScanResult:
    """Scan *skill_dir* through the platform skill-security endpoint.

    The platform route defaults to the same ``standard`` depth used by the web
    Skill Store, so Hermes intentionally does not send scan-depth options.
    """
    instance_id = os.environ.get("INSTANCE_ID")
    if not instance_id:
        raise SkillSecurityScanError("INSTANCE_ID is not configured")

    scan_archive = archive or build_skill_security_archive(skill_dir)
    payload = json.dumps(
        {
            "skillSlug": skill_slug,
            "fingerprint": scan_archive.fingerprint,
            "filename": f"{skill_slug}.tar.gz",
            "archiveBase64": base64.b64encode(scan_archive.archive).decode("ascii"),
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        _scan_url(instance_id),
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {_platform_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=SCAN_TIMEOUT_SECONDS) as resp:
            body = _parse_json_body(resp.read())
    except urllib.error.HTTPError as exc:
        body = _parse_json_body(exc.read())
        result = _normalize_result(body)
        return SkillSecurityScanResult(
            decision="retry",
            reason=result.reason or f"Platform security scan returned HTTP {exc.code}",
            scan_id=result.scan_id,
            archive_sha256=result.archive_sha256 or scan_archive.archive_sha256,
            execution_status=result.execution_status,
            overall_verdict=result.overall_verdict,
            raw=result.raw or body,
        )
    except Exception as exc:
        raise SkillSecurityScanError(str(exc)) from exc

    result = _normalize_result(body)
    if not result.archive_sha256:
        result = SkillSecurityScanResult(
            decision=result.decision,
            reason=result.reason,
            scan_id=result.scan_id,
            archive_sha256=scan_archive.archive_sha256,
            execution_status=result.execution_status,
            overall_verdict=result.overall_verdict,
            raw=result.raw,
        )
    return result
