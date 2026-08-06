import io
import json
import random
import shutil
import tarfile
from hashlib import sha256

import pytest

from tools.skill_security_certik import (
    MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_FILE_BYTES,
    MAX_ARCHIVE_FILE_COUNT,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    SCAN_TIMEOUT_SECONDS,
    SkillSecurityScanError,
    SkillSecurityScanResult,
    _tar_skill_dir,
    build_skill_security_archive,
)
from tools.skill_security_gate import (
    drain_skill_security_scan_reports,
    drain_skill_security_warnings,
    ensure_skill_certik_allowed_for_session_load,
    format_skill_security_scan_report,
    forget_skill_certik_decision,
    fingerprint_skill_dir,
    SkillFingerprintError,
    security_index_path,
)


@pytest.fixture(autouse=True)
def _clear_skill_security_queues(monkeypatch):
    monkeypatch.setenv("SKILL_SECURITY_GATE_ENABLED", "true")
    drain_skill_security_warnings()
    drain_skill_security_scan_reports()
    yield
    drain_skill_security_warnings()
    drain_skill_security_scan_reports()


def _write_skill(root, name="demo-skill", extra_files=None):
    skill_dir = root / "skills" / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Demo skill\n---\n",
        encoding="utf-8",
    )
    for rel, content in (extra_files or {}).items():
        path = skill_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return skill_dir


def test_scan_timeout_matches_platform_standard_default():
    assert SCAN_TIMEOUT_SECONDS == 120


def test_archive_budget_matches_platform_scan_payload_limit():
    assert MAX_ARCHIVE_BYTES == 5 * 1024 * 1024


def _write_index_record(key, record):
    path = security_index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 2, "skills": {key: record}}),
        encoding="utf-8",
    )


def test_gate_disabled_allows_without_scanning_or_fingerprinting(monkeypatch, tmp_path):
    monkeypatch.setenv("SKILL_SECURITY_GATE_ENABLED", "false")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("archive should not be built when the gate is disabled")

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not run when the gate is disabled")

    monkeypatch.setattr(
        "tools.skill_security_gate.build_skill_security_archive",
        _fail_archive,
    )
    monkeypatch.setattr(
        "tools.skill_security_gate.scan_skill_dir_with_platform",
        _fail_scan,
    )

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.source == "disabled"
    assert decision.fingerprint == ""
    assert drain_skill_security_scan_reports() == []


def _managed_hash(skill_dir):
    hasher = sha256()
    for path in sorted(skill_dir.rglob("*")):
        if path.is_file():
            rel = path.relative_to(skill_dir).as_posix()
            rel_bytes = rel.encode("utf-8")
            data = path.read_bytes()
            hasher.update(str(len(rel_bytes)).encode("ascii"))
            hasher.update(b"\0")
            hasher.update(rel_bytes)
            hasher.update(b"\0")
            hasher.update(str(len(data)).encode("ascii"))
            hasher.update(b"\0")
            hasher.update(data)
            hasher.update(b"\0")
    return hasher.hexdigest()


def _write_fake_package_bundled_skill(root, name, content):
    package_root = root / "package"
    source_skill = package_root / "skills" / name
    source_skill.mkdir(parents=True)
    (source_skill / "SKILL.md").write_text(content, encoding="utf-8")
    return package_root


def test_allows_existing_certik_allow_stamp(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    fp = fingerprint_skill_dir(skill_dir)
    _write_index_record(
        "local:demo-skill",
        {
            "provider": "certik",
            "decision": "allow",
            "fingerprint": fp.value,
            "scanId": "scan-ok",
        },
    )

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not run for an existing allow stamp")

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("archive should not be rebuilt for an existing allow stamp")

    (skill_dir / ".env").write_text("SECRET_TOKEN=local-only\n", encoding="utf-8")
    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)
    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-ok"
    assert drain_skill_security_scan_reports() == []


def test_forget_certik_decision_forces_next_load_to_scan(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    fp = fingerprint_skill_dir(skill_dir)
    _write_index_record(
        "local:demo-skill",
        {
            "provider": "certik",
            "decision": "allow",
            "fingerprint": fp.value,
            "scanId": "scan-ok",
        },
    )

    scan_calls = []

    def _scan(skill_dir_arg, *, skill_slug=None, archive=None):
        del skill_slug
        scan_calls.append((skill_dir_arg, archive))
        return SkillSecurityScanResult(
            decision="allow",
            reason="ok",
            scan_id="scan-new",
            archive_sha256=(archive.archive_sha256 if archive else None),
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    cached = ensure_skill_certik_allowed_for_session_load(skill_dir)
    (skill_dir / "new-package.py").write_text("print('new package')\n", encoding="utf-8")
    forget_skill_certik_decision(skill_dir)
    rescanned = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert cached.allowed is True
    assert cached.scan_id == "scan-ok"
    assert rescanned.allowed is True
    assert rescanned.scan_id == "scan-new"
    assert len(scan_calls) == 1


def test_blocks_existing_certik_block_stamp_without_rescan(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    fp = fingerprint_skill_dir(skill_dir)
    _write_index_record(
        "local:demo-skill",
        {
            "provider": "certik",
            "decision": "block",
            "fingerprint": fp.value,
            "scanId": "scan-blocked",
            "reason": "high severity finding",
        },
    )

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not rerun for an existing block stamp")

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("archive should not be rebuilt for an existing block stamp")

    (skill_dir / "fixed.py").write_text("print('fixed')\n", encoding="utf-8")
    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)
    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is False
    assert decision.reason == "high severity finding"
    assert decision.scan_id == "scan-blocked"
    assert drain_skill_security_scan_reports() == []


def test_ignores_user_writable_bundled_manifest_for_security_skip(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    (tmp_path / "skills" / ".bundled_manifest").write_text(
        f"demo-skill:{_managed_hash(skill_dir)}\n",
        encoding="utf-8",
    )
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="clean despite forged manifest",
            scan_id="scan-forged-manifest",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-forged-manifest"
    assert len(calls) == 1


def test_skips_matching_hermes_bundled_source_tree(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    skill_dir = _write_skill(home)
    package_root = _write_fake_package_bundled_skill(
        tmp_path,
        "demo-skill",
        "---\nname: demo-skill\ndescription: Demo skill\n---\n",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate.__file__",
        str(package_root / "tools" / "skill_security_gate.py"),
    )

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not run for a bundled source match")

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.source == "managed"
    assert "Hermes bundled skill" in decision.reason
    assert decision.fingerprint.startswith("managed-sha256:")
    assert drain_skill_security_scan_reports() == []


def test_managed_skip_uses_supplied_archive_snapshot(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    skill_dir = _write_skill(home)
    archive = build_skill_security_archive(skill_dir)

    package_root = _write_fake_package_bundled_skill(
        tmp_path,
        "demo-skill",
        "---\nname: demo-skill\ndescription: Changed after snapshot\n---\n",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate.__file__",
        str(package_root / "tools" / "skill_security_gate.py"),
    )
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="snapshot did not match managed source",
            scan_id="scan-snapshot",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir, archive=archive)

    assert decision.allowed is True
    assert decision.scan_id == "scan-snapshot"
    assert len(calls) == 1


def test_does_not_treat_live_skills_dir_as_bundled_source(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_BUNDLED_SKILLS", raising=False)
    skill_dir = _write_skill(tmp_path)
    monkeypatch.setattr(
        "tools.skill_security_gate.__file__",
        str(tmp_path / "tools" / "skill_security_gate.py"),
    )
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="clean live dir fallback",
            scan_id="scan-live-dir",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-live-dir"
    assert len(calls) == 1


def test_ignores_hermes_bundled_skills_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    fake_bundled = tmp_path / "outside-fake-bundled"
    source_skill = fake_bundled / "demo-skill"
    source_skill.mkdir(parents=True)
    (source_skill / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Demo skill\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_BUNDLED_SKILLS", str(fake_bundled))
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="bundled env override ignored",
            scan_id="scan-fake-home-bundled",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-fake-home-bundled"
    assert len(calls) == 1


def test_does_not_trust_fixed_bundled_source_under_hermes_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    skill_dir = _write_skill(home)
    source_skill = home / "fake-package" / "skills" / "demo-skill"
    source_skill.mkdir(parents=True, exist_ok=True)
    (source_skill / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Demo skill\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate.__file__",
        str(home / "fake-package" / "tools" / "skill_security_gate.py"),
    )
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="fixed home bundled dir ignored",
            scan_id="scan-fixed-home-bundled",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-fixed-home-bundled"
    assert len(calls) == 1


def test_skips_matching_platform_managed_source_tree(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path, name="okx")
    platform_source = tmp_path / "platform-source"
    source_skill = platform_source / "okx"
    source_skill.mkdir(parents=True)
    (source_skill / "SKILL.md").write_text(
        "---\nname: okx\ndescription: Demo skill\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate._PLATFORM_MANAGED_SKILLS_DIR",
        platform_source,
    )

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not run for a platform-managed skill")

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.source == "managed"
    assert "Platform-managed skill" in decision.reason


def test_platform_managed_source_tree_ignores_stale_certik_block_stamp(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path, name="okx")
    platform_source = tmp_path / "platform-source"
    source_skill = platform_source / "okx"
    source_skill.mkdir(parents=True)
    (source_skill / "SKILL.md").write_text(
        "---\nname: okx\ndescription: Demo skill\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate._PLATFORM_MANAGED_SKILLS_DIR",
        platform_source,
    )
    _write_index_record(
        "local:okx",
        {
            "provider": "certik",
            "decision": "block",
            "fingerprint": "archive-sha256:old",
            "reason": "old user-skill block",
        },
    )

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not run for a platform-managed skill")

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("platform-managed skill should not be archived")

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)
    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.source == "managed"
    assert "Platform-managed skill" in decision.reason


def test_skips_official_okx_onchainos_skill_symlink_without_scanning(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    official_skill_dir = (
        tmp_path / ".openclaw" / "onchainos-skills" / "skills" / "okx-dex-swap"
    )
    official_skill_dir.mkdir(parents=True)
    (official_skill_dir / "SKILL.md").write_text(
        "---\nname: okx-dex-swap\ndescription: OKX skill\n---\n",
        encoding="utf-8",
    )
    for index in range(MAX_ARCHIVE_FILE_COUNT + 1):
        (official_skill_dir / f"file-{index}.txt").write_text("", encoding="utf-8")

    active_skill_dir = tmp_path / "skills" / "okx-dex-swap"
    active_skill_dir.parent.mkdir(parents=True)
    try:
        active_skill_dir.symlink_to(official_skill_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("official OKX skill should not be archived")

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("official OKX skill should not be scanned")

    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)
    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)

    decision = ensure_skill_certik_allowed_for_session_load(active_skill_dir)

    assert decision.allowed is True
    assert decision.source == "managed"
    assert "OKX" in decision.reason
    assert decision.fingerprint.startswith("official-okx-onchainos:")
    assert drain_skill_security_scan_reports() == []


def test_okx_named_workspace_skill_still_scans_when_not_official(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(
        tmp_path,
        name="okx-dex-swap",
        extra_files={"tool.py": "print('user installed')\n"},
    )
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="clean user skill",
            scan_id="scan-user-okx",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-user-okx"
    assert len(calls) == 1


def test_skips_matching_hosted_merchant_without_archiving_runtime_state(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("MERCHANT_USE_UPSTREAM_SKILL", "true")
    skill_dir = _write_skill(
        tmp_path,
        name="purrfect-merchant-skill",
        extra_files={
            "CLAUDE.md": "merchant guidance\n",
            "platform-entry.js": "export const merchant = true;\n",
            "data/merchant.db": "live database contents",
            "node_modules/runtime/index.js": "installed dependency",
        },
    )
    try:
        (skill_dir / "AGENTS.md").symlink_to("CLAUDE.md")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    source_dir = tmp_path / "merchant-source"
    shutil.copytree(skill_dir, source_dir, symlinks=True)
    (source_dir / "data" / "merchant.db").write_text(
        "image placeholder",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate._HOSTED_MERCHANT_SKILL_SOURCE_DIR",
        source_dir,
    )

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("hosted merchant skill should not be archived")

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("hosted merchant skill should not be scanned")

    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)
    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.source == "managed"
    assert "Hosted merchant skill" in decision.reason


def test_blocks_changed_hosted_merchant_without_scanning(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("MERCHANT_USE_UPSTREAM_SKILL", "true")
    skill_dir = _write_skill(
        tmp_path,
        name="purrfect-merchant-skill",
        extra_files={"platform-entry.js": "export const merchant = false;\n"},
    )
    source_dir = tmp_path / "merchant-source"
    shutil.copytree(skill_dir, source_dir)
    (skill_dir / "platform-entry.js").write_text(
        "export const merchant = 'tampered';\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate._HOSTED_MERCHANT_SKILL_SOURCE_DIR",
        source_dir,
    )

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("changed hosted merchant skill should not be archived")

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("changed hosted merchant skill should not be scanned")

    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)
    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is False
    assert decision.source == "managed"
    assert "differs from platform-managed source" in decision.reason


def test_changed_platform_managed_skill_scans_external_replacement(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path, name="okx")
    platform_source = tmp_path / "platform-source"
    source_skill = platform_source / "okx"
    source_skill.mkdir(parents=True)
    (source_skill / "SKILL.md").write_text(
        "---\nname: okx\ndescription: Demo skill\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tools.skill_security_gate._PLATFORM_MANAGED_SKILLS_DIR",
        platform_source,
    )
    (skill_dir / "SKILL.md").write_text(
        "---\nname: okx\ndescription: Replaced externally\n---\n",
        encoding="utf-8",
    )
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="clean replacement",
            scan_id="scan-replaced",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-replaced"
    assert len(calls) == 1


def test_scans_missing_stamp_and_records_allow(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path, extra_files={"references/api.md": "docs"})

    def _scan(skill_dir_arg, *, skill_slug, archive):
        assert skill_dir_arg == skill_dir.resolve()
        assert skill_slug == "demo-skill"
        assert archive.fingerprint.startswith("archive-sha256:")
        assert archive.archive_sha256 in archive.fingerprint
        return SkillSecurityScanResult(
            decision="allow",
            reason="clean",
            scan_id="scan-1",
            archive_sha256="archive-sha",
            execution_status="succeeded",
            overall_verdict="pass",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    data = json.loads(security_index_path().read_text(encoding="utf-8"))
    record = data["skills"]["local:demo-skill"]
    assert record["decision"] == "allow"
    assert record["scanId"] == "scan-1"
    assert record["archiveSha256"] == "archive-sha"
    report = format_skill_security_scan_report(drain_skill_security_scan_reports())
    assert report.startswith("🐾 Found 1 new or updated skill.\n🛡️ CertiK scanned it:")
    assert "1 passed, 0 did not pass" in report
    assert "Passed: demo-skill." in report


def test_blocks_when_scan_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)

    monkeypatch.setattr(
        "tools.skill_security_gate.scan_skill_dir_with_platform",
        lambda *_args, **_kwargs: SkillSecurityScanResult(
            decision="block",
            reason="high severity finding",
            scan_id="scan-blocked",
        ),
    )

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is False
    assert "high severity" in decision.reason
    assert any("demo-skill" in msg for msg in drain_skill_security_warnings())
    report = format_skill_security_scan_report(drain_skill_security_scan_reports())
    assert "0 passed, 1 did not pass" in report
    assert "Blocked: demo-skill (high severity finding)." in report


def test_existing_allow_stamp_survives_user_file_changes(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    old_fp = fingerprint_skill_dir(skill_dir)
    _write_index_record(
        "local:demo-skill",
        {
            "provider": "certik",
            "decision": "allow",
            "fingerprint": old_fp.value,
            "scanId": "old-scan",
        },
    )
    (skill_dir / "references").mkdir()
    (skill_dir / "references" / "changed.md").write_text("new content", encoding="utf-8")
    (skill_dir / "large-runtime.bin").write_bytes(b"x" * (MAX_ARCHIVE_FILE_BYTES + 1))

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("scanner should not rerun for an existing allow stamp")

    def _fail_archive(*_args, **_kwargs):
        raise AssertionError("archive should not be rebuilt for an existing allow stamp")

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)
    monkeypatch.setattr("tools.skill_security_gate.build_skill_security_archive", _fail_archive)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "old-scan"
    assert decision.fingerprint == old_fp.value


def test_archive_and_fingerprint_include_dependency_named_dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(
        tmp_path,
        extra_files={
            "node_modules/payload/index.js": "module.exports = 'scan me';\n",
            ".venv/lib/python/tool.py": "print('scan me too')\n",
        },
    )

    first_fp = fingerprint_skill_dir(skill_dir)
    first_archive = build_skill_security_archive(skill_dir)
    archive, _archive_sha = _tar_skill_dir(skill_dir)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        names = set(tf.getnames())

    assert first_fp.value == first_archive.fingerprint
    assert first_archive.archive == archive
    assert "node_modules/payload/index.js" in names
    assert ".venv/lib/python/tool.py" in names

    (skill_dir / "node_modules" / "payload" / "index.js").write_text(
        "module.exports = 'changed';\n",
        encoding="utf-8",
    )
    assert fingerprint_skill_dir(skill_dir).value != first_fp.value


def test_security_archive_blocks_single_oversized_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    blob = skill_dir / "assets" / "large.txt"
    blob.parent.mkdir()
    blob.write_bytes(b"x" * (MAX_ARCHIVE_FILE_BYTES + 1))

    with pytest.raises(SkillSecurityScanError, match="too large"):
        build_skill_security_archive(skill_dir)


def test_security_archive_blocks_total_uncompressed_budget(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    assets = skill_dir / "assets"
    assets.mkdir()
    file_size = MAX_ARCHIVE_FILE_BYTES
    for index in range(MAX_ARCHIVE_UNCOMPRESSED_BYTES // file_size + 1):
        (assets / f"blob-{index}.txt").write_bytes(b"x" * file_size)

    with pytest.raises(SkillSecurityScanError, match="too large.*before compression"):
        build_skill_security_archive(skill_dir)


def test_security_archive_blocks_file_count_budget(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    refs = skill_dir / "references"
    refs.mkdir()
    for index in range(MAX_ARCHIVE_FILE_COUNT):
        (refs / f"item-{index}.md").write_text("doc\n", encoding="utf-8")

    with pytest.raises(SkillSecurityScanError, match="too many files"):
        build_skill_security_archive(skill_dir)


def test_security_archive_blocks_compressed_payload_over_platform_limit(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    rng = random.Random(0)
    assets = skill_dir / "assets"
    assets.mkdir()
    for index in range(6):
        (assets / f"random-{index}.bin").write_bytes(rng.randbytes(1024 * 1024))

    with pytest.raises(SkillSecurityScanError, match="archive is too large"):
        build_skill_security_archive(skill_dir)


def test_security_archive_is_deterministic(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(
        tmp_path,
        extra_files={
            "references/api.md": "docs\n",
            "bin/run.sh": "#!/usr/bin/env bash\n",
        },
    )

    first = build_skill_security_archive(skill_dir)
    second = build_skill_security_archive(skill_dir)

    assert first.archive == second.archive
    assert first.archive_sha256 == second.archive_sha256
    assert first.fingerprint == f"archive-sha256:{first.archive_sha256}"


def test_symlink_directory_blocks_full_tree_submission(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    skill_dir = _write_skill(tmp_path)
    target = tmp_path / "external"
    target.mkdir()
    link = skill_dir / "linked-dir"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable in test environment: {exc}")

    with pytest.raises(SkillFingerprintError, match="symlink"):
        fingerprint_skill_dir(skill_dir)
    with pytest.raises(SkillSecurityScanError, match="symlink"):
        _tar_skill_dir(skill_dir)
