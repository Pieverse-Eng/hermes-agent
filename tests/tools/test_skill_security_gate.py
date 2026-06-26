import io
import json
import tarfile

import pytest

from tools.skill_security_certik import (
    SkillSecurityScanError,
    SkillSecurityScanResult,
    _tar_skill_dir,
    build_skill_security_archive,
)
from tools.skill_security_gate import (
    drain_skill_security_warnings,
    ensure_skill_certik_allowed_for_session_load,
    fingerprint_skill_dir,
    SkillFingerprintError,
    security_index_path,
)


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


def _write_index_record(key, record):
    path = security_index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "skills": {key: record}}),
        encoding="utf-8",
    )


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
        raise AssertionError("scanner should not run for a matching allow stamp")

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _fail_scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "scan-ok"


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


def test_stale_allow_stamp_rescans_after_file_change(monkeypatch, tmp_path):
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
    calls = []

    def _scan(_skill_dir_arg, *, skill_slug, archive):
        calls.append((skill_slug, archive.fingerprint))
        return SkillSecurityScanResult(
            decision="allow",
            reason="clean after change",
            scan_id="new-scan",
        )

    monkeypatch.setattr("tools.skill_security_gate.scan_skill_dir_with_platform", _scan)

    decision = ensure_skill_certik_allowed_for_session_load(skill_dir)

    assert decision.allowed is True
    assert decision.scan_id == "new-scan"
    assert len(calls) == 1
    assert calls[0][1] != old_fp.value


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
