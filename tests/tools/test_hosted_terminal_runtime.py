"""Hosted CLIs survive shell initialization without weakening lifecycle guards."""

import os
import shlex
import subprocess

import pytest

from cron.lifecycle_guard import contains_gateway_lifecycle_command_or_referenced_script as blocked
from tools.environments.local import LocalEnvironment


@pytest.mark.parametrize("prefix", [".", "source"])
def test_sourced_script_blocks_gateway_restart(prefix, tmp_path):
    script = tmp_path / "sourced.sh"
    script.write_text("systemctl restart hermes-gateway\n")
    assert blocked(f"{prefix} {script}")


@pytest.mark.parametrize("command", [
    "printf '%s' 'Hermes gateway restart'",
    "echo 'launchctl submit -l ai.hermes.gateway -- /bin/true'",
])
def test_output_text_is_not_an_executed_lifecycle_command(command):
    assert not blocked(command)


@pytest.mark.parametrize("prefix", ["exec", "env TEST=1", "exec env -u TEST TEST=1"])
def test_wrappers_cannot_hide_nested_shell_restart(tmp_path, prefix):
    inner = tmp_path / "inner.sh"
    inner.write_text("#!/bin/sh\nhermes gateway restart\n")
    outer = tmp_path / "outer.sh"
    outer.write_text(f"#!/bin/sh\n{prefix} {shlex.quote(str(inner))}\n")
    assert blocked(f"sh {shlex.quote(str(outer))}")


@pytest.mark.parametrize("command", [
    "exec env MODE=test hermes gateway stop",
    "env -u HOME sh -lc 'hermes gateway restart'",
    "echo \"$(hermes gateway stop)\"",
    "sh -lc 'exec hermes gateway restart'",
    "sudo -u hermes env TEST=1 hermes gateway stop",
    "echo \"don't $(hermes gateway stop)\"",
    "eval 'hermes gateway stop'",
])
def test_executed_lifecycle_commands_remain_blocked(command):
    assert blocked(command)


def test_large_node_bundle_is_not_scanned_as_shell(tmp_path):
    bundle = tmp_path / "a2a.mjs"
    bundle.write_text("#!/usr/bin/env node\nconsole.log('Hermes gateway restart');\n" + "// padding\n" * 120000)
    bundle.chmod(0o755)
    shim = tmp_path / "shim"
    shim.write_text(f"#!/bin/sh\nexec {shlex.quote(str(bundle))} \"$@\"\n")
    assert not blocked(f"{shlex.quote(str(bundle))} --help")
    assert not blocked(f"{shlex.quote(str(shim))} --version")
    # Forcing the same file through a shell must retain the shell size cap.
    assert blocked(f"sh {shlex.quote(str(bundle))}")


@pytest.mark.parametrize("shebang", ["#!/bin/sh\n", ""])
def test_oversized_shell_or_unknown_script_stays_blocked(tmp_path, shebang):
    script = tmp_path / "unknown"
    script.write_text(shebang + "# padding\n" * 120000)
    assert blocked(str(script))


def test_quoted_parenthesis_does_not_hide_substitution_restart():
    assert blocked('printf "%s\\n" "$(printf \')\'; systemctl restart hermes-gateway)"')


def test_non_shell_visit_does_not_skip_later_shell_interpretation(tmp_path):
    script = tmp_path / "mixed"
    script.write_text("#!/usr/bin/env node\nsystemctl restart hermes-gateway\n", encoding="utf-8")
    assert blocked(f"{shlex.quote(str(script))} || sh {shlex.quote(str(script))}")


@pytest.mark.parametrize("command", [
    "printf '%s\\n' 'example:\nhermes gateway restart\nend'",
    "cat <<'EOF'\nhermes gateway restart\nEOF",
])
def test_multiline_output_is_literal(command):
    assert not blocked(command)


def test_malformed_env_split_is_a_verdict_not_an_exception():
    assert isinstance(blocked('env -S "\'"'), bool)


@pytest.mark.parametrize("command", [
    "env --split-string='systemctl restart hermes-gateway'",
    "env -S'systemctl restart hermes-gateway'",
])
def test_attached_env_split_string_cannot_hide_restart(command):
    assert blocked(command)


@pytest.mark.parametrize("command", [
    "echo safe # comment\nhermes gateway stop",
    "sh <<'EOF'\nhermes gateway stop\nEOF",
    "cat <<'EOF' | sh\nhermes gateway stop\nEOF",
    "cat <<EOF\n$(systemctl restart hermes-gateway)\nEOF",
    'cat <<EOF "literal <<BAD"\nsafe text\nEOF\nsystemctl restart hermes-gateway',
])
def test_comments_and_heredocs_cannot_hide_executed_restart(command):
    assert blocked(command)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell execution")
@pytest.mark.live_system_guard_bypass  # The executable is shadowed below.
@pytest.mark.parametrize("command", [
    "2>/dev/null systemctl restart hermes-gateway",
    "{ systemctl restart hermes-gateway; }",
    'printf "%s\\n" "text\n<<EOF\n"; systemctl restart hermes-gateway',
    "cat <<EOF\n'$(systemctl restart hermes-gateway)'\nEOF",
], ids=["redirection", "brace_group", "multiline_quote", "heredoc_expansion"])
def test_shell_execution_shapes_cannot_bypass_guard(command):
    # Shadow the lifecycle executable: establish actual Bash execution with
    # a harmless function, without touching any gateway or host service.
    result = subprocess.run(
        ["bash", "-c", 'systemctl() { printf "called:%s\\n" "$*"; };\n' + command],
        capture_output=True, text=True, check=True,
    )
    assert "called:restart hermes-gateway" in result.stdout
    assert blocked(command)


@pytest.fixture
def tenant(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    for directory, name, output in [
        (".platform-bin", "onchainos", "platform-shim"),
        (".local/bin", "onchainos", "installed-copy"),
        (".npm-global/bin", "purrfect-a2a", "a2a-ok"),
    ]:
        path = tmp_path / directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
        path.chmod(0o755)
    init = tmp_path / "init.sh"
    init.write_text(
        f'export PATH="/user/first:{tmp_path}/.local/bin:/usr/bin:/bin:/user/last"\n'
        'export USER_INIT_MARKER="initialized"\n'
    )
    monkeypatch.setattr("tools.environments.local._read_terminal_shell_init_config", lambda: ([str(init)], False))
    return tmp_path


@pytest.mark.skipif(os.name == "nt", reason="POSIX hosted shell paths")
@pytest.mark.parametrize("snapshot", [True, False])
def test_terminal_cli_paths_after_login_and_on_later_calls(tenant, snapshot):
    env = LocalEnvironment(cwd=str(tenant), timeout=15)
    if not snapshot:
        env._snapshot_ready = False
        env._prefer_nonlogin = True
        env.env["PATH"] = "/user/first:/usr/bin:/bin:/user/last"
    try:
        for _ in range(2):
            result = env.execute('onchainos; purrfect-a2a; printf "INIT=%s\\nPATH=%s\\n" "$USER_INIT_MARKER" "$PATH"')
            output = result["output"]
            assert result["returncode"] == 0
            assert "platform-shim" in output
            assert "installed-copy" not in output
            assert "a2a-ok" in output
            if snapshot:
                assert "INIT=initialized" in output
            path = output.split("PATH=", 1)[1].splitlines()[0].split(":")
            assert path.index(str(tenant / ".platform-bin")) < path.index(str(tenant / ".local/bin"))
            assert path.index("/user/first") < path.index("/usr/bin") < path.index("/user/last")
    finally:
        env.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX hosted shell paths")
def test_cli_paths_survive_failed_login_snapshot(tenant):
    (tenant / "init.sh").write_text('export PATH="/usr/bin:/bin"\nexit 42\n')
    env = LocalEnvironment(
        cwd=str(tenant), timeout=15,
        env={"PATH": "/user/first:/usr/bin:/bin:/user/last"},
    )
    try:
        for _ in range(2):
            result = env.execute("onchainos; purrfect-a2a")
            assert result["returncode"] == 0
            assert "platform-shim" in result["output"]
            assert "installed-copy" not in result["output"]
            assert "a2a-ok" in result["output"]
    finally:
        env.cleanup()
