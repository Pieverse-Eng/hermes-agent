"""Gateway lifecycle guard for cron job creation (#30719).

An agent running inside a gateway can schedule a cron job that calls
``hermes gateway restart`` (or ``launchctl kickstart ai.hermes.gateway``
or ``systemctl restart hermes-gateway``).  When the cron fires, the
gateway dies, the supervisor (launchd KeepAlive / systemd Restart=)
revives it, auto-resume picks up the offending session, and the resumed
turn re-runs the same logic — a SIGTERM-respawn loop every ~10 seconds
until manually broken.

This module rejects cron job specs whose prompt or script contains a
direct shell-level gateway-lifecycle command.  It is enforced at
``cron.jobs.create_job`` so it fires on every job-creation path: the
``hermes cron create`` CLI subcommand AND the agent's ``cronjob`` model
tool (which calls ``create_job`` directly, bypassing the CLI layer).

The pattern is intentionally command-shaped: it anchors on a concrete
command identifier (``hermes gateway``, ``launchctl ... hermes-gateway``,
``systemctl ... hermes-gateway``, ``pkill`` against the gateway) so it
cannot fire on prose.  A cron ``prompt`` is fed to a future LLM, not a
shell, so an over-broad substring match on English ("Kong API gateway
autoscaling and restart behavior") would produce a high false-positive
rate without preventing the actual foot-gun, which requires a real
command shape.

This is a defence-in-depth layer.  ``tools/terminal_tool.py`` blocks direct
commands and shell scripts they reference when ``_HERMES_GATEWAY=1``. It also
rejects ``launchctl submit`` in gateway sessions because launchd treats that
primitive as a persistent KeepAlive job, not a one-shot task. ``hermes gateway
stop|restart`` separately refuse to self-target from inside the gateway.
Blocking cron specs at creation time as well means the agent gets an immediate,
informative rejection instead of scheduling a job that will only fail
(silently) when it fires.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import stat
from pathlib import Path
from typing import Callable, Iterator, Optional

logger = logging.getLogger(__name__)


class GatewayLifecycleBlocked(ValueError):
    """Raised when a cron job spec contains a gateway-lifecycle command."""


# Shell-level command shapes that target the gateway lifecycle. Each branch
# is anchored on a concrete command identifier so a match can only fire on
# actual shell-command-shaped strings, not on prose.
_GATEWAY_LIFECYCLE_PATTERN = re.compile(
    r"(?i)"
    # Branch A: `hermes gateway restart|stop` — the canonical foot-gun.
    # `start` is intentionally excluded: starting a gateway from inside a
    # gateway is benign (a no-op or "already running" error), and a
    # legitimate cron job might start a sibling profile's gateway.
    r"(?:hermes\s+gateway\s+(?:restart|stop))"
    # Branch B: launchctl ops on a hermes-gateway label. macOS launchd
    # labels look like `ai.hermes.gateway` / `hermes-gateway`. Requiring the
    # gateway identifier prevents blocking unrelated hermes services (e.g.
    # `launchctl unload ai.hermes.update-checker.plist`).
    # `submit` and `bootstrap` are included alongside the direct verbs
    # (kickstart/etc.): `launchctl submit -l ai.hermes.gateway-<suffix> --
    # <helper-script>` (or `launchctl bootstrap gui/<uid> <plist>`) creates
    # a NEW keepalive job wrapping an arbitrary helper, which is how a
    # blocked direct restart/kill gets laundered into a persistent restart
    # loop instead (#62891) — same foot-gun, indirect shape. Neutral-label
    # submissions that dodge this text anchor are caught separately by
    # `contains_launchctl_submit_command` (execution-aware, label-independent).
    r"|(?:launchctl\s+(?:kickstart|unload|load|stop|restart|submit|bootstrap)\b[^\n]*\bhermes[.\-]?gateway)"
    # Branch C: systemctl ops on a hermes-gateway unit.
    r"|(?:systemctl\s+(?:-\S+\s+)*(?:restart|stop|start)\b[^\n]*\bhermes[.\-]?gateway)"
    # Branch D: pkill / kill targeting the hermes gateway process. Both
    # token orders because real reproductions show both.
    r"|(?:p?kill\b[^\n]*\bhermes\b[^\n]*\bgateway)"
    r"|(?:p?kill\b[^\n]*\bgateway\b[^\n]*\bhermes)"
)


# A backslash immediately followed by a newline is a POSIX shell line
# continuation — the shell joins the two lines before parsing. Every branch
# above uses `[^\n]*` between its verb and the gateway identifier so the
# match can't span unrelated lines of a longer cron prompt/script, but that
# also means a real multi-line shell invocation split across continuation
# lines (e.g. `launchctl submit \` / `  -l ai.hermes.gateway-... \` / `  -- ...`,
# the exact reported shape in #62891) would otherwise slip past. Collapse
# continuations to a single space before matching, mirroring what the shell
# itself does, rather than loosening `[^\n]*` and risking false positives
# across genuinely separate lines.
_SHELL_LINE_CONTINUATION = re.compile(r"\\\r?\n[ \t]*")


def contains_gateway_lifecycle_command(text: str) -> bool:
    """Return True if *text* contains a gateway lifecycle command pattern."""
    if not text:
        return False
    normalized = _SHELL_LINE_CONTINUATION.sub(" ", text)
    return bool(_GATEWAY_LIFECYCLE_PATTERN.search(normalized))


_SHELL_EXECUTABLES = frozenset({"sh", "bash", "dash", "ksh", "zsh"})
_SHELL_OPTIONS_WITH_VALUES = frozenset({"-O", "+O", "-o", "+o"})
_MAX_REFERENCED_SCRIPT_BYTES = 1024 * 1024
_MAX_REFERENCED_SCRIPT_DEPTH = 8
_CONTROL_CHARS = frozenset(";&|()\n")
_REDIRECTION_OPERATORS = frozenset({"<", ">", ">>", "<>", ">|", "<&", ">&", "<<<", "&>", "&>>"})




_ReadRemoteScriptFn = Callable[[str], Optional[str]]


def _strip_shell_comments(command: str, *, initial_quote: str = "") -> str:
    # shlex drops the newline along with comments, joining two commands.
    # Remove comments first while retaining newlines and quoted data.
    result: list[str] = []
    quote = initial_quote
    index = 0
    while index < len(command):
        char = command[index]
        if char == "\\" and quote != "'":
            result.append(command[index:index + 2])
            index += 2
            continue
        if char in {"'", '"'} and (not quote or char == quote):
            quote = char if not quote else ""
        if char == "#" and not quote and (index == 0 or command[index - 1].isspace() or command[index - 1] in ";&|()"):
            newline = command.find("\n", index)
            if newline == -1:
                break
            index = newline
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _raw_command_segments(command: str) -> Iterator[list[str]]:
    try:
        lexer = shlex.shlex(_strip_shell_comments(command.replace("\\\n", "")), posix=True, punctuation_chars=";&|()\n<>")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return
    segment: list[str] = []
    for token in tokens:
        if token and set(token) <= _CONTROL_CHARS:
            if segment:
                yield segment
                segment = []
        else:
            segment.append(token)
    if segment:
        yield segment


def _extract_heredocs(command: str) -> tuple[str, list[str]]:
    """Remove stdin text from shell syntax; retain code actually executed."""
    lines = command.splitlines(keepends=True)
    output: list[str] = []
    payloads: list[str] = []
    index = 0
    quote = ""
    while index < len(lines):
        header = lines[index]
        index += 1
        syntax_header = _strip_shell_comments(header, initial_quote=quote)
        operators, quote = _heredoc_operators(syntax_header, initial_quote=quote)
        # Remove the consumed redirection too. The syntax is inspected by
        # several walkers; leaving <<EOF behind would consume the following
        # executable lines again on their next pass.
        for match in reversed(operators):
            syntax_header = syntax_header[:match.start()] + " " + syntax_header[match.end():]
        output.append(syntax_header)
        segments = list(_raw_command_segments(header))
        if not operators:
            continue
        shell_input = False
        for segment in segments:
            executable = _command_token_index(segment)
            if executable is not None and Path(segment[executable]).name in _SHELL_EXECUTABLES:
                shell_input = True
        for match in operators:
            delimiter = shlex.split(match[2])[0]
            body: list[str] = []
            while index < len(lines):
                line = lines[index]
                index += 1
                candidate = line.lstrip("\t") if match[1] else line
                if candidate.rstrip("\r\n") == delimiter:
                    break
                body.append(line)
            text = "".join(body)
            if shell_input:
                payloads.append(text)
            elif not any(char in match[2] for char in "'\"\\"):
                payloads.extend(_iter_command_substitutions(text, heredoc=True))
    return "".join(output), payloads


def _heredoc_operators(header: str, *, initial_quote: str = "") -> tuple[list[re.Match], str]:
    pattern = re.compile(r"<<(-?)\s*('[^']*'|\"[^\"]*\"|[^\s;&|<>]+)")
    quote = initial_quote
    operators: list[re.Match] = []
    index = 0
    while index < len(header):
        char = header[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if char in {"'", '"'} and (not quote or char == quote):
            quote = char if not quote else ""
        if not quote and header.startswith("<<", index):
            match = None if header.startswith("<<<", index) else pattern.match(header, index)
            if match:
                operators.append(match)
                index = match.end()
                continue
        index += 1
    return operators, quote


def _iter_command_segments(command: str) -> Iterator[list[str]]:
    """Yield executable segments, preserving multiline quoted data."""
    syntax, _ = _extract_heredocs(command)
    yield from _raw_command_segments(syntax)


def _command_token_index(segment: list[str]) -> Optional[int]:
    """Unwrap shell execution prefixes without treating output as commands."""
    index = 0
    while index < len(segment):
        token = segment[index]
        # Redirections can precede the command word (2>/dev/null command).
        # shlex separates an IO number, the operator and its target.
        if token in _REDIRECTION_OPERATORS:
            index += 2
            continue
        if token.isdigit() and index + 1 < len(segment) and segment[index + 1] in _REDIRECTION_OPERATORS:
            index += 3
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        name = Path(token).name
        if name in {"exec", "env", "command", "builtin", "sudo", "nohup"}:
            index += 1
            while index < len(segment) and segment[index].startswith("-"):
                option = segment[index]
                index += 1
                if name == "env" and (option in {"-S", "--split-string"} or option.startswith("--split-string=") or option.startswith("-S")):
                    attached = option not in {"-S", "--split-string"}
                    if not attached and index >= len(segment):
                        return None
                    payload = option.split("=", 1)[1] if option.startswith("--split-string=") else option[2:] if attached else segment[index]
                    if attached:
                        index -= 1
                    try:
                        segment[index:index + 1] = shlex.split(payload)
                    except ValueError:
                        return None
                    break
                if (name == "env" and option in {"-u", "--unset", "-C", "--chdir"}) or (name == "exec" and option == "-a"):
                    index += 1
                if name == "sudo" and option in {"-u", "-g", "-h", "-p", "-C", "-T"}:
                    index += 1
                if option == "--":
                    break
            continue
        if token in {"if", "then", "elif", "else", "while", "until", "do", "!", "{"}:
            index += 1
            continue
        return index
    return None


def _contains_executed_lifecycle_command(command: str) -> bool:
    for segment in _iter_command_segments(command):
        index = _command_token_index(segment)
        if index is None:
            continue
        executable = Path(segment[index]).name.lower()
        arguments = segment[index + 1:]
        if executable == "hermes":
            if len(arguments) >= 2 and arguments[0].lower() == "gateway" and arguments[1].lower() in {"restart", "stop"}:
                return True
        elif executable in {"launchctl", "systemctl", "pkill", "kill"}:
            if contains_gateway_lifecycle_command(" ".join([executable, *arguments])):
                return True
    return contains_launchctl_submit_command(command)


def contains_launchctl_submit_command(command: str) -> bool:
    """Detect an executed ``launchctl submit``/``bootstrap``, not quoted text.

    Label-independent by design: the label of a submitted/bootstrapped job is
    chosen by whoever writes it, so a neutral name (``ai.hermes.svc-reload-tmp``)
    defeats any label-anchored regex (#62891, second reproduction). Both verbs
    register a NEW persistent launchd job (``submit`` jobs get KeepAlive
    semantics; ``bootstrap`` loads an arbitrary plist), which is never safe to
    do from inside the gateway process.
    """
    for segment in _iter_command_segments(command):
        index = _command_token_index(segment)
        if index is None:
            continue
        if Path(segment[index]).name == "launchctl":
            arguments = segment[index + 1 :]
            if arguments and arguments[0].lower() in {"submit", "bootstrap"}:
                return True
    return False


def _expand_candidate_path(candidate: str) -> Optional[Path]:
    """Sanitize a tokenized path candidate at the ingestion boundary.

    Candidate tokens come from shlex-splitting arbitrary command text —
    including text recursively decoded from binaries or remote reads — so
    they can carry NUL bytes or other junk no real filesystem path can
    contain. Every OS-facing ``Path`` operation downstream (``expanduser``,
    ``os.open``, ``resolve``) raises a *different* exception for the same
    junk (``ValueError: embedded null byte``, ``RuntimeError: Could not
    determine home directory`` when HOME is unset under launchd, OSError
    for over-long paths). Rejecting here — once, before any OS call — is
    the whole-class fix; catching per-syscall was the whack-a-mole that
    produced #76762, #77703, #77780, and #78256.

    Returns ``None`` for candidates that cannot be a real path (nothing to
    scan), otherwise the ``expanduser()``-expanded ``Path``.
    """
    if not candidate or "\x00" in candidate:
        return None
    try:
        return Path(candidate).expanduser()
    except (ValueError, RuntimeError, OSError):
        return None


def _resolve_terminal_script_path(candidate: str, cwd: Optional[str]) -> Optional[Path]:
    path = _expand_candidate_path(candidate)
    if path is None:
        return None
    if not path.is_absolute():
        try:
            path = Path(cwd or Path.cwd()) / path
        except OSError:
            # Path.cwd() can raise when the process cwd was deleted.
            return None
    return path


def _executable_name(token: str) -> str:
    """Preserve POSIX dot-source, which has no pathlib name component."""
    # Backport NousResearch/hermes-agent 5921ba8c0646e04a778b0ab3f7e4e5756a2eabdd.
    return Path(token).name or token


def _iter_referenced_shell_scripts(
    command: str,
    *,
    cwd: Optional[str] = None,
) -> Iterator[tuple[Path, bool]]:
    """Yield scripts executed directly or through a POSIX shell."""
    for segment in _iter_command_segments(command):
        index = _command_token_index(segment)
        if index is None:
            continue
        executable = segment[index]
        executable_name = _executable_name(executable)

        if executable_name in {".", "source"}:
            if len(segment) > index + 1:
                resolved = _resolve_terminal_script_path(segment[index + 1], cwd)
                if resolved is not None:
                    yield resolved, True
            continue

        if executable_name in _SHELL_EXECUTABLES:
            arguments = segment[index + 1 :]
            arg_index = 0
            while arg_index < len(arguments):
                argument = arguments[arg_index]
                if argument == "--":
                    arg_index += 1
                    break
                if argument == "--command" or (argument.startswith("-") and not argument.startswith("--") and "c" in argument[1:]):
                    break
                if argument in _SHELL_OPTIONS_WITH_VALUES:
                    arg_index += 2
                    continue
                if argument.startswith("-"):
                    arg_index += 1
                    continue
                break
            if arg_index < len(arguments) and not arguments[arg_index].startswith("-"):
                resolved = _resolve_terminal_script_path(arguments[arg_index], cwd)
                if resolved is not None:
                    yield resolved, True
            continue

        # A bare "/" token is pathlib's division operator in Python sources
        # (e.g. `Path.home() / ".hermes"`), not an executable reference.
        # Resolving it walks to the filesystem root and fails the
        # regular-file check below, hard-blocking innocent .py scripts
        # (#77131). Skip pure-separator tokens.
        if executable.strip("/"):
            if "/" in executable or executable.endswith((".sh", ".bash", ".zsh")):
                resolved = _resolve_terminal_script_path(executable, cwd)
                if resolved is not None:
                    yield resolved, False


def _iter_shell_command_payloads(command: str) -> Iterator[str]:
    """Yield code passed through ``sh|bash|... -c`` for recursive scanning."""
    for segment in _iter_command_segments(command):
        index = _command_token_index(segment)
        if index is None:
            continue
        arguments = segment[index + 1 :]
        if Path(segment[index]).name == "eval":
            yield " ".join(arguments)
            continue
        if Path(segment[index]).name not in _SHELL_EXECUTABLES:
            continue
        for arg_index, argument in enumerate(arguments[:-1]):
            if argument == "--command" or (argument.startswith("-") and not argument.startswith("--") and "c" in argument[1:]):
                yield arguments[arg_index + 1]
                break


def _iter_command_substitutions(command: str, *, heredoc: bool = False) -> Iterator[str]:
    # Substitution executes even inside echo/printf arguments. Single-quoted
    # text is literal, so leave it out of the scan. In an unquoted heredoc
    # body quotes are data and do not suppress command expansion.
    single_quote = False
    double_quote = False
    index = 0
    while index < len(command):
        if command[index] == "\\":
            index += 2
            continue
        if not heredoc and command[index] == "'" and not double_quote:
            single_quote = not single_quote
        if not heredoc and command[index] == '"' and not single_quote:
            double_quote = not double_quote
        if not single_quote and command.startswith("$(", index):
            start = index + 2
            end, nesting = start, 1
            inner_quote = ""
            while end < len(command) and nesting:
                char = command[end]
                if char == "\\" and inner_quote != "'":
                    end += 2
                    continue
                if char in {"'", '"'} and (not inner_quote or char == inner_quote):
                    inner_quote = char if not inner_quote else ""
                if char == "(" and not inner_quote:
                    nesting += 1
                elif char == ")" and not inner_quote:
                    nesting -= 1
                end += 1
            if nesting == 0:
                yield command[start:end - 1]
                index = end
                continue
        if not single_quote and command[index] == "`":
            end = command.find("`", index + 1)
            if end != -1:
                yield command[index + 1:end]
                index = end + 1
                continue
        index += 1


def _resolve_script_directory(script_path: str) -> Optional[str]:
    """Return the directory *script_path* resolves to, handling relative names."""
    try:
        path = _resolve_script_path(script_path)
        if path is not None and path.is_absolute():
            return str(path.parent)
    except Exception:
        pass
    return None


def _is_non_shell_script(data: bytes) -> bool:
    """Identify known interpreters before applying the shell scanning cap."""
    header = data.split(b"\n", 1)[0][:256]
    if not header.startswith(b"#!"):
        return False
    try:
        tokens = shlex.split(header[2:].decode("utf-8"))
        index = _command_token_index(tokens)
        interpreter = Path(tokens[index]).name if index is not None else ""
    except (ValueError, UnicodeDecodeError):
        return False
    return bool(re.fullmatch(r"(?:node|nodejs|python[\d.]*|pypy[\d.]*|ruby|perl)", interpreter))


def _read_referenced_script(path: Path, *, force_shell: bool = False) -> tuple[Optional[str], bool]:
    """Return ``(text, unsafe)`` using bounded, regular-file-only reads."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except (OSError, ValueError):
        # OSError: unreadable / missing / over-long paths. ValueError: an
        # embedded NUL byte in *path* itself — a binary's decoded bytes
        # tokenized into a bogus script path by the recursion (#77703). A
        # guarded read must never crash the guard, so treat either as
        # "nothing to scan" (mirrors the resolve() ValueError guard below).
        return None, False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, True
        # Read a bounded chunk first — even for oversized files, the first
        # chunk tells us if this is a binary (NUL bytes) that should be
        # skipped as "nothing to scan" rather than failing closed (#76762).
        data = os.read(descriptor, _MAX_REFERENCED_SCRIPT_BYTES + 1)
    except OSError:
        return None, False
    finally:
        os.close(descriptor)
    # A NUL byte in the first chunk means this is a binary (ELF/Mach-O/
    # PE), not a shell script — scanning its decoded contents would
    # tokenize machine code and feed junk paths into the recursion
    # (including a `ValueError: embedded null byte` from Path.resolve,
    # #76762). Treat it as "nothing to scan" rather than unsafe: a binary
    # executed by the user is not a referenced *shell script*.
    if b"\x00" in data:
        return None, False
    if not force_shell and _is_non_shell_script(data):
        return None, False
    if len(data) > _MAX_REFERENCED_SCRIPT_BYTES:
        return None, True
    return data.decode("utf-8", errors="replace"), False


def _sanitize_remote_script_text(text: Optional[str], *, force_shell: bool = False) -> tuple[Optional[str], bool]:
    """Apply the local-read contract to text from a ``read_remote_script`` callback.

    The recursion boundary must not trust its callbacks: any backend (SSH,
    Modal, Daytona, or a future one) can hand back raw binary bytes decoded
    as text, or arbitrarily large output. Mirror
    ``_read_referenced_script``'s semantics exactly — NUL bytes mean binary
    (nothing to scan, checked first, #77703), oversized text fails closed
    like an oversized local file (#76762) — so remote and local reads can
    never diverge again. The size check re-encodes to compare *bytes*
    (matching the local read and the ``head -c`` wire bound): a >1 MiB
    multibyte file truncated at the byte cap decodes to fewer characters
    than bytes, and a character-count check would scan the truncated text
    instead of failing closed. Enforced here rather than inside each
    callback so the guarantee holds for every callback, not just the ones
    we hardened.
    """
    if not text:
        return None, False
    if "\x00" in text:
        return None, False
    if not force_shell and _is_non_shell_script(text[:256].encode("utf-8")):
        return None, False
    if len(text.encode("utf-8", errors="replace")) > _MAX_REFERENCED_SCRIPT_BYTES:
        return None, True
    return text, False


def _contains_unsafe_gateway_action(
    command: str,
    *,
    cwd: Optional[str],
    depth: int,
    visited: set[tuple[Path, bool]],
    read_remote_script: Optional[_ReadRemoteScriptFn] = None,
) -> bool:
    syntax, heredoc_payloads = _extract_heredocs(command)
    if _contains_executed_lifecycle_command(syntax):
        return True
    if depth >= _MAX_REFERENCED_SCRIPT_DEPTH:
        return True

    for payload in (*_iter_shell_command_payloads(syntax), *_iter_command_substitutions(syntax), *heredoc_payloads):
        if _contains_unsafe_gateway_action(
            payload,
            cwd=cwd,
            depth=depth + 1,
            visited=visited,
            read_remote_script=read_remote_script,
        ):
            return True

    for script_path, force_shell in _iter_referenced_shell_scripts(syntax, cwd=cwd):
        try:
            resolved = script_path.resolve(strict=False)
        except (OSError, ValueError):
            # OSError: unreadable/long paths. ValueError: embedded NUL byte
            # from a binary's decoded contents tokenized as a path — a
            # guarded path must never crash the guard (#76762).
            resolved = script_path
        identity = (resolved, force_shell)
        if identity in visited:
            continue
        visited.add(identity)
        script_text, unsafe = _read_referenced_script(script_path, force_shell=force_shell)
        if unsafe:
            return True
        if script_text is None and read_remote_script is not None:
            # Local path missing; try the remote backend if one is available.
            # The callback's output crosses the same trust boundary as a
            # local read — sanitize it identically before it enters the
            # recursion (binary skip + size fail-closed).
            script_text, unsafe = _sanitize_remote_script_text(
                read_remote_script(str(script_path)), force_shell=force_shell
            )
            if unsafe:
                return True
        if not script_text:
            continue
        # Relative references inside a script resolve against that script's
        # directory, not the original command's cwd.
        script_dir = _resolve_script_directory(str(resolved)) or cwd
        if _contains_unsafe_gateway_action(
            script_text,
            cwd=script_dir,
            depth=depth + 1,
            visited=visited,
            read_remote_script=read_remote_script,
        ):
            return True
    return False


def contains_gateway_lifecycle_command_or_referenced_script(
    command: str,
    *,
    cwd: Optional[str] = None,
    read_remote_script: Optional[_ReadRemoteScriptFn] = None,
) -> bool:
    """Detect lifecycle/submit commands, including bounded nested scripts.

    Total by construction: this function returns a verdict for *every*
    input and never raises. The direct scans below are pure string
    operations; the referenced-script walk touches the filesystem, remote
    backends, and shlex on arbitrary decoded bytes, so it is best-effort
    defense-in-depth — any unexpected failure inside it is logged and
    treated as "walk found nothing" rather than crashing the caller.

    This is the contract #76762 established ("a guarded path must never
    crash the guard") enforced at the boundary instead of per-syscall: a
    guard crash propagates out of ``tools/terminal_tool.py`` and breaks
    every terminal command until the gateway restarts (#77780, #78256),
    which is strictly worse than either verdict.
    """
    try:
        # Includes the direct regex/submit scans at depth 0.
        return _contains_unsafe_gateway_action(
            command,
            cwd=cwd,
            depth=0,
            visited=set(),
            read_remote_script=read_remote_script,
        )
    except Exception:
        logger.warning(
            "lifecycle guard referenced-script walk failed; "
            "falling back to direct-scan verdict",
            exc_info=True,
        )
        # Pure string scans of the top-level command — cannot raise.
        return _contains_executed_lifecycle_command(command)




def _resolve_script_path(script_path: str) -> Optional[Path]:
    """Resolve a cron ``script`` value the same way the scheduler does.

    The scheduler (``cron.scheduler``) resolves a bare/relative script path
    under ``<HERMES_HOME>/scripts/`` and only accepts absolute paths as-is.
    We MUST mirror that here so the guard scans the file that will actually
    run — otherwise a job whose script lives at the scheduler's real location
    (``~/.hermes/scripts/restart.sh``) but is passed as the bare name
    ``restart.sh`` would read as a nonexistent relative path and silently
    scan prompt-only content, letting the command through.

    Returns ``None`` for values that cannot be a real path (NUL bytes,
    unexpandable ``~``) — the same ingestion contract as
    ``_expand_candidate_path``; such a value can never name a file the
    scheduler would execute, so there is nothing to scan.
    """
    from hermes_constants import get_hermes_home

    raw = _expand_candidate_path(script_path)
    if raw is None:
        return None
    if raw.is_absolute():
        return raw
    try:
        return get_hermes_home() / "scripts" / raw
    except (RuntimeError, OSError):
        # get_hermes_home() falls back to Path.home(), which raises when
        # neither HERMES_HOME nor HOME is resolvable (launchd/systemd
        # environments) — same ingestion contract: nothing to scan.
        return None


def _read_script_for_scanning(script_path: str) -> str:
    """Read a cron script with the bounded terminal-script scanner.

    Non-regular or oversized inputs fail closed by returning a lifecycle-shaped
    sentinel, while missing/unreadable/unresolvable paths remain empty so
    ordinary scheduler path validation can report them.
    """
    resolved = _resolve_script_path(script_path)
    if resolved is None:
        return ""
    script_text, unsafe = _read_referenced_script(resolved, force_shell=True)
    if unsafe:
        return "hermes gateway restart"
    return script_text or ""


def check_gateway_lifecycle(
    prompt: Optional[str],
    script: Optional[str] = None,
) -> None:
    """Raise ``GatewayLifecycleBlocked`` if *prompt* or *script* contains a
    gateway-lifecycle command pattern.

    ``prompt`` is scanned directly.  ``script``, when supplied, is read from
    disk and concatenated for the scan.  Both are considered together so a
    job cannot slip through by splitting the command across the prompt and
    the script.

    Callers should let the exception propagate when they want the create to
    fail with a ``ValueError``-shaped error (the agent's ``cronjob`` tool
    surfaces this as a tool error; the CLI prints it in red and exits 1).
    """
    combined = prompt or ""
    python_script = False
    if script:
        resolved_script = _resolve_script_path(script)
        python_script = resolved_script is not None and resolved_script.suffix == ".py"
        script_text = _read_script_for_scanning(script)
        if script_text:
            combined = f"{combined}\n{script_text}"

    if python_script:
        # Python is executed by the interpreter, never through a POSIX
        # shell: the shell-script reference walk is a false-positive
        # generator on Python sources (pathlib's "/" operator resolves to
        # the filesystem root and trips the regular-file check, blocking
        # every innocent .py cron script, #77131). The direct command
        # regex below still scans the full text, so a literal
        # `hermes gateway restart` embedded in a .py script is still
        # blocked. Non-regular/oversized script files still fail closed
        # via the lifecycle-shaped sentinel in _read_script_for_scanning.
        unsafe = contains_gateway_lifecycle_command(combined)
    else:
        script_dir = _resolve_script_directory(script) if script else None
        unsafe = contains_gateway_lifecycle_command(combined) or contains_gateway_lifecycle_command_or_referenced_script(
            combined,
            cwd=script_dir,
        )
    if unsafe:
        raise GatewayLifecycleBlocked(
            "Blocked: cron job contains a gateway lifecycle command or persistent "
            "launchctl submit operation. This is blocked to prevent agent-driven "
            "SIGTERM-respawn loops under launchd/systemd supervision "
            "(#30719). Run `hermes gateway restart` from a shell outside "
            "the running gateway instead."
        )
