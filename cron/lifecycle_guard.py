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
    r"(?:hermes\s+gateway\s+(?:restart|stop)\b)"
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
    # Leading \b ensures we match "pkill" or "kill" as whole words, not as
    # suffixes of other words (e.g. "skill" -> "kill").
    r"|(?:\bp?kill\b[^\n]*\bhermes\b[^\n]*\bgateway)"
    r"|(?:\bp?kill\b[^\n]*\bgateway\b[^\n]*\bhermes)"
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
_CONTROL_CHARS = frozenset(";&|()")




_ReadRemoteScriptFn = Callable[[str], Optional[str]]


def _split_logical_lines(text: str) -> list[str]:
    """Split text on newlines that are not inside quotes.

    A newline inside a quoted string (single or double quotes) is data,
    not a command separator. Handles escaped quotes within strings.
    """
    lines = []
    current = []
    in_single = False
    in_double = False
    escape = False

    for ch in text:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            escape = True
            current.append(ch)
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            current.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            current.append(ch)
            continue
        if ch == "\n" and not in_single and not in_double:
            lines.append("".join(current))
            current = []
            continue
        current.append(ch)

    if current:
        lines.append("".join(current))
    return lines


def _iter_command_segments(command: str) -> Iterator[list[str]]:
    """Yield shell-tokenized command segments, honoring quotes and comments.

    A newline inside a quoted token is data, not a command separator.
    First split on logical lines (newlines outside quotes), then tokenize
    each logical line with shlex. If a logical line cannot be tokenized
    (unbalanced quotes), fall back to per-physical-line tokenization for
    that logical line.
    """
    normalized = command.replace("\\\n", "")
    logical_lines = _split_logical_lines(normalized)

    for line in logical_lines:
        # Try to tokenize the logical line as a whole.
        try:
            lexer = shlex.shlex(
                line,
                posix=True,
                punctuation_chars=";&|()",
            )
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError:
            # Fall back to per-physical-line tokenization for this logical line.
            # This handles cases where quotes are unbalanced across lines.
            for physical_line in line.splitlines():
                try:
                    lexer = shlex.shlex(
                        physical_line,
                        posix=True,
                        punctuation_chars=";&|()",
                    )
                    lexer.whitespace_split = True
                    lexer.commenters = "#"
                    tokens = list(lexer)
                except ValueError:
                    continue

                segment: list[str] = []
                for token in tokens:
                    if token and set(token) <= _CONTROL_CHARS:
                        if segment:
                            yield segment
                            segment = []
                        continue
                    segment.append(token)
                if segment:
                    yield segment
            continue

        segment: list[str] = []
        for token in tokens:
            if token and set(token) <= _CONTROL_CHARS:
                if segment:
                    yield segment
                    segment = []
                continue
            segment.append(token)
        if segment:
            yield segment


def _executable_name(token: str) -> str:
    """Return the command name for a tokenized executable token.

    ``Path(token).name`` is right for real paths (``/usr/bin/bash`` →
    ``bash``), but pathlib has no name component for the pure-path tokens
    ``.``, ``..`` and ``/``, so it returns "" for them. The POSIX
    dot-source builtin is spelled ``.``, so keying the sourced-script
    branch on ``Path(token).name`` alone made it unreachable: ``source
    ./helper.sh`` was scanned but its exact synonym ``. ./helper.sh`` was
    not, letting a referenced script carrying a lifecycle command through
    both the cron guard and the in-gateway terminal guard. Fall back to the
    raw token so ``.`` survives.
    """
    return Path(token).name or token


# Prefixes that hand execution straight to their argument tail: the command
# that actually runs sits further right. A guard that reads only the first
# token sees `sudo`/`env`/`nohup` and never inspects what they run, so
# `sudo bash ~/restart.sh` walked past the same walk that stops
# `bash ~/restart.sh`, and `sudo launchctl submit ...` past the
# label-independent submit block (#62891). `_PIPE_TO_INTERPRETER` above
# already reads `sudo ` this way for the pipe case; this generalises that
# reading to the command position.
_TRANSPARENT_COMMAND_PREFIXES = frozenset({
    "sudo", "doas", "env", "nohup", "setsid", "nice", "ionice", "stdbuf",
    "timeout", "exec", "command", "builtin", "eatmydata",
})

# Options of those wrappers that consume the NEXT token as their value, so a
# value is never mistaken for the wrapped command (`sudo -u deploy bash x.sh`).
_TRANSPARENT_PREFIX_VALUE_OPTIONS = {
    "sudo": {"-u", "-g", "-U", "-C", "-p", "-r", "-t", "-T",
             "--user", "--group", "--prompt"},
    "doas": {"-u", "-C"},
    "env": {"-u", "--unset", "-S", "--split-string", "-C", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "--class", "--classdata"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
}

# Wrappers whose first non-option operand is a VALUE, not the command
# (`timeout 60 bash x.sh`).
_TRANSPARENT_PREFIX_OPERANDS = {"timeout": 1}

_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Bound the walk: a pathological token run must not spin here.
_MAX_PREFIX_PEELS = 8


def _peel_transparent_prefixes(segment: list[str], index: int) -> int:
    """Return the index of the command a wrapper chain actually executes.

    Returns *index* unchanged when the token there is not a wrapper, and may
    return ``len(segment)`` when a wrapper has no operand — callers must
    bounds-check before indexing.
    """
    for _ in range(_MAX_PREFIX_PEELS):
        if index >= len(segment):
            return index
        name = _executable_name(segment[index])
        if name not in _TRANSPARENT_COMMAND_PREFIXES:
            return index
        wrapper_index = index
        value_options = _TRANSPARENT_PREFIX_VALUE_OPTIONS.get(name, frozenset())
        index += 1
        while index < len(segment):
            token = segment[index]
            if token == "--":
                # POSIX end-of-options: the command starts at the next token.
                index += 1
                break
            if name == "env" and (
                token == "--split-string" or token.startswith("--split-string=")
                or token.startswith("-S")
            ):
                # The command is inside this option's string. Preserve the
                # wrapper for the upstream payload walk instead of losing it.
                return wrapper_index
            if token in value_options:
                index += 2
                continue
            if token.startswith("-") or _ENV_ASSIGNMENT.match(token):
                index += 1
                continue
            break
        for _ in range(_TRANSPARENT_PREFIX_OPERANDS.get(name, 0)):
            if index < len(segment) and not segment[index].startswith("-"):
                index += 1
    return index


def _command_token_index(segment: list[str]) -> Optional[int]:
    """Return the executable token index after simple env assignments."""
    for index, token in enumerate(segment):
        if _ENV_ASSIGNMENT.match(token):
            continue
        return index
    return None


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
        index = _peel_transparent_prefixes(segment, index)
        if index >= len(segment):
            continue
        if _executable_name(segment[index]) == "launchctl":
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


def _references_at(
    segment: list[str], index: int, cwd: Optional[str]
) -> Iterator[tuple[Path, bool]]:
    """Yield the scripts the token at *index* executes, if any."""
    if index >= len(segment):
        return
    executable = segment[index]
    executable_name = _executable_name(executable)

    if executable_name in {".", "source"}:
        if len(segment) > index + 1:
            resolved = _resolve_terminal_script_path(segment[index + 1], cwd)
            if resolved is not None:
                yield resolved, True
        return

    if executable_name in _SHELL_EXECUTABLES:
        arguments = segment[index + 1 :]
        arg_index = 0
        while arg_index < len(arguments):
            argument = arguments[arg_index]
            if argument == "--":
                arg_index += 1
                break
            if argument in {"-c", "--command"}:
                break
            if argument in _SHELL_OPTIONS_WITH_VALUES:
                arg_index += 2
                continue
            if argument.startswith("-"):
                arg_index += 1
                continue
            break
        if arg_index < len(arguments) and arguments[arg_index] not in {
            "-c",
            "--command",
        }:
            resolved = _resolve_terminal_script_path(arguments[arg_index], cwd)
            if resolved is not None:
                yield resolved, True
        return

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


def _iter_referenced_shell_scripts(
    command: str,
    *,
    cwd: Optional[str] = None,
) -> Iterator[tuple[Path, bool]]:
    """Yield scripts executed directly or through a POSIX shell.

    Each segment is read twice: once at the token the walk has always used,
    and again at the command a wrapper chain hands off to. Additive on
    purpose — peeling must never REMOVE a reference the un-peeled read would
    have found. A local script named ``./timeout`` is a script, not the
    coreutils wrapper, and reading only the peeled index would skip it.
    """
    for segment in _iter_command_segments(command):
        index = _command_token_index(segment)
        if index is None:
            continue
        yield from _references_at(segment, index, cwd)
        peeled = _peel_transparent_prefixes(segment, index)
        if peeled != index:
            yield from _references_at(segment, peeled, cwd)


def _iter_option_values(segment: list[str], start: int, option: str) -> Iterator[str]:
    """Yield option values, following the official upstream payload helper."""
    prefix = option + "="
    for position in range(start + 1, len(segment)):
        token = segment[position]
        if token == "--":
            break
        if token == option and position + 1 < len(segment):
            yield segment[position + 1]
        elif token.startswith(prefix):
            yield token[len(prefix):]
        elif option == "-S" and token.startswith("-S") and len(token) > 2:
            yield token[2:]


def _iter_shell_command_payloads(command: str) -> Iterator[str]:
    """Yield code passed through ``sh|bash|... -c`` for recursive scanning."""
    for segment in _iter_command_segments(command):
        index = _command_token_index(segment)
        if index is None:
            continue
        index = _peel_transparent_prefixes(segment, index)
        if index >= len(segment):
            continue
        if _executable_name(segment[index]) == "env":
            yield from _iter_option_values(segment, index, "-S")
            yield from _iter_option_values(segment, index, "--split-string")
            continue
        if _executable_name(segment[index]) not in _SHELL_EXECUTABLES:
            continue
        arguments = segment[index + 1 :]
        for arg_index, argument in enumerate(arguments[:-1]):
            if argument in {"-c", "--command"}:
                yield arguments[arg_index + 1]
                break


def _resolve_script_directory(script_path: str) -> Optional[str]:
    """Return the directory *script_path* resolves to, handling relative names."""
    try:
        path = _resolve_script_path(script_path)
        if path is not None and path.is_absolute():
            return str(path.parent)
    except Exception:
        pass
    return None


def _is_node_script(data: bytes) -> bool:
    """Identify known interpreters before applying the shell scanning cap."""
    header = data.split(b"\n", 1)[0][:256]
    if not header.startswith(b"#!"):
        return False
    try:
        tokens = shlex.split(header[2:].decode("utf-8"))
        index = _command_token_index(tokens)
        if index is not None:
            index = _peel_transparent_prefixes(tokens, index)
        if index is not None and index >= len(tokens):
            return False
        interpreter = Path(tokens[index]).name if index is not None else ""
    except (ValueError, UnicodeDecodeError):
        return False
    return bool(re.fullmatch(r"(?:node|nodejs)", interpreter))


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
    if not force_shell and _is_node_script(data):
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
    if not force_shell and _is_node_script(text[:256].encode("utf-8")):
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
    if contains_gateway_lifecycle_command(command) or contains_launchctl_submit_command(
        command
    ):
        return True
    if depth >= _MAX_REFERENCED_SCRIPT_DEPTH:
        return True

    for payload in _iter_shell_command_payloads(command):
        if _contains_unsafe_gateway_action(
            payload,
            cwd=cwd,
            depth=depth + 1,
            visited=visited,
            read_remote_script=read_remote_script,
        ):
            return True

    for script_path, force_shell in _iter_referenced_shell_scripts(command, cwd=cwd):
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
        return contains_gateway_lifecycle_command(
            command
        ) or contains_launchctl_submit_command(command)




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
        unsafe = contains_gateway_lifecycle_command_or_referenced_script(
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
