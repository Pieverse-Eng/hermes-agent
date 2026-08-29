"""Runtime authorization for platform-managed News Ingress runs."""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from typing import Any


_READ_TOOLS = frozenset({"web_search", "web_extract"})
_VALUE_RE = re.compile(r"^[A-Za-z0-9._:/=-]{1,256}$")


def _valid_client_argv(argv: list[str], client_path: str) -> bool:
    if len(argv) < 3 or argv[:2] != ["node", client_path]:
        return False
    if argv[2:] == ["pull"]:
        return True
    if len(argv) in {5, 7} and argv[2] == "read" and argv[3] == "--item-id":
        if not _VALUE_RE.fullmatch(argv[4]):
            return False
        return len(argv) == 5 or (
            argv[5] == "--version-id" and bool(_VALUE_RE.fullmatch(argv[6]))
        )
    return (
        len(argv) == 7
        and argv[2] == "ack"
        and argv[3] == "--claim-token"
        and bool(_VALUE_RE.fullmatch(argv[4]))
        and argv[5] == "--thinking-work-id"
        and bool(_VALUE_RE.fullmatch(argv[6]))
    )


def authorize_news_ingress_tool(
    agent: Any,
    tool_name: str,
    args: Mapping[str, Any] | None,
) -> str | None:
    """Return a refusal for a prohibited News run tool call, else ``None``."""
    client_path = getattr(agent, "_purrfect_news_client_path", None)
    if not isinstance(client_path, str) or not client_path:
        return None
    if tool_name in _READ_TOOLS:
        return None
    if tool_name != "terminal" or not isinstance(args, Mapping):
        return f"Tool '{tool_name}' is not allowed in a News Ingress background run."
    if set(args) != {"command"} or not isinstance(args.get("command"), str):
        return (
            "This terminal invocation is not allowed in a News Ingress background run."
        )
    try:
        argv = shlex.split(args["command"], posix=True)
    except ValueError:
        argv = []
    if not _valid_client_argv(argv, client_path):
        return "This terminal command is not allowed in a News Ingress background run."
    return None
