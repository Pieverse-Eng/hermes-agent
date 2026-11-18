"""Host-bound proposal sessions reuse Agent research without arbitrary execution.

This does not sandbox a shell: shell/code/browser/delegation/background jobs and
unknown plugin/MCP tools are unavailable in this scope. Financial execution
belongs to the host's independently authenticated human-confirmation path.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import json

PROPOSAL_ONLY_TOOL_NAMES = frozenset({
    "web_search", "web_extract", "x_search",
    "memory", "session_search", "todo", "skills_list", "skill_view", "send_message", "clarify",
})
_policy = ContextVar("host_tool_execution_policy", default=None)
PUBLIC_ROOM_POLICY = "squad-public-market-v1"
PUBLIC_ROOM_TOOL_NAMES = frozenset({"discover_markets"})
_public_room = ContextVar("public_room_execution_policy", default=False)


@contextmanager
def public_room_scope(enabled: bool):
    # Keep this independent of proposal scope: nested scopes cannot restore
    # private tools, including in a copied executor-thread context.
    token = _public_room.set(bool(enabled) or _public_room.get())
    try:
        yield
    finally:
        _public_room.reset(token)


def is_public_room_scope() -> bool:
    return _public_room.get()

@contextmanager
def proposal_only_scope(enabled: bool, *, host_tools=(), available_tools=None):
    from tools.registry import registry
    host_names = frozenset(host_tools)
    if any(registry.get_toolset_for_tool(name) != "api_host_tools" for name in host_names):
        raise ValueError("Host tools must be registered in the api_host_tools proxy toolset")
    allowed = PROPOSAL_ONLY_TOOL_NAMES | host_names
    if available_tools is not None:
        allowed &= frozenset(available_tools)
    token = _policy.set(allowed if enabled else None)
    try:
        yield
    finally:
        _policy.reset(token)

def is_proposal_only_scope() -> bool:
    return _public_room.get() or _policy.get() is not None

def proposal_available_tools():
    allowed = _policy.get()
    if _public_room.get():
        return PUBLIC_ROOM_TOOL_NAMES if allowed is None else PUBLIC_ROOM_TOOL_NAMES & allowed
    return allowed

def proposal_available_toolsets():
    from tools.registry import registry
    return {toolset for name in (proposal_available_tools() or ())
            if (toolset := registry.get_toolset_for_tool(name))}

def execution_scope_error(name: str):
    if _public_room.get() and name not in PUBLIC_ROOM_TOOL_NAMES:
        return json.dumps({"error": "Shared rooms permit public market discovery only.",
                           "error_type": "public_room_isolation", "tool": name})
    allowed = _policy.get()
    if allowed is not None and name not in allowed:
        return json.dumps({"error": "This proposal-only conversation cannot execute arbitrary tools. Prepare a host card for the user's separate review and confirmation.", "error_type": "proposal_only", "tool": name})
    return None

# A versioned business-proxy manifest adds no native execution permission.
# Owner tool configuration remains authoritative; unlike proposal scope this
# scope only exposes explicitly bound proxy schemas.
_bound_host_tools = ContextVar("bound_current_host_tools", default=frozenset())
_compact_tool_disclosure = ContextVar("compact_host_tool_disclosure", default=False)

@contextmanager
def host_tool_scope(names=(), *, compact=False):
    from tools.registry import registry
    if any(registry.get_toolset_for_tool(name) != "api_host_tools" for name in names):
        raise ValueError("Host tools must be registered proxies")
    token = _bound_host_tools.set(frozenset(names))
    disclosure_token = _compact_tool_disclosure.set(bool(compact))
    try:
        yield
    finally:
        _compact_tool_disclosure.reset(disclosure_token)
        _bound_host_tools.reset(token)

def bound_host_tools():
    return _bound_host_tools.get()

def compact_tool_disclosure():
    """Presentation only: original toolsets and execution permissions still apply."""
    return _compact_tool_disclosure.get()
