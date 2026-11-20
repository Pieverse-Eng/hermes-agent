"""Host-bound proposal sessions reuse Agent research without arbitrary execution.

This does not sandbox a shell: shell/code/browser/delegation/background jobs and
unknown plugin/MCP tools are unavailable in this scope. Financial execution
belongs to the host's independently authenticated human-confirmation path.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import threading
from types import MappingProxyType

PROPOSAL_ONLY_TOOL_NAMES = frozenset({
    "web_search", "web_extract", "x_search",
    "memory", "session_search", "todo", "skills_list", "skill_view", "send_message", "clarify",
})
_policy = ContextVar("host_tool_execution_policy", default=None)
PUBLIC_ROOM_POLICY = "squad-public-market-v1"
PUBLIC_ROOM_TOOL_NAMES = frozenset({"discover_markets"})
# The platform plugin's toolset that private conversations also use.
PUBLIC_ROOM_TOOLSET = "pieverse-market-research"
# Tools of this toolset exist for shared rooms only: outside a room they get
# neither a schema nor a dispatch, whatever the owner's toolset configuration.
PUBLIC_ROOM_ONLY_TOOLSET = "pieverse-room-research"
PUBLIC_ROOM_RESEARCH_POLICY = "squad-public-research-v2"
# A room admits a name only from the fixed platform toolset that owns it.
PUBLIC_ROOM_TOOL_TOOLSETS = MappingProxyType({
    "discover_markets": PUBLIC_ROOM_TOOLSET,
    "compare_trade_routes": PUBLIC_ROOM_TOOLSET,
    "plan_spot_purchase": PUBLIC_ROOM_TOOLSET,
    "market_snapshot": PUBLIC_ROOM_ONLY_TOOLSET,
    "market_candles": PUBLIC_ROOM_ONLY_TOOLSET,
    "onchain_token": PUBLIC_ROOM_ONLY_TOOLSET,
    "search_news": PUBLIC_ROOM_ONLY_TOOLSET,
    "search_web": PUBLIC_ROOM_ONLY_TOOLSET,
    "search_x": PUBLIC_ROOM_ONLY_TOOLSET,
})
PUBLIC_ROOM_RESEARCH_TOOL_NAMES = frozenset(PUBLIC_ROOM_TOOL_TOOLSETS)
# Paid searches share one cap per reply.
PUBLIC_ROOM_SEARCH_TOOL_NAMES = frozenset({"search_web", "search_x"})
# The platform has no X search route for hosted instances yet. The policy
# admits the name once the platform plugin registers it; v2 does not need it.
PUBLIC_ROOM_OPTIONAL_TOOL_NAMES = frozenset({"search_x"})
PUBLIC_ROOM_MAX_TOOL_CALLS = 12
PUBLIC_ROOM_MAX_SEARCH_CALLS = 4
# Model calls of one reply: every tool call plus refusals and the final answer.
PUBLIC_ROOM_MAX_ITERATIONS = PUBLIC_ROOM_MAX_TOOL_CALLS + 4
PUBLIC_ROOM_POLICIES = MappingProxyType({
    PUBLIC_ROOM_POLICY: PUBLIC_ROOM_TOOL_NAMES,
    PUBLIC_ROOM_RESEARCH_POLICY: PUBLIC_ROOM_RESEARCH_TOOL_NAMES,
})
# The active room policy id; None outside a room.
_public_room = ContextVar("public_room_execution_policy", default=None)


def _narrower(current: str, requested: str) -> str:
    if PUBLIC_ROOM_POLICIES[requested] <= PUBLIC_ROOM_POLICIES[current]:
        return requested
    if PUBLIC_ROOM_POLICIES[current] <= PUBLIC_ROOM_POLICIES[requested]:
        return current
    return PUBLIC_ROOM_POLICY


@contextmanager
def public_room_scope(enabled: bool, *, policy: str | None = None):
    # Keep this independent of proposal scope: nested scopes cannot restore
    # private tools, including in a copied executor-thread context. A nested
    # scope can narrow the room policy and can never widen it; a room entered
    # without a policy gets the narrowest one.
    if policy is not None and policy not in PUBLIC_ROOM_POLICIES:
        raise ValueError("Unknown public room policy")
    current = _public_room.get()
    if current is not None:
        active = current if policy is None else _narrower(current, policy)
    else:
        active = (policy or PUBLIC_ROOM_POLICY) if enabled else None
    token = _public_room.set(active)
    try:
        yield
    finally:
        _public_room.reset(token)


def is_public_room_scope() -> bool:
    return _public_room.get() is not None


def public_room_policy() -> str | None:
    """The active room policy id, or None outside a room."""
    return _public_room.get()


def public_room_tool_names(policy: str | None = None):
    """The allowlist of a room policy (default: the active one); None outside a room."""
    policy = _public_room.get() if policy is None else policy
    return None if policy is None else PUBLIC_ROOM_POLICIES[policy]


def _registered_toolset(name: str):
    from tools.registry import registry
    return registry.get_toolset_for_tool(name)


def public_room_tool_bound(name: str) -> bool:
    """A registered room tool must come from the platform toolset that owns its name."""
    toolset = _registered_toolset(name)
    return toolset is None or toolset == PUBLIC_ROOM_TOOL_TOOLSETS.get(name)


def public_room_only_tool(name: str) -> bool:
    return _registered_toolset(name) == PUBLIC_ROOM_ONLY_TOOLSET


def public_room_research_tools():
    """Research tools the platform plugin registered, or None when a required one is absent."""
    registered = frozenset(
        name for name, toolset in PUBLIC_ROOM_TOOL_TOOLSETS.items()
        if _registered_toolset(name) == toolset)
    required = PUBLIC_ROOM_RESEARCH_TOOL_NAMES - PUBLIC_ROOM_OPTIONAL_TOOL_NAMES
    return registered if required <= registered else None


class PublicRoomToolBudget:
    """Tool calls of one room reply. Tool output is untrusted and can ask for more calls."""

    def __init__(self, max_calls=PUBLIC_ROOM_MAX_TOOL_CALLS, max_searches=PUBLIC_ROOM_MAX_SEARCH_CALLS):
        self.max_calls, self.max_searches = max_calls, max_searches
        self.calls = self.searches = 0
        self._lock = threading.Lock()

    def charge(self, name: str):
        """Count one admitted call; return a refusal when the reply is over a cap."""
        search = name in PUBLIC_ROOM_SEARCH_TOOL_NAMES
        with self._lock:
            if self.calls >= self.max_calls:
                limit, kind = self.max_calls, "tool calls"
            elif search and self.searches >= self.max_searches:
                limit, kind = self.max_searches, "web and X searches"
            else:
                self.calls += 1
                self.searches += search
                return None
        return json.dumps({
            "error": f"This room reply reached its limit of {limit} {kind}. "
                     "Answer now with the evidence already returned.",
            "error_type": "public_room_tool_budget", "tool": name, "limit": limit})


def public_room_budget_error(agent, name: str):
    """Charge the Agent's reply budget at the Agent-local dispatch boundary."""
    budget = getattr(agent, "public_room_budget", None)
    if not isinstance(budget, PublicRoomToolBudget):
        budget = PublicRoomToolBudget()
        try:
            agent.public_room_budget = budget
        except Exception:
            return json.dumps({"error": "Shared room tool budget is unavailable.",
                               "error_type": "public_room_tool_budget", "tool": name, "limit": 0})
    return budget.charge(name)

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
    return _public_room.get() is not None or _policy.get() is not None

def proposal_available_tools():
    allowed = _policy.get()
    room = public_room_tool_names()
    if room is not None:
        return room if allowed is None else room & allowed
    return allowed

def proposal_available_toolsets():
    from tools.registry import registry
    return {toolset for name in (proposal_available_tools() or ())
            if (toolset := registry.get_toolset_for_tool(name))}

def execution_scope_error(name: str):
    room = public_room_tool_names()
    if room is not None:
        if name not in room or not public_room_tool_bound(name):
            return json.dumps({
                "error": ("Shared rooms permit public market discovery only."
                          if _public_room.get() == PUBLIC_ROOM_POLICY
                          else "Shared rooms permit public read-only research tools only."),
                "error_type": "public_room_isolation", "tool": name})
    elif public_room_only_tool(name):
        return json.dumps({"error": "This tool is available in shared squad rooms only.",
                           "error_type": "public_room_only", "tool": name})
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
