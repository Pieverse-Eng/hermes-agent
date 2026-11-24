"""Host-bound proposal sessions reuse Agent research without arbitrary execution.

This does not sandbox a shell: shell/code/browser/delegation/background jobs and
unknown plugin/MCP tools are unavailable in this scope. Financial execution
belongs to the host's independently authenticated human-confirmation path.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import re
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
# The memory policy (v3): the research tools and one fixed tool that changes
# the notes of the room's own squad (gateway/room_memory.py).
PUBLIC_ROOM_MEMORY_POLICY = "squad-public-memory-v3"
PUBLIC_ROOM_MEMORY_TOOL = "room_memory"
# Hermes owns this toolset. Like the room research toolset it exists for
# shared rooms only.
PUBLIC_ROOM_MEMORY_TOOLSET = "pieverse-room-memory"
PUBLIC_ROOM_ONLY_TOOLSETS = frozenset({PUBLIC_ROOM_ONLY_TOOLSET, PUBLIC_ROOM_MEMORY_TOOLSET})
# The research tools of v2. The v2 declaration lists these names and no other.
_RESEARCH_TOOL_TOOLSETS = {
    "discover_markets": PUBLIC_ROOM_TOOLSET,
    "compare_trade_routes": PUBLIC_ROOM_TOOLSET,
    "plan_spot_purchase": PUBLIC_ROOM_TOOLSET,
    "market_snapshot": PUBLIC_ROOM_ONLY_TOOLSET,
    "market_candles": PUBLIC_ROOM_ONLY_TOOLSET,
    "onchain_token": PUBLIC_ROOM_ONLY_TOOLSET,
    "search_news": PUBLIC_ROOM_ONLY_TOOLSET,
    "search_web": PUBLIC_ROOM_ONLY_TOOLSET,
    "search_x": PUBLIC_ROOM_ONLY_TOOLSET,
}
# Reads of the room's own public history (platform #100). The platform plugin
# registers it in the room research toolset. A Run gets it only with the
# history grant that the platform sent in the Run's body
# (gateway/public_room.py `room_history_binding`): the allowlist of a research
# or memory room lists it only while that grant is bound (`public_room_scope`),
# so a Run without one has neither its schema nor its dispatch.
PUBLIC_ROOM_HISTORY_TOOL = "room_history"
# A room admits a name only from the fixed toolset that owns it.
PUBLIC_ROOM_TOOL_TOOLSETS = MappingProxyType({
    **_RESEARCH_TOOL_TOOLSETS, PUBLIC_ROOM_MEMORY_TOOL: PUBLIC_ROOM_MEMORY_TOOLSET,
    PUBLIC_ROOM_HISTORY_TOOL: PUBLIC_ROOM_ONLY_TOOLSET,
})
PUBLIC_ROOM_RESEARCH_TOOL_NAMES = frozenset(_RESEARCH_TOOL_TOOLSETS)
PUBLIC_ROOM_MEMORY_TOOL_NAMES = PUBLIC_ROOM_RESEARCH_TOOL_NAMES | {PUBLIC_ROOM_MEMORY_TOOL}
# Paid searches share one cap per reply.
PUBLIC_ROOM_SEARCH_TOOL_NAMES = frozenset({"search_web", "search_x"})
# The platform has no X search route for hosted instances yet. The policy
# admits the name once the platform plugin registers it; v2 does not need it.
PUBLIC_ROOM_OPTIONAL_TOOL_NAMES = frozenset({"search_x"})
PUBLIC_ROOM_MAX_TOOL_CALLS = 12
PUBLIC_ROOM_MAX_SEARCH_CALLS = 4
# Room text is untrusted and can ask for many notes: one reply changes the
# room memory a fixed number of times. These calls also count as tool calls.
PUBLIC_ROOM_MAX_MEMORY_CALLS = 3
# Requests to the model provider of one reply: every tool call plus refusals
# and the final answer. A retry and a stream reconnect are requests too.
PUBLIC_ROOM_MAX_MODEL_REQUESTS = PUBLIC_ROOM_MAX_TOOL_CALLS + 4
# The loop never turns more often than it may ask the model.
PUBLIC_ROOM_MAX_ITERATIONS = PUBLIC_ROOM_MAX_MODEL_REQUESTS
# The whole error of a Run that used its model requests. It names no provider,
# no request and no room text, and it matches no provider error pattern.
PUBLIC_ROOM_MODEL_BUDGET_ERROR = (
    f"Shared room reply stopped: this reply used all {PUBLIC_ROOM_MAX_MODEL_REQUESTS} "
    "of its model requests.")
PUBLIC_ROOM_POLICIES = MappingProxyType({
    PUBLIC_ROOM_POLICY: PUBLIC_ROOM_TOOL_NAMES,
    PUBLIC_ROOM_RESEARCH_POLICY: PUBLIC_ROOM_RESEARCH_TOOL_NAMES,
    PUBLIC_ROOM_MEMORY_POLICY: PUBLIC_ROOM_MEMORY_TOOL_NAMES,
})
# The policies whose Runs may hold a history grant: the ones with the research tools.
PUBLIC_ROOM_HISTORY_POLICIES = frozenset({PUBLIC_ROOM_RESEARCH_POLICY, PUBLIC_ROOM_MEMORY_POLICY})
# The active room policy id; None outside a room.
_public_room = ContextVar("public_room_execution_policy", default=None)
# The room memory of the active room Run (gateway.room_memory.RoomMemory): the
# store of the squad that the platform named for this Run. None outside a
# room, and in a room whose policy has no memory.
_public_room_memory = ContextVar("public_room_memory_binding", default=None)
# The room history grant of the active room Run: `(grant, path)` exactly as the
# platform sent it in the Run's body. None outside a room, in a v1 room and in
# a Run without one.
_public_room_history = ContextVar("public_room_history_binding", default=None)


def _narrower(current: str, requested: str) -> str:
    if PUBLIC_ROOM_POLICIES[requested] <= PUBLIC_ROOM_POLICIES[current]:
        return requested
    if PUBLIC_ROOM_POLICIES[current] <= PUBLIC_ROOM_POLICIES[requested]:
        return current
    return PUBLIC_ROOM_POLICY


# The default of `memory` and `history`: keep what the enclosing scope bound.
_KEEP_MEMORY = object()


def _history_value(history):
    """A history binding as stored: None, or a `(grant, path)` pair of strings.

    The Agent keeps the `{"grant", "path"}` form of `public_room_history()`;
    both forms bind the same grant.
    """
    if history is None or history is _KEEP_MEMORY:
        return history
    if isinstance(history, dict) and set(history) == {"grant", "path"}:
        history = (history["grant"], history["path"])
    if (isinstance(history, tuple) and len(history) == 2
            and all(isinstance(part, str) and part for part in history)):
        return history
    raise ValueError("Invalid room history binding")


@contextmanager
def public_room_scope(enabled: bool, *, policy: str | None = None, memory=_KEEP_MEMORY,
                      history=_KEEP_MEMORY):
    # Keep this independent of proposal scope: nested scopes cannot restore
    # private tools, including in a copied executor-thread context. A nested
    # scope can narrow the room policy and can never widen it; a room entered
    # without a policy gets the narrowest one.
    #
    # `memory` is the room memory of this Run. Only the code that admits or
    # restores a Run passes it: the request handler (the store of the squad
    # that the platform named) and the Agent's own tool boundary (the Agent's
    # store, or None for an Agent without one). A scope that does not pass it
    # keeps the store of the enclosing scope. A nested scope never replaces a
    # bound store with another one: two different stores bind none. A scope
    # whose policy has no memory tool binds none.
    #
    # `history` is the room history grant of this Run, `(grant, path)`, under
    # the same rules: only the code that admits or restores a Run passes it, a
    # scope that does not pass it keeps the enclosing one, two different grants
    # bind none, and a scope whose policy is neither the research nor the
    # memory policy binds none.
    if policy is not None and policy not in PUBLIC_ROOM_POLICIES:
        raise ValueError("Unknown public room policy")
    history = _history_value(history)
    current = _public_room.get()
    outer = _public_room_memory.get()
    outer_history = _public_room_history.get()
    if current is not None:
        active = current if policy is None else _narrower(current, policy)
        if memory is _KEEP_MEMORY:
            bound = outer
        elif outer is None or outer is memory:
            bound = memory
        else:
            bound = None
        if history is _KEEP_MEMORY:
            granted = outer_history
        elif outer_history is None or outer_history == history:
            granted = history
        else:
            granted = None
    else:
        active = (policy or PUBLIC_ROOM_POLICY) if enabled else None
        bound = None if memory is _KEEP_MEMORY else memory
        granted = None if history is _KEEP_MEMORY else history
    if active is None or PUBLIC_ROOM_MEMORY_TOOL not in PUBLIC_ROOM_POLICIES[active]:
        bound = None
    if active not in PUBLIC_ROOM_HISTORY_POLICIES:
        granted = None
    token = _public_room.set(active)
    memory_token = _public_room_memory.set(bound)
    history_token = _public_room_history.set(granted)
    try:
        yield
    finally:
        _public_room_history.reset(history_token)
        _public_room_memory.reset(memory_token)
        _public_room.reset(token)


def is_public_room_scope() -> bool:
    return _public_room.get() is not None


def public_room_policy() -> str | None:
    """The active room policy id, or None outside a room."""
    return _public_room.get()


def public_room_memory():
    """The room memory bound to the active room Run, or None."""
    return _public_room_memory.get()


def public_room_history():
    """The room history grant bound to the active room Run, or None.

    `{"grant", "path"}` exactly as the platform sent it in the Run's body; the
    platform plugin's `room_history` reads with it. Nothing of a model call
    selects or supplies it.
    """
    binding = _public_room_history.get()
    return None if binding is None else {"grant": binding[0], "path": binding[1]}


def public_room_tool_names(policy: str | None = None):
    """The allowlist of a room policy (default: the active one); None outside a room.

    The allowlist of the active Run also lists `room_history` while a history
    grant is bound to it.
    """
    active = _public_room.get()
    policy = active if policy is None else policy
    if policy is None:
        return None
    names = PUBLIC_ROOM_POLICIES[policy]
    if policy == active and _public_room_history.get() is not None:
        names = names | {PUBLIC_ROOM_HISTORY_TOOL}
    return names


def _registered_toolset(name: str):
    from tools.registry import registry
    return registry.get_toolset_for_tool(name)


def public_room_tool_bound(name: str) -> bool:
    """A registered room tool must come from the platform toolset that owns its name."""
    toolset = _registered_toolset(name)
    return toolset is None or toolset == PUBLIC_ROOM_TOOL_TOOLSETS.get(name)


def public_room_only_tool(name: str) -> bool:
    return _registered_toolset(name) in PUBLIC_ROOM_ONLY_TOOLSETS


def public_room_research_tools():
    """Research tools the platform plugin registered, or None when a required one is absent."""
    registered = frozenset(
        name for name, toolset in _RESEARCH_TOOL_TOOLSETS.items()
        if _registered_toolset(name) == toolset)
    required = PUBLIC_ROOM_RESEARCH_TOOL_NAMES - PUBLIC_ROOM_OPTIONAL_TOOL_NAMES
    return registered if required <= registered else None


def public_room_history_tool_registered() -> bool:
    """Whether the platform plugin registered `room_history` in the toolset that owns it."""
    return _registered_toolset(PUBLIC_ROOM_HISTORY_TOOL) == PUBLIC_ROOM_ONLY_TOOLSET


def public_room_memory_tools():
    """The tools of a memory room on this pod, or None when it cannot run one.

    A memory room needs every required research tool and the memory tool,
    each registered in the toolset that owns its name.
    """
    import tools.room_memory_tool  # noqa: F401  (registers the built-in memory tool)
    research = public_room_research_tools()
    if research is None or _registered_toolset(PUBLIC_ROOM_MEMORY_TOOL) != PUBLIC_ROOM_MEMORY_TOOLSET:
        return None
    return research | {PUBLIC_ROOM_MEMORY_TOOL}


_ROOM_MEMORY_ACTIONS = ("add", "replace", "remove")
_ROOM_MEMORY_NOTE_ID = re.compile(r"m[0-9]{1,9}")


def room_memory_call_record(arguments) -> dict:
    """What a `room_memory` call may show outside the model request that made it.

    One action of the tool and the id of a note, and no other text of the
    model. The text of a note stays in the room memory of its squad: a clear
    of that memory must leave no copy in a log, an event, a session row or a
    summary. The result is never empty, so no caller falls back to the raw
    arguments.
    """
    arguments = arguments if isinstance(arguments, dict) else {}
    action, note_id = arguments.get("action"), arguments.get("id")
    record = {"action": action if action in _ROOM_MEMORY_ACTIONS else "invalid"}
    if isinstance(note_id, str) and _ROOM_MEMORY_NOTE_ID.fullmatch(note_id):
        record["id"] = note_id
    return record


def durable_tool_calls(tool_calls):
    """The tool calls of an assistant message as they may be stored or summarized.

    Each `room_memory` call keeps its action and its note id only
    (`room_memory_call_record`). Every other call, and a list without such a
    call, comes back unchanged. The session store applies this to each row
    that it writes, so no write path can store the text of a note.

    The live message of a reply in progress keeps its own arguments: the
    model reads them in the same reply.
    """
    if not isinstance(tool_calls, list):
        return tool_calls
    stored = None
    for index, call in enumerate(tool_calls):
        if not isinstance(call, dict):
            continue
        function = call.get("function")
        holder = function if isinstance(function, dict) else call
        if holder.get("name") != PUBLIC_ROOM_MEMORY_TOOL or "arguments" not in holder:
            continue
        arguments = holder["arguments"]
        if isinstance(arguments, str):
            try:
                parsed = json.loads(arguments)
            except ValueError:
                parsed = None
            record = json.dumps(room_memory_call_record(parsed), separators=(",", ":"))
        else:
            record = room_memory_call_record(arguments)
        if stored is None:
            stored = list(tool_calls)
        changed = {**holder, "arguments": record}
        stored[index] = {**call, "function": changed} if holder is function else changed
    return tool_calls if stored is None else stored


class PublicRoomModelBudgetExceeded(Exception):
    """One room reply asked for more model requests than its budget has."""

    def __init__(self):
        super().__init__(PUBLIC_ROOM_MODEL_BUDGET_ERROR)


class PublicRoomBudget:
    """Tool calls and model requests of one room reply.

    Tool output is untrusted and can ask for more calls. A provider that fails
    can ask for more requests. Neither changes what one reply may spend.
    """

    def __init__(self, max_calls=PUBLIC_ROOM_MAX_TOOL_CALLS, max_searches=PUBLIC_ROOM_MAX_SEARCH_CALLS,
                 max_requests=PUBLIC_ROOM_MAX_MODEL_REQUESTS,
                 max_memory_calls=PUBLIC_ROOM_MAX_MEMORY_CALLS):
        self.max_calls, self.max_searches, self.max_requests = max_calls, max_searches, max_requests
        self.max_memory_calls = max_memory_calls
        self.calls = self.searches = self.requests = self.memory_calls = 0
        self._lock = threading.Lock()

    def charge_model_request(self):
        """Count one request to the model provider; refuse the one over the cap."""
        with self._lock:
            if self.requests >= self.max_requests:
                raise PublicRoomModelBudgetExceeded()
            self.requests += 1

    def charge(self, name: str):
        """Count one admitted call; return a refusal when the reply is over a cap."""
        search = name in PUBLIC_ROOM_SEARCH_TOOL_NAMES
        memory = name == PUBLIC_ROOM_MEMORY_TOOL
        with self._lock:
            if self.calls >= self.max_calls:
                limit, kind = self.max_calls, "tool calls"
            elif search and self.searches >= self.max_searches:
                limit, kind = self.max_searches, "web and X searches"
            elif memory and self.memory_calls >= self.max_memory_calls:
                limit, kind = self.max_memory_calls, "room memory changes"
            else:
                self.calls += 1
                self.searches += search
                self.memory_calls += memory
                return None
        return json.dumps({
            "error": f"This room reply reached its limit of {limit} {kind}. "
                     "Answer now with the evidence already returned.",
            "error_type": "public_room_tool_budget", "tool": name, "limit": limit})


def public_room_budget_error(agent, name: str):
    """Charge the Agent's reply budget at the Agent-local dispatch boundary."""
    budget = getattr(agent, "public_room_budget", None)
    if not isinstance(budget, PublicRoomBudget):
        budget = PublicRoomBudget()
        try:
            agent.public_room_budget = budget
        except Exception:
            return json.dumps({"error": "Shared room tool budget is unavailable.",
                               "error_type": "public_room_tool_budget", "tool": name, "limit": 0})
    return budget.charge(name)


def public_room_model_budget(agent):
    """The budget that the model requests of a room reply spend; None outside a room."""
    if getattr(agent, "public_room_policy", False) is not True and not is_public_room_scope():
        return None
    budget = getattr(agent, "public_room_budget", None)
    if not isinstance(budget, PublicRoomBudget):
        # A room Agent without a budget sends nothing.
        raise PublicRoomModelBudgetExceeded()
    return budget


def charge_public_room_model_request(agent):
    """Count one model request of a room reply. Call it directly before each send.

    Every attempt is a request: a first try, a retry after a provider error and
    a stream reconnect. Outside a room this does nothing. In a room it raises
    PublicRoomModelBudgetExceeded in place of the request over the cap, so the
    cap holds however the caller handles that error.
    """
    budget = public_room_model_budget(agent)
    if budget is not None:
        budget.charge_model_request()

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
                          else "Shared rooms permit public read-only research tools only."
                          if _public_room.get() == PUBLIC_ROOM_RESEARCH_POLICY
                          else "Shared rooms permit public read-only research tools and the "
                               "room memory tool only."),
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
