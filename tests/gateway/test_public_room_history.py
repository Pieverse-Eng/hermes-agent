"""Room history (platform #100): a room Run reads its room's history only with its grant.

The platform sends `room_history: {grant, path}` in the body of a research or
memory Run to a pod that declares the tool. Hermes binds that grant to the
Run's room scope; the platform plugin's `room_history` tool reads it from
there and never from the model's arguments. A Run without a grant has neither
the tool's schema nor its dispatch. Tests stub inference; no paid model call.
"""
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.public_room import (
    ROOM_RESEARCH_FEATURE, ROOM_RUN_PATH, SESSION_PREFIX, room_history_binding,
    room_research_capability, validate_room_request,
)
from tools.execution_scope import (
    PUBLIC_ROOM_HISTORY_POLICIES, PUBLIC_ROOM_HISTORY_TOOL, PUBLIC_ROOM_MEMORY_POLICY,
    PUBLIC_ROOM_ONLY_TOOLSET, PUBLIC_ROOM_POLICY, PUBLIC_ROOM_RESEARCH_POLICY,
    PUBLIC_ROOM_RESEARCH_TOOL_NAMES, PUBLIC_ROOM_SEARCH_TOOL_NAMES, PUBLIC_ROOM_TOOL_TOOLSETS,
    execution_scope_error, proposal_available_tools, public_room_history, public_room_policy,
    public_room_scope, public_room_tool_names,
)
from tests.gateway.test_api_server_runs import _make_adapter, _create_runs_app

AUTH = {"Authorization": "Bearer room-fixture-key"}
MODEL = {"model": {"provider": "openai", "api_mode": "chat_completions"}}
GRANT = "Ab0_-" * 8 + "xyz"
PATH = "/v1/instances/0f9fd9c4-0da1-40e7-be10-7d13dce8acf6/room-history"
BINDING = {"grant": GRANT, "path": PATH}
OTHER = {"grant": "Z" * 43, "path": PATH}


def request_body(policy=PUBLIC_ROOM_RESEARCH_POLICY, **extra):
    return {"session_id": SESSION_PREFIX + str(uuid4()), "input": "public room JSON",
            "room_policy": policy, **extra}


def register(name, toolset, handler):
    from tools.registry import registry
    registry.register(name=name, toolset=toolset, handler=handler,
                      schema={"name": name, "description": "Public read",
                              "parameters": {"type": "object", "properties": {}}})


@pytest.fixture
def history_room(monkeypatch):
    """A pod whose platform plugin registered the research tools and `room_history`.

    Returns the grants that the `room_history` handler found bound when it ran.
    """
    from tools.registry import registry
    monkeypatch.setattr(registry, "_tools", dict(registry._tools))
    monkeypatch.setattr("gateway.run._load_gateway_config", lambda: MODEL)
    for name in sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES):
        register(name, PUBLIC_ROOM_TOOL_TOOLSETS[name],
                 Mock(return_value=json.dumps({"tool": name})))
    seen = []

    def read(*_args, **_kwargs):
        seen.append(public_room_history())
        return json.dumps({"tool": PUBLIC_ROOM_HISTORY_TOOL})
    register(PUBLIC_ROOM_HISTORY_TOOL, PUBLIC_ROOM_ONLY_TOOLSET, Mock(side_effect=read))
    return seen


# --- Declaration --------------------------------------------------------------------

def test_the_tool_is_room_only_and_declared_only_while_the_plugin_registers_it(history_room):
    from tools.registry import registry
    assert PUBLIC_ROOM_TOOL_TOOLSETS[PUBLIC_ROOM_HISTORY_TOOL] == PUBLIC_ROOM_ONLY_TOOLSET
    assert PUBLIC_ROOM_HISTORY_POLICIES == {PUBLIC_ROOM_RESEARCH_POLICY, PUBLIC_ROOM_MEMORY_POLICY}
    declared = room_research_capability()
    assert declared["tools"] == sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES | {PUBLIC_ROOM_HISTORY_TOOL})
    # It is no paid search.
    assert declared["search_tools"] == sorted(PUBLIC_ROOM_SEARCH_TOOL_NAMES)
    assert ROOM_RESEARCH_FEATURE == "squad_room_research_v2"
    # Without the plugin's tool the declaration is the one deployed platforms know.
    del registry._tools[PUBLIC_ROOM_HISTORY_TOOL]
    assert room_research_capability()["tools"] == sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES)


# --- The binding of a Run -----------------------------------------------------------

@pytest.mark.parametrize("policy", [PUBLIC_ROOM_RESEARCH_POLICY, PUBLIC_ROOM_MEMORY_POLICY])
def test_a_research_or_memory_run_binds_the_exact_grant_of_its_body(policy):
    body = request_body(policy, room_history=dict(BINDING))
    assert room_history_binding(body) == (GRANT, PATH)
    assert room_history_binding(request_body(policy)) is None


@pytest.mark.parametrize("binding", [
    {"grant": GRANT}, {"path": PATH}, {**BINDING, "squad_id": "x"}, {**BINDING, "grant": GRANT[:-1]},
    {**BINDING, "grant": GRANT + "\n"}, {**BINDING, "grant": GRANT[:-1] + "="},
    {**BINDING, "path": PATH + "/"}, {**BINDING, "path": "/v1/instances/other/room-history"},
    {**BINDING, "path": PATH.replace("room-history", "room-memory")}, {**BINDING, "grant": 7},
    [GRANT, PATH], GRANT, None,
])
def test_any_other_shape_of_the_binding_refuses_the_run(binding):
    body = request_body(room_history=binding)
    with pytest.raises(ValueError):
        room_history_binding(body)
    with pytest.raises(ValueError):
        validate_room_request(body, authenticated=True)


def test_a_v1_run_never_binds_a_grant():
    body = request_body(PUBLIC_ROOM_POLICY, room_history=dict(BINDING))
    with pytest.raises(ValueError):
        room_history_binding(body)
    with pytest.raises(ValueError):
        validate_room_request(body, authenticated=True)


def test_scopes_bind_one_grant_and_never_swap_it(history_room):
    assert public_room_history() is None
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=(GRANT, PATH)):
        assert public_room_history() == BINDING
        assert PUBLIC_ROOM_HISTORY_TOOL in public_room_tool_names()
        assert PUBLIC_ROOM_HISTORY_TOOL in proposal_available_tools()
        assert execution_scope_error(PUBLIC_ROOM_HISTORY_TOOL) is None
        # A nested scope keeps it; the Agent's own form binds the same grant.
        with public_room_scope(True), public_room_scope(False):
            assert public_room_history() == BINDING
        with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=dict(BINDING)):
            assert public_room_history() == BINDING
        # Another grant never replaces the bound one, and an Agent without one gets none.
        for other in (OTHER, None):
            with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=other):
                assert public_room_history() is None
                assert PUBLIC_ROOM_HISTORY_TOOL not in public_room_tool_names()
                assert execution_scope_error(PUBLIC_ROOM_HISTORY_TOOL) is not None
        # The v1 room has no research tools and therefore no history.
        with public_room_scope(True, policy=PUBLIC_ROOM_POLICY):
            assert public_room_policy() == PUBLIC_ROOM_POLICY and public_room_history() is None
            assert execution_scope_error(PUBLIC_ROOM_HISTORY_TOOL) is not None
        assert public_room_history() == BINDING
    # A memory Run that narrows to the research policy keeps its grant.
    with public_room_scope(True, policy=PUBLIC_ROOM_MEMORY_POLICY, history=(GRANT, PATH)):
        with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
            assert public_room_history() == BINDING
    for policy in (PUBLIC_ROOM_POLICY, None):
        with public_room_scope(True, policy=policy, history=(GRANT, PATH)):
            assert public_room_history() is None
    with public_room_scope(False, history=(GRANT, PATH)):
        assert public_room_history() is None
    # The allowlist of a policy as such never lists the tool.
    assert PUBLIC_ROOM_HISTORY_TOOL not in public_room_tool_names(PUBLIC_ROOM_RESEARCH_POLICY)
    assert public_room_history() is None and public_room_tool_names() is None
    with pytest.raises(ValueError):
        with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=(GRANT,)):
            pass


def test_the_tool_has_no_schema_and_no_dispatch_without_a_grant(history_room):
    from model_tools import handle_function_call
    from tools.registry import registry
    # Outside a room: the room-only rule.
    assert not registry.get_definitions({PUBLIC_ROOM_HISTORY_TOOL})
    assert json.loads(handle_function_call(PUBLIC_ROOM_HISTORY_TOOL, {}))["error_type"] == \
        "public_room_only"
    # In a research room without a grant: not in the room's allowlist.
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
        assert not registry.get_definitions({PUBLIC_ROOM_HISTORY_TOOL})
        assert json.loads(handle_function_call(PUBLIC_ROOM_HISTORY_TOOL, {}))["error_type"] == \
            "public_room_isolation"
    assert history_room == []
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=(GRANT, PATH)):
        assert [tool["function"]["name"] for tool in
                registry.get_definitions({PUBLIC_ROOM_HISTORY_TOOL})] == [PUBLIC_ROOM_HISTORY_TOOL]


# --- The Agent and the Run ------------------------------------------------------------

def test_the_agent_factory_binds_a_grant_to_research_and_memory_runs_only(history_room, monkeypatch):
    adapter = _make_adapter("room-fixture-key")
    monkeypatch.setattr("gateway.run._resolve_runtime_agent_kwargs", lambda: {
        "api_key": "fixture", "base_url": "http://127.0.0.1:1/v1", "provider": "openai",
        "api_mode": "chat_completions"})
    monkeypatch.setattr("gateway.run._resolve_gateway_model", lambda: "test/model")
    monkeypatch.setattr(adapter, "_ensure_session_db", lambda: None)
    with patch("run_agent.AIAgent") as create:
        for kwargs in ({"public_room": True, "room_policy": PUBLIC_ROOM_POLICY,
                        "room_history": (GRANT, PATH)},
                       {"room_history": (GRANT, PATH)}):
            with pytest.raises(ValueError):
                adapter._create_agent(**kwargs)
        create.assert_not_called()


def test_an_agent_keeps_the_grant_of_its_run_after_ambient_context_is_lost(history_room):
    from run_agent import AIAgent
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=(GRANT, PATH)):
        agent = AIAgent(api_key="fixture-only", base_url="http://127.0.0.1:1/v1",
                        model="test/model", quiet_mode=True)
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
        plain = AIAgent(api_key="fixture-only", base_url="http://127.0.0.1:1/v1",
                        model="test/model", quiet_mode=True)
    try:
        assert agent.public_room_history == BINDING and plain.public_room_history is None
        assert public_room_history() is None
        # The Agent's own tool boundary binds its grant again, and the handler finds it.
        assert json.loads(agent._invoke_tool(PUBLIC_ROOM_HISTORY_TOOL, {}, "room")) == {
            "tool": PUBLIC_ROOM_HISTORY_TOOL}
        assert history_room == [BINDING]
        # An Agent of a Run without a grant cannot call the tool, whatever the arguments say.
        refused = json.loads(plain._invoke_tool(PUBLIC_ROOM_HISTORY_TOOL, dict(BINDING), "room"))
        assert refused["error_type"] == "public_room_isolation"
        # Nor inside another Run that holds one.
        with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY, history=(GRANT, PATH)):
            refused = json.loads(plain._invoke_tool(PUBLIC_ROOM_HISTORY_TOOL, {}, "room"))
            assert refused["error_type"] == "public_room_isolation"
        assert history_room == [BINDING]
    finally:
        agent.close()
        plain.close()


@pytest.mark.asyncio
async def test_the_room_route_binds_the_grant_of_the_body_and_refuses_a_bad_one(history_room):
    adapter = _make_adapter("room-fixture-key")
    seen = []

    def create(**kwargs):
        def run(**_inputs):
            seen.append((kwargs.get("room_history"), public_room_history(),
                         execution_scope_error(PUBLIC_ROOM_HISTORY_TOOL) is None))
            return {"final_response": "public reply"}
        return SimpleNamespace(run_conversation=run, session_prompt_tokens=0,
                               session_completion_tokens=0, session_total_tokens=0)

    with patch.object(adapter, "_create_agent", side_effect=create) as factory:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers=AUTH) as client:
            for body in (request_body(room_history=dict(BINDING)), request_body()):
                response = await client.post(ROOM_RUN_PATH, json=body)
                assert response.status == 202, await response.text()
                run = (await response.json())["run_id"]
                if run in adapter._active_run_tasks:
                    await adapter._active_run_tasks[run]
            calls = factory.call_count
            for body in (request_body(room_history={"grant": GRANT}),
                         request_body(PUBLIC_ROOM_POLICY, room_history=dict(BINDING))):
                response = await client.post(ROOM_RUN_PATH, json=body)
                assert response.status == 400
                assert (await response.json())["error"]["code"] == "invalid_room_policy"
            assert factory.call_count == calls
    assert seen == [((GRANT, PATH), BINDING, True), (None, None, False)]
