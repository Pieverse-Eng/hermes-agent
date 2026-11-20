"""Room research policy v2 widens public reads and keeps every v1 exclusion.

Mixed versions: a deployed platform validates ``features.squad_room_isolation``
with a strict schema, so that declaration stays byte-identical and v2 is
declared under its own feature key. Tests stub inference; no paid model call.
"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.public_room import (
    PUBLIC_ROOM_PROMPT, PUBLIC_ROOM_RESEARCH_PROMPT, ROOM_RESEARCH_FEATURE, ROOM_RUN_PATH,
    SESSION_PREFIX, room_capability, room_research_capability,
)
from tools.execution_scope import (
    PUBLIC_ROOM_POLICY, PUBLIC_ROOM_RESEARCH_POLICY, PUBLIC_ROOM_RESEARCH_TOOL_NAMES,
    PUBLIC_ROOM_TOOLSET, execution_scope_error, is_public_room_scope, proposal_available_tools,
    proposal_only_scope, public_room_policy, public_room_scope,
)
from tests.gateway.test_api_server_runs import _make_adapter, _create_runs_app

AUTH = {"Authorization": "Bearer room-fixture-key"}
# The exact bytes a deployed platform's strict schema accepts today.
V1_DECLARATION = ('{"policy":"squad-public-market-v1","run_path":"/v1/room-runs","memory":false,'
                  '"context_files":false,"tools":["discover_markets"]}')
V2_DECLARATION = {
    "policy": "squad-public-research-v2", "run_path": "/v1/room-runs",
    "memory": False, "context_files": False, "skills": False, "mcp": False,
    "tools": ["compare_trade_routes", "discover_markets", "market_candles", "market_snapshot",
              "onchain_token", "plan_spot_purchase", "search_news", "search_web", "search_x"],
    "search_tools": ["search_web", "search_x"],
    "max_tool_calls": 12, "max_search_calls": 4,
}
FORBIDDEN = [
    "memory", "session_search", "todo", "skills_list", "skill_view", "skill_manage",
    "terminal", "process", "execute_code", "read_file", "write_file", "patch", "search_files",
    "browser_navigate", "web_search", "web_extract", "x_search", "delegate_task", "cronjob",
    "send_message", "clarify", "mcp_fixture_read", "wallet_transfer", "paper_execute",
    "account_balance", "terminal_read", "terminal_prepare_card", "unknown_plugin",
]


def request_body(policy=PUBLIC_ROOM_RESEARCH_POLICY):
    return {"session_id": SESSION_PREFIX + str(uuid4()), "input": "public room JSON",
            "room_policy": policy}


def compact(value):
    return json.dumps(value, separators=(",", ":"))


@pytest.fixture
def research_tools(monkeypatch):
    """The platform plugin's fixed tools, registered in its own toolset."""
    from tools.registry import registry
    monkeypatch.setattr(registry, "_tools", dict(registry._tools))
    handlers = {}
    for name in sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES):
        handlers[name] = Mock(return_value=json.dumps({"tool": name}))
        registry.register(name=name, toolset=PUBLIC_ROOM_TOOLSET,
                          schema={"name": name, "description": "Public read",
                                  "parameters": {"type": "object", "properties": {}}},
                          handler=handlers[name])
    return handlers


def capabilities_app(adapter):
    app = _create_runs_app(adapter)
    app.router.add_get("/v1/capabilities", adapter._handle_capabilities)
    return app


# --- Invariant 1: mixed versions -------------------------------------------------

def test_v1_declaration_stays_byte_identical_and_v2_is_exact(research_tools):
    assert compact(room_capability()) == V1_DECLARATION
    assert room_research_capability() == V2_DECLARATION
    assert ROOM_RESEARCH_FEATURE == "squad_room_research_v2"
    assert V2_DECLARATION["tools"] == sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES)
    assert PUBLIC_ROOM_POLICY == "squad-public-market-v1"


@pytest.mark.asyncio
async def test_capabilities_keep_v1_bytes_and_declare_v2_under_a_new_key(research_tools, monkeypatch):
    monkeypatch.setattr("gateway.run._load_gateway_config",
                        lambda: {"model": {"provider": "openai", "api_mode": "chat_completions"}})
    adapter = _make_adapter("room-fixture-key")
    async with TestClient(TestServer(capabilities_app(adapter)), headers=AUTH) as client:
        features = (await (await client.get("/v1/capabilities")).json())["features"]
    assert compact(features["squad_room_isolation"]) == V1_DECLARATION
    assert features[ROOM_RESEARCH_FEATURE] == V2_DECLARATION


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["search_news", "market_snapshot", "discover_markets"])
async def test_v2_is_neither_declared_nor_admitted_without_every_platform_tool(
        research_tools, missing, monkeypatch):
    from tools.registry import registry
    monkeypatch.setattr("gateway.run._load_gateway_config",
                        lambda: {"model": {"provider": "openai", "api_mode": "chat_completions"}})
    del registry._tools[missing]
    adapter = _make_adapter("room-fixture-key")
    with patch.object(adapter, "_create_agent") as create:
        async with TestClient(TestServer(capabilities_app(adapter)), headers=AUTH) as client:
            features = (await (await client.get("/v1/capabilities")).json())["features"]
            assert features[ROOM_RESEARCH_FEATURE] is None
            assert compact(features["squad_room_isolation"]) == V1_DECLARATION
            assert (await client.post(ROOM_RUN_PATH, json=request_body())).status == 400
        create.assert_not_called()


@pytest.mark.asyncio
async def test_a_tool_of_another_toolset_never_qualifies_v2(research_tools, monkeypatch):
    from tools.registry import registry
    monkeypatch.setattr("gateway.run._load_gateway_config",
                        lambda: {"model": {"provider": "openai", "api_mode": "chat_completions"}})
    del registry._tools["search_web"]
    registry.register(name="search_web", toolset="owner-plugin",
                      schema={"name": "search_web", "description": "Owner tool",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=Mock(side_effect=AssertionError("owner handler entered")))
    adapter = _make_adapter("room-fixture-key")
    async with TestClient(TestServer(capabilities_app(adapter)), headers=AUTH) as client:
        features = (await (await client.get("/v1/capabilities")).json())["features"]
        assert features[ROOM_RESEARCH_FEATURE] is None
        assert (await client.post(ROOM_RUN_PATH, json=request_body())).status == 400
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
        assert json.loads(execution_scope_error("search_web"))["error_type"] == "public_room_isolation"


@pytest.mark.asyncio
async def test_room_route_admits_both_policies_each_with_its_own_tools_and_prompt(research_tools):
    adapter = _make_adapter("room-fixture-key")
    seen = {}

    def create(**kwargs):
        policy = kwargs["room_policy"]

        def run(**inputs):
            seen[policy] = (kwargs["public_room"], is_public_room_scope(), public_room_policy(),
                            set(proposal_available_tools()), inputs["conversation_history"],
                            execution_scope_error("market_snapshot") is None,
                            execution_scope_error("memory") is None)
            return {"final_response": "public reply"}
        return SimpleNamespace(run_conversation=run, session_prompt_tokens=0,
                               session_completion_tokens=0, session_total_tokens=0)

    with patch.object(adapter, "_create_agent", side_effect=create), \
         patch.object(adapter, "_ensure_session_db_async") as history:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers=AUTH) as client:
            responses = await asyncio.gather(
                client.post(ROOM_RUN_PATH, json=request_body(PUBLIC_ROOM_POLICY)),
                client.post(ROOM_RUN_PATH, json=request_body(PUBLIC_ROOM_RESEARCH_POLICY)),
            )
            for response in responses:
                assert response.status == 202
            run_ids = [(await response.json())["run_id"] for response in responses]
            await asyncio.gather(*(adapter._active_run_tasks[run] for run in run_ids
                                   if run in adapter._active_run_tasks))
        history.assert_not_called()
    assert seen[PUBLIC_ROOM_POLICY] == (True, True, PUBLIC_ROOM_POLICY, {"discover_markets"},
                                        [], False, False)
    assert seen[PUBLIC_ROOM_RESEARCH_POLICY] == (
        True, True, PUBLIC_ROOM_RESEARCH_POLICY, set(PUBLIC_ROOM_RESEARCH_TOOL_NAMES), [], True, False)


def test_a_v1_agent_still_exposes_and_dispatches_only_discover_markets(research_tools):
    from run_agent import AIAgent
    from model_tools import get_tool_definitions, handle_function_call
    with public_room_scope(True, policy=PUBLIC_ROOM_POLICY):
        agent = AIAgent(api_key="fixture-only", base_url="http://127.0.0.1:1/v1",
                        model="test/model", quiet_mode=True)
        try:
            assert agent.public_room_policy is True
            assert agent.public_room_policy_id == PUBLIC_ROOM_POLICY
            tools = get_tool_definitions(enabled_toolsets=agent.enabled_toolsets, quiet_mode=True,
                                         skip_tool_search_assembly=True)
            assert {tool["function"]["name"] for tool in tools} == {"discover_markets"}
            for name in sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES - {"discover_markets"}):
                assert json.loads(handle_function_call(name, {}))["error_type"] == "public_room_isolation"
                assert json.loads(agent._invoke_tool(name, {}, "room"))["error_type"] == "public_room_isolation"
                research_tools[name].assert_not_called()
            assert json.loads(agent._invoke_tool("discover_markets", {}, "room")) == {"tool": "discover_markets"}
        finally:
            agent.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["squad-public-research-v3", "squad-public-market-v0", "", 2, None,
                                    ["squad-public-research-v2"]])
async def test_unknown_policy_is_refused_before_agent_or_history_access(research_tools, policy):
    adapter = _make_adapter("room-fixture-key")
    with patch.object(adapter, "_create_agent") as create, \
         patch.object(adapter, "_ensure_session_db_async") as history:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers=AUTH) as client:
            response = await client.post(ROOM_RUN_PATH, json=request_body(policy))
            assert response.status == 400
        create.assert_not_called()
        history.assert_not_called()


# --- Invariant 3: v2 keeps every v1 exclusion ------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("delta", [
    {"session_id": "owner-private-session"}, {"session_id": SESSION_PREFIX + "not-a-uuid"},
    {"session_id": "agent-chat-pawchat-" + str(uuid4())},
    {"input": [{"role": "user", "content": "private transcript"}]},
    {"conversation_history": []}, {"previous_response_id": "owner-response"},
    {"interaction_context": None},
    {"interaction_context": {"version": 2, "execution_policy": "pawpilot", "host_tools": ["paper_read"]}},
])
async def test_v2_rejects_history_private_sessions_and_financial_contexts(research_tools, delta):
    adapter = _make_adapter("room-fixture-key")
    body = {**request_body(), **delta}
    with patch.object(adapter, "_create_agent") as create, \
         patch.object(adapter, "_ensure_session_db_async") as history:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers=AUTH) as client:
            assert (await client.post(ROOM_RUN_PATH, json=body)).status == 400
        create.assert_not_called()
        history.assert_not_called()


@pytest.mark.asyncio
async def test_v2_requires_the_native_bearer_and_never_runs_on_the_private_route(research_tools):
    adapter = _make_adapter("room-fixture-key")
    with patch.object(adapter, "_create_agent") as create:
        async with TestClient(TestServer(_create_runs_app(adapter))) as client:
            assert (await client.post(ROOM_RUN_PATH, json=request_body())).status == 401
        async with TestClient(TestServer(_create_runs_app(adapter)), headers=AUTH) as client:
            body = request_body()
            del body["room_policy"]
            assert (await client.post("/v1/runs", json=body)).status == 400
        create.assert_not_called()


@pytest.mark.parametrize("tool", FORBIDDEN)
def test_v2_dispatch_refuses_private_tools_before_any_handler_or_middleware(research_tools, tool):
    from agent.tool_executor import _run_agent_tool_execution_middleware
    execute = Mock(side_effect=AssertionError("private handler entered"))
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY), proposal_only_scope(False):
        assert tool not in proposal_available_tools()
        result = _run_agent_tool_execution_middleware(
            SimpleNamespace(), function_name=tool, function_args={}, effective_task_id="room",
            tool_call_id="forged", execute=execute)
    assert result.blocked and not result.dispatched
    assert json.loads(result.result)["error_type"] == "public_room_isolation"
    execute.assert_not_called()


@pytest.mark.parametrize("tool", ["memory", "session_search", "delegate_task"])
def test_v2_direct_invocation_cannot_enter_private_sources(tool):
    from agent.agent_runtime_helpers import invoke_tool
    private = Mock(side_effect=AssertionError("private source entered"))
    agent = SimpleNamespace(public_room_policy=True, public_room_policy_id=PUBLIC_ROOM_RESEARCH_POLICY,
                            _get_session_db_for_recall=private, _dispatch_delegate_task=private)
    result = invoke_tool(agent, tool, {}, "room", skip_tool_execution_middleware=True)
    assert json.loads(result)["error_type"] == "public_room_isolation"
    private.assert_not_called()


def test_nested_scopes_never_widen_v1_to_v2_and_the_context_restores():
    with public_room_scope(True, policy=PUBLIC_ROOM_POLICY):
        with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY), public_room_scope(False):
            assert public_room_policy() == PUBLIC_ROOM_POLICY
            assert proposal_available_tools() == {"discover_markets"}
            assert execution_scope_error("market_snapshot") is not None
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
        with public_room_scope(True), public_room_scope(False), proposal_only_scope(False):
            assert public_room_policy() == PUBLIC_ROOM_RESEARCH_POLICY
            assert proposal_available_tools() == PUBLIC_ROOM_RESEARCH_TOOL_NAMES
        with public_room_scope(True, policy=PUBLIC_ROOM_POLICY):
            assert proposal_available_tools() == {"discover_markets"}
        assert public_room_policy() == PUBLIC_ROOM_RESEARCH_POLICY
    with public_room_scope(True):
        assert public_room_policy() == PUBLIC_ROOM_POLICY
    assert not is_public_room_scope() and public_room_policy() is None
    assert execution_scope_error("memory") is None
    with pytest.raises(ValueError):
        with public_room_scope(True, policy="squad-public-research-v3"):
            pass


def test_a_room_agent_keeps_its_own_policy_after_ambient_context_is_lost(research_tools):
    from agent.tool_executor import _run_agent_tool_execution_middleware
    handler = Mock(return_value="{}")

    def call(agent, name):
        return _run_agent_tool_execution_middleware(
            agent, function_name=name, function_args={}, effective_task_id="room",
            tool_call_id="call", execute=handler)

    research = SimpleNamespace(public_room_policy=True,
                               public_room_policy_id=PUBLIC_ROOM_RESEARCH_POLICY)
    assert call(research, "memory").blocked
    assert not call(research, "market_snapshot").blocked
    # An Agent marked as a room without a policy id gets the narrowest policy.
    legacy = SimpleNamespace(public_room_policy=True)
    assert call(legacy, "market_snapshot").blocked
    assert not call(legacy, "discover_markets").blocked
    assert handler.call_count == 2


def test_owner_hooks_middleware_and_prompt_sources_never_enter_a_v2_room(monkeypatch):
    from agent.system_prompt import build_system_prompt_parts
    from hermes_cli.plugins import PluginContext, PluginManager
    private = Mock(return_value="PRIVATE_HOOK_SENTINEL")
    manager = PluginManager()
    ctx = PluginContext(SimpleNamespace(name="private-fixture"), manager)
    ctx.register_hook("pre_llm_call", private)
    ctx.register_hook("pre_tool_call", private)
    ctx.register_middleware("llm_request", private)
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
        assert manager.invoke_hook("pre_llm_call") == []
        assert manager.invoke_hook("pre_tool_call") == []
        assert manager.invoke_middleware("llm_request") == []
        agent = SimpleNamespace(public_room_policy=True,
                                public_room_policy_id=PUBLIC_ROOM_RESEARCH_POLICY)
        parts = build_system_prompt_parts(agent, system_message="PRIVATE_SYSTEM_MESSAGE")
    assert parts == {"stable": PUBLIC_ROOM_RESEARCH_PROMPT, "context": "", "volatile": ""}
    assert build_system_prompt_parts(SimpleNamespace(public_room_policy=True),
                                     system_message="PRIVATE") == {
        "stable": PUBLIC_ROOM_PROMPT, "context": "", "volatile": ""}
    private.assert_not_called()


def test_actual_v2_agent_loads_no_private_store_context_skill_or_mcp(research_tools, monkeypatch):
    import os
    from pathlib import Path
    from run_agent import AIAgent
    from model_tools import handle_function_call, get_tool_definitions
    from tools.registry import registry
    from agent.system_prompt import build_system_prompt

    home = Path(os.environ["HERMES_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        "memory:\n  memory_enabled: true\n  user_profile_enabled: true\n  provider: honcho\n"
        "context:\n  engine: private-fixture\n", encoding="utf-8")
    for name in ("MEMORY.md", "USER.md", "SOUL.md"):
        (home / name).write_text("PRIVATE_FILE_SENTINEL", encoding="utf-8")
    skill = home / "skills" / "private-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: private-skill\ndescription: PRIVATE_SKILL_SENTINEL\n---\nPRIVATE_SKILL_BODY\n",
        encoding="utf-8")
    transfer = Mock(return_value=json.dumps({"transferred": True}))
    registry.register(name="wallet_transfer", toolset="fixture-wallet",
                      schema={"name": "wallet_transfer", "description": "Fixture transfer",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=transfer)
    with patch("tools.memory_tool.MemoryStore.load_from_disk") as memory, \
         patch("plugins.memory.load_memory_provider") as provider, \
         patch("plugins.context_engine.load_context_engine") as context:
        with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY):
            agent = AIAgent(api_key="fixture-only", base_url="http://127.0.0.1:1/v1",
                            model="test/model", quiet_mode=True,
                            enabled_toolsets=["memory", "session_search", "terminal", "skills",
                                              "web", "cronjob", "file", "browser"],
                            skip_memory=False, skip_context_files=False, load_soul_identity=True,
                            fallback_model={"provider": "copilot-acp", "model": "external-fixture"})
            try:
                assert agent.public_room_policy is True
                assert agent.public_room_policy_id == PUBLIC_ROOM_RESEARCH_POLICY
                assert agent._memory_store is None and agent._memory_manager is None
                assert agent.skip_context_files and not agent.load_soul_identity
                assert agent._skip_mcp_refresh
                assert agent._fallback_chain == []
                assert agent.enabled_toolsets == [PUBLIC_ROOM_TOOLSET]
                prompt = build_system_prompt(agent, system_message="PRIVATE_CALLER_SENTINEL")
                assert prompt == PUBLIC_ROOM_RESEARCH_PROMPT
                assert "PRIVATE" not in prompt
                tools = get_tool_definitions(enabled_toolsets=agent.enabled_toolsets,
                                             quiet_mode=True, skip_tool_search_assembly=True)
                assert {tool["function"]["name"] for tool in tools} == PUBLIC_ROOM_RESEARCH_TOOL_NAMES
                for name in sorted(PUBLIC_ROOM_RESEARCH_TOOL_NAMES):
                    assert json.loads(agent._invoke_tool(name, {}, "room")) == {"tool": name}
                for name in ("wallet_transfer", "memory", "terminal", "skill_view", "web_search",
                             "x_search", "cronjob", "read_file"):
                    assert json.loads(handle_function_call(name, {}))["error_type"] == "public_room_isolation"
                transfer.assert_not_called()
            finally:
                agent.close()
        memory.assert_not_called()
        provider.assert_not_called()
        context.assert_not_called()
    for handler in research_tools.values():
        handler.assert_called_once()
    assert json.loads(handle_function_call("wallet_transfer", {}))["transferred"]


@pytest.mark.parametrize("mode,provider,base", [
    ("codex_app_server", "openai", "http://127.0.0.1:1/v1"),
    ("chat_completions", "copilot-acp", "acp://copilot"),
])
def test_v2_refuses_external_runtimes_like_v1(mode, provider, base):
    from run_agent import AIAgent
    with public_room_scope(True, policy=PUBLIC_ROOM_RESEARCH_POLICY), \
         patch.object(AIAgent, "_get_transport") as transport, patch("subprocess.Popen") as process:
        with pytest.raises(ValueError, match="supported Hermes tool loop"):
            AIAgent(api_key="fixture", model="test/model", base_url=base,
                    provider=provider, api_mode=mode, quiet_mode=True)
        transport.assert_not_called()
        process.assert_not_called()
