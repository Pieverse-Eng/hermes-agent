"""Room isolation is enforced at native admission and dispatch, without model calls."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.public_room import PUBLIC_ROOM_PROMPT, ROOM_RUN_PATH, SESSION_PREFIX
from tools.execution_scope import (
    PUBLIC_ROOM_POLICY, execution_scope_error, is_public_room_scope,
    proposal_only_scope, public_room_scope, proposal_available_tools,
)
from tests.gateway.test_api_server_runs import _make_adapter, _create_runs_app


def request_body():
    return {"session_id": SESSION_PREFIX + str(uuid4()), "input": "public room JSON",
            "room_policy": PUBLIC_ROOM_POLICY}


@pytest.mark.asyncio
@pytest.mark.parametrize("delta", [
    {"room_policy": "unknown"}, {"room_policy": None},
    {"session_id": "owner-private-session"}, {"session_id": SESSION_PREFIX + "not-a-uuid"},
    {"input": [{"role": "user", "content": "private transcript"}]},
    {"conversation_history": []}, {"previous_response_id": "owner-response"},
    {"interaction_context": None},
])
async def test_rejects_policy_widening_before_agent_or_history_access(delta):
    adapter = _make_adapter("room-fixture-key")
    body = {**request_body(), **delta}
    with patch.object(adapter, "_create_agent") as create, patch.object(adapter, "_ensure_session_db_async") as history:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers={"Authorization": "Bearer room-fixture-key"}) as client:
            response = await client.post(ROOM_RUN_PATH, json=body)
            assert response.status == 400
        create.assert_not_called()
        history.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", [SESSION_PREFIX, "agent-chat-pawchat-"])
async def test_isolated_namespace_cannot_fall_back_to_private_policy(prefix):
    adapter = _make_adapter("room-fixture-key")
    body = request_body()
    body["session_id"] = prefix + str(uuid4())
    del body["room_policy"]
    async with TestClient(TestServer(_create_runs_app(adapter)), headers={"Authorization": "Bearer room-fixture-key"}) as client:
        assert (await client.post("/v1/runs", json=body)).status == 400


@pytest.mark.asyncio
async def test_dedicated_route_never_accepts_an_ordinary_private_request():
    adapter = _make_adapter("room-fixture-key")
    with patch.object(adapter, "_create_agent") as create:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers={"Authorization": "Bearer room-fixture-key"}) as client:
            response = await client.post(ROOM_RUN_PATH, json={"input": "ordinary private turn"})
            assert response.status == 400
        create.assert_not_called()


@pytest.mark.asyncio
async def test_room_admission_requires_the_native_bearer():
    adapter = _make_adapter("room-fixture-key")
    with patch.object(adapter, "_create_agent") as create:
        async with TestClient(TestServer(_create_runs_app(adapter))) as client:
            assert (await client.post(ROOM_RUN_PATH, json=request_body())).status == 401
        create.assert_not_called()


@pytest.mark.asyncio
async def test_room_scope_survives_real_run_thread_and_private_concurrency():
    adapter = _make_adapter("room-fixture-key")
    seen = []

    def create(**kwargs):
        room = kwargs["public_room"]

        def run(**inputs):
            seen.append((room, is_public_room_scope(), inputs["conversation_history"],
                         kwargs["ephemeral_system_prompt"]))
            if room:
                assert execution_scope_error("wallet_transfer") is not None
                assert execution_scope_error("session_search") is not None
            else:
                assert execution_scope_error("wallet_transfer") is None
            return {"final_response": "public reply"}
        return SimpleNamespace(run_conversation=run, session_prompt_tokens=0,
                               session_completion_tokens=0, session_total_tokens=0)

    body = {**request_body(), "instructions": "OWNER_PRIVATE_PROMPT_SENTINEL"}
    with patch.object(adapter, "_create_agent", side_effect=create), \
         patch.object(adapter, "_configured_system_prompt", return_value="PRIVATE_CONFIG_SENTINEL"), \
         patch.object(adapter, "_ensure_session_db_async") as history:
        async with TestClient(TestServer(_create_runs_app(adapter)), headers={"Authorization": "Bearer room-fixture-key"}) as client:
            responses = await asyncio.gather(
                client.post(ROOM_RUN_PATH, json=body, headers={"Idempotency-Key": "room-one"}),
                client.post("/v1/runs", json={"input": "ordinary private turn"}),
            )
            for response in responses:
                assert response.status == 202
            run_ids = [(await response.json())["run_id"] for response in responses]
            await asyncio.gather(*(adapter._active_run_tasks[run] for run in run_ids if run in adapter._active_run_tasks))
            replay = await client.post(ROOM_RUN_PATH, json=body, headers={"Idempotency-Key": "room-one"})
            assert (await replay.json())["run_id"] == run_ids[0]
            changed = await client.post(ROOM_RUN_PATH, json={**body, "room_policy": "unknown"},
                                        headers={"Idempotency-Key": "room-one"})
            assert changed.status == 400
        history.assert_not_called()
    assert sorted((room, scoped) for room, scoped, _, _ in seen) == [(False, False), (True, True)]
    assert next(item for item in seen if item[0])[2:] == ([], PUBLIC_ROOM_PROMPT)


@pytest.mark.parametrize("tool", ["memory", "session_search", "terminal", "tool_call", "delegate_task",
                                  "wallet_transfer", "paper_execute", "account_balance", "unknown_plugin"])
def test_real_agent_local_dispatch_refuses_before_any_handler_or_middleware(tool):
    from agent.tool_executor import _run_agent_tool_execution_middleware
    execute = Mock(side_effect=AssertionError("private handler entered"))
    with public_room_scope(True), proposal_only_scope(False):
        result = _run_agent_tool_execution_middleware(
            SimpleNamespace(), function_name=tool, function_args={}, effective_task_id="room",
            tool_call_id="forged", execute=execute)
    assert result.blocked and not result.dispatched
    assert json.loads(result.result)["error_type"] == "public_room_isolation"
    execute.assert_not_called()


def test_nested_scopes_cannot_widen_room_tools_and_context_restores():
    with public_room_scope(True), public_room_scope(False), proposal_only_scope(False):
        assert proposal_available_tools() == {"discover_markets"}
        assert execution_scope_error("discover_markets") is None
        assert execution_scope_error("memory") is not None
    assert not is_public_room_scope()
    assert execution_scope_error("memory") is None


def test_room_agent_keeps_local_tool_guard_after_ambient_context_is_lost():
    from agent.tool_executor import _run_agent_tool_execution_middleware
    handler = Mock()
    result = _run_agent_tool_execution_middleware(
        SimpleNamespace(public_room_policy=True), function_name="memory", function_args={},
        effective_task_id="room", tool_call_id="forged", execute=handler)
    assert result.blocked and not result.dispatched
    handler.assert_not_called()


@pytest.mark.parametrize("tool", ["memory", "session_search", "delegate_task"])
def test_direct_invocation_cannot_bypass_room_policy_or_enter_private_sources(tool):
    from agent.agent_runtime_helpers import invoke_tool
    private = Mock(side_effect=AssertionError("private source entered"))
    agent = SimpleNamespace(public_room_policy=True, _get_session_db_for_recall=private,
                            _dispatch_delegate_task=private)
    result = invoke_tool(agent, tool, {}, "room", skip_tool_execution_middleware=True)
    assert json.loads(result)["error_type"] == "public_room_isolation"
    private.assert_not_called()


def test_owner_prompt_sources_and_hooks_never_enter_a_room(monkeypatch):
    from agent.system_prompt import build_system_prompt_parts
    from hermes_cli.plugins import PluginContext, PluginManager
    private = Mock(return_value="PRIVATE_HOOK_SENTINEL")
    manager = PluginManager()
    ctx = PluginContext(SimpleNamespace(name="private-fixture"), manager)
    ctx.register_hook("pre_llm_call", private)
    ctx.register_middleware("llm_request", private)
    def private_execution(request, next_call, **kwargs):
        private()
        return next_call({**request, "private": "PRIVATE_MIDDLEWARE_SENTINEL"})
    ctx.register_middleware("llm_execution", private_execution)
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    with public_room_scope(True):
        assert manager.invoke_hook("pre_llm_call") == []
        assert manager.invoke_middleware("llm_request") == []
        from hermes_cli.middleware import run_llm_execution_middleware
        provider = Mock(side_effect=lambda request: request)
        assert run_llm_execution_middleware({"messages": []}, provider) == {"messages": []}
        provider.assert_called_once_with({"messages": []})
        parts = build_system_prompt_parts(SimpleNamespace(public_room_policy=True),
                                          system_message="PRIVATE_SYSTEM_MESSAGE")
    assert parts == {"stable": PUBLIC_ROOM_PROMPT, "context": "", "volatile": ""}
    private.assert_not_called()
    assert manager.invoke_hook("pre_llm_call") == ["PRIVATE_HOOK_SENTINEL"]


def test_actual_agent_constructor_keeps_private_stores_and_context_providers_unloaded(tmp_path, monkeypatch):
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
    monkeypatch.setattr(registry, "_tools", dict(registry._tools))
    market = Mock(return_value=json.dumps({"markets": ["PUBLIC_BTC"]}))
    transfer = Mock(return_value=json.dumps({"transferred": True}))
    registry.register(name="discover_markets", toolset="pieverse-market-research",
                      schema={"name": "discover_markets", "description": "Read public markets",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=market)
    registry.register(name="wallet_transfer", toolset="fixture-wallet",
                      schema={"name": "wallet_transfer", "description": "Fixture transfer",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=transfer)
    with patch("tools.memory_tool.MemoryStore.load_from_disk") as memory, \
         patch("plugins.memory.load_memory_provider") as provider, \
         patch("plugins.context_engine.load_context_engine") as context:
        with public_room_scope(True):
            agent = AIAgent(api_key="fixture-only", base_url="http://127.0.0.1:1/v1",
                            model="test/model", quiet_mode=True,
                            enabled_toolsets=["memory", "session_search", "terminal"],
                            skip_memory=False, skip_context_files=False, load_soul_identity=True)
            try:
                assert agent._memory_store is None and agent._memory_manager is None
                assert agent.skip_context_files and not agent.load_soul_identity
                assert agent._skip_mcp_refresh
                prompt = build_system_prompt(agent, system_message="PRIVATE_CALLER_SENTINEL")
                assert prompt == PUBLIC_ROOM_PROMPT
                tools = get_tool_definitions(enabled_toolsets=agent.enabled_toolsets,
                                             quiet_mode=True, skip_tool_search_assembly=True)
                assert {tool["function"]["name"] for tool in tools} == {"discover_markets"}
                assert json.loads(agent._invoke_tool("discover_markets", {}, "room"))["markets"] == ["PUBLIC_BTC"]
                assert json.loads(handle_function_call("wallet_transfer", {}))["error_type"] == "public_room_isolation"
                transfer.assert_not_called()
            finally:
                agent.close()
        memory.assert_not_called()
        provider.assert_not_called()
        context.assert_not_called()
    market.assert_called_once()
    assert json.loads(handle_function_call("wallet_transfer", {}))["transferred"]
    transfer.assert_called_once()
