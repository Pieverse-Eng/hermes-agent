"""Native HTTP host exchange and restricted tool schemas, without model I/O."""
import asyncio
import json
from unittest.mock import patch

import pytest
from aiohttp.test_utils import TestClient, TestServer
from tools.registry import registry
from tests.gateway.test_api_server_interactive_messages import _interactive_app, context, settle
from tests.gateway.test_api_server_runs import _make_adapter
from hermes_cli.tools_config import _get_platform_tools as native_platform_tools


@pytest.fixture
def host_plugin(monkeypatch):
    from tools.registry import ToolRegistry
    isolated = ToolRegistry()
    isolated.register(name="test_host_read", toolset="api_host_tools",
        schema={"name": "test_host_read", "parameters": {"type": "object", "properties": {}}},
        handler=lambda *a, **kw: pytest.fail("Native fallback must never execute"))
    monkeypatch.setitem(registry._tools, "test_host_read", isolated._tools["test_host_read"])
    monkeypatch.setattr("hermes_cli.tools_config._get_platform_tools", lambda *a: ["api_host_tools", "skills"])
    return "test_host_read"


class HostAgent:
    session_prompt_tokens = session_completion_tokens = session_total_tokens = 0
    valid_tool_names = {"test_host_read", "skills_list", "skill_view"}

    def __init__(self, arguments=None):
        self.arguments = arguments or {}

    def run_conversation(self, **kwargs):
        from model_tools import handle_function_call
        self.result = json.loads(handle_function_call("test_host_read", self.arguments))
        return {"final_response": "done"}


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", [{}, {"mode": "live", "execution_policy": "proposal_only"}])
async def test_authenticated_native_result_resolves_one_original_run(host_plugin, policy):
    adapter, agent = _make_adapter("test-key"), HostAgent()
    headers = {"Authorization": "Bearer test-key"}
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", headers=headers, json={
                "input": "Read", "interaction_context": {**context(), **policy, "host_tools": [host_plugin]}})
            assert response.status == 202, await response.text()
            run_id = (await response.json())["run_id"]
            stream = await client.get(f"/v1/runs/{run_id}/events", headers=headers)
            while True:
                line = await asyncio.wait_for(stream.content.readline(), 5)
                if line.startswith(b"data:"):
                    event = json.loads(line[5:])
                    if event.get("event") == "host_tool.request":
                        break
            route = f"/v1/runs/{run_id}/host-tools/{event['callId']}/result"
            reply = {"requestHash": event["requestHash"], "result": {"status": "ready", "data": {"balance": "100"}}}
            assert (await client.post(route, json=reply)).status == 401
            assert (await client.post(route, headers=headers, json={**reply, "requestHash": "wrong"})).status == 409
            assert (await client.post(route.replace(run_id, "other-run"), headers=headers, json=reply)).status == 404
            assert (await client.post(route, headers=headers, json=reply)).status == 200
            await settle(adapter, run_id)
            assert adapter._create_agent.call_args.kwargs["proposal_only"] is True
            assert agent.result["data"]["balance"] == "100"
            assert agent.result["callId"] == event["callId"]
            stream.release()


@pytest.mark.asyncio
async def test_live_host_manifest_requires_explicit_proposal_policy(host_plugin):
    adapter = _make_adapter("test-key")
    async with TestClient(TestServer(_interactive_app(adapter))) as client:
        response = await client.post("/v1/runs", headers={"Authorization": "Bearer test-key"}, json={
            "input": "Read", "interaction_context": {**context(), "mode": "live", "host_tools": [host_plugin]}})
        assert response.status == 400
        assert not adapter._active_run_tasks


def test_live_proposal_scope_blocks_native_execution_and_preserves_metadata(host_plugin):
    from gateway.interactive_messages import current_message_scope, send_current_message
    from tools.execution_scope import execution_scope_error
    delivered = []
    metadata = {"coachCard": {"version": 1, "kind": "paper_practice_invite", "title": "Practise BTC"}}
    with current_message_scope(lambda *args: delivered.append(args), {
        **context(), "mode": "live", "execution_policy": "proposal_only", "host_tools": [host_plugin]
    }):
        assert json.loads(execution_scope_error("terminal"))["error_type"] == "proposal_only"
        assert execution_scope_error(host_plugin) is None
        assert send_current_message("Practise first", metadata=metadata)["metadata"] == metadata
    assert delivered[0][3] == metadata
    assert execution_scope_error("terminal") is None


@pytest.mark.asyncio
async def test_host_runs_require_configured_auth_and_registered_owner_tool(host_plugin):
    for key, name in [("", host_plugin), ("test-key", "terminal")]:
        adapter = _make_adapter(key)
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", headers={"Authorization": "Bearer test-key"},
                json={"input": "Read", "interaction_context": {**context(), "host_tools": [name]}})
            assert response.status == 400
            assert not adapter._active_run_tasks


def test_scoped_schema_cache_cannot_restore_broad_tools(host_plugin):
    from model_tools import get_tool_definitions
    from tools.execution_scope import proposal_only_scope
    with proposal_only_scope(True, host_tools=[host_plugin], available_tools=[host_plugin, "skills_list"]):
        first = get_tool_definitions(enabled_toolsets=["api_host_tools", "skills"], quiet_mode=True)
    with proposal_only_scope(True, available_tools=["skill_view"]):
        second = get_tool_definitions(enabled_toolsets=["api_host_tools", "skills"], quiet_mode=True)
    assert {t["function"]["name"] for t in first} == {host_plugin, "skills_list"}
    assert {t["function"]["name"] for t in second} == {"skill_view"}

@pytest.mark.asyncio
@pytest.mark.parametrize("platform_run_id", [None, "platform-original-run"])
async def test_stop_releases_host_wait_without_native_or_channel_fallback(host_plugin, platform_run_id):
    adapter, agent = _make_adapter("test-key"), HostAgent({"runId": "model-forged-run"})
    headers = {"Authorization": "Bearer test-key"}
    interaction_context = {**context(), "host_tools": [host_plugin]}
    if platform_run_id is not None:
        interaction_context["context_id"] = platform_run_id
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", headers=headers, json={"input": "Read",
                "interaction_context": interaction_context})
            assert response.status == 202, await response.text()
            run_id = (await response.json())["run_id"]
            stream = await client.get(f"/v1/runs/{run_id}/events", headers=headers)
            while True:
                line = await asyncio.wait_for(stream.content.readline(), 5)
                if line.startswith(b"data:"):
                    event = json.loads(line[5:])
                    if event.get("event") == "host_tool.request":
                        break
            assert event["run_id"] == run_id
            task = adapter._active_run_tasks[run_id]
            assert (await client.post(f"/v1/runs/{run_id}/stop", headers=headers)).status == 200
            await asyncio.wait_for(task, 2)
            expected = {"status": "error", "error": {"code": "HOST_CALL_CANCELLED"},
                        "callId": event["callId"]}
            if platform_run_id is not None:
                assert platform_run_id != run_id
                expected["runId"] = platform_run_id
            assert agent.result == expected
            assert run_id not in adapter._run_host_tools
            stream.release()


@pytest.mark.parametrize("configured", ["api_host_tools", "all", "*"])
def test_unbound_api_turns_do_not_discover_configured_host_proxies(host_plugin, configured, monkeypatch):
    from unittest.mock import MagicMock
    from model_tools import get_tool_definitions
    adapter = _make_adapter("test-key")
    monkeypatch.setattr("hermes_cli.tools_config._get_platform_tools", lambda *a: [configured, "api_host_tools", "skills"])
    def construct(**kwargs):
        agent = MagicMock()
        agent.tools = get_tool_definitions(enabled_toolsets=kwargs["enabled_toolsets"],
            quiet_mode=True, skip_tool_search_assembly=True)
        return agent
    with patch("gateway.run._resolve_runtime_agent_kwargs", return_value={"api_key":"test-key",
        "base_url":None, "provider":None, "api_mode":None, "command":None, "args":[]}), \
        patch("gateway.run._resolve_gateway_model", return_value="test/model"), \
        patch("gateway.run._load_gateway_config", return_value={}), \
        patch("run_agent.AIAgent", side_effect=construct):
        normal = adapter._create_agent()
        interactive = adapter._create_agent(interactive_messages=True)
        bound = adapter._create_agent(interactive_messages=True, proposal_only=True,
            host_tool_names=[host_plugin])
    for agent in (normal, interactive):
        assert host_plugin not in {tool["function"]["name"] for tool in agent.tools}
    assert host_plugin in bound.valid_tool_names


def test_native_telegram_plugin_discovery_does_not_advertise_unbound_host_proxies(host_plugin, monkeypatch):
    from model_tools import get_tool_definitions
    monkeypatch.setattr("hermes_cli.tools_config._get_plugin_toolset_keys", lambda: {"api_host_tools"})
    configured = native_platform_tools({}, "telegram")
    # Exercise normal plugin auto-discovery rather than an API constructor.
    assert "api_host_tools" in configured
    definitions = get_tool_definitions(enabled_toolsets=configured,
        quiet_mode=True, skip_tool_search_assembly=True)
    names = {tool["function"]["name"] for tool in definitions}
    assert host_plugin not in names
    assert "skills_list" in names


@pytest.mark.asyncio
@pytest.mark.parametrize("closed", [False, True])
async def test_finished_host_call_has_typed_nonexecution_acknowledgement(host_plugin, closed):
    from queue import Queue
    from concurrent.futures import ThreadPoolExecutor
    from gateway.host_tools import HostToolBroker
    adapter = _make_adapter("test-key")
    headers = {"Authorization": "Bearer test-key"}
    events = Queue()
    broker = HostToolBroker("retained-run", {host_plugin}, events.put, timeout=0.05)
    if closed:
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(broker.call, host_plugin, {})
            event = events.get(timeout=2)
            broker.close()
            original = pending.result(timeout=2)
    else:
        original = broker.call(host_plugin, {})
        event = events.get_nowait()
    adapter._run_host_tools["retained-run"] = broker
    adapter._run_owners["retained-run"] = adapter._run_idempotency_scope(None)
    route = f"/v1/runs/retained-run/host-tools/{event['callId']}/result"
    body = {"requestHash":event["requestHash"], "result":{"status":"ready"}}
    async with TestClient(TestServer(_interactive_app(adapter))) as client:
        assert (await client.post(route, json=body)).status == 401
        assert (await client.post(route, headers=headers, json={**body,"requestHash":"wrong"})).status == 409
        assert (await client.post(route.replace(event["callId"],"unknown"), headers=headers,json=body)).status == 404
        response = await client.post(route, headers=headers, json=body)
        assert response.status == 410, await response.text()
        assert (await response.json())["error"]["code"] == "host_call_inactive"
        assert (await client.post(route, headers=headers, json=body)).status == 410
    assert original["error"]["code"] == ("HOST_CALL_CANCELLED" if closed else "HOST_CALL_UNKNOWN")
    broker.close()


def test_publication_proxy_has_its_own_opt_in_and_budget_without_exposing_an_agent_tool():
    from gateway.host_tools import HostToolBroker
    requests = []
    def publish(request):
        requests.append(request)
        broker.resolve(request['callId'], request['requestHash'], {'status': 'ready'})
    broker = HostToolBroker('run', ['test_host_read', '__publish_current_message'], publish, timeout=0.05)
    large = {'message': {'text': 'x' * 60000}}
    assert broker.call('__publish_current_message', large)['status'] == 'ready'
    assert broker.call('test_host_read', large)['error']['code'] == 'HOST_REQUEST_INVALID'
    assert broker.call('__publish_current_message', {'value': 'x' * 65536})['error']['code'] == 'HOST_REQUEST_INVALID'
    disabled = HostToolBroker('run', [], lambda request: pytest.fail('Unadmitted publication'), timeout=0.05)
    assert disabled.call('__publish_current_message', {})['error']['code'] == 'HOST_TOOL_UNAVAILABLE'
    expired = HostToolBroker('run', ['__publish_current_message'], lambda request: None, timeout=0.01)
    assert expired.call('__publish_current_message', {})['error']['code'] == 'HOST_CALL_UNKNOWN'
    broker.close()
    assert broker.call('__publish_current_message', {})['error']['code'] == 'HOST_CALL_CANCELLED'
