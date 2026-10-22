"""Current-conversation delivery through the real run entry, without model I/O."""
import json
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from aiohttp.test_utils import TestClient, TestServer
from aiohttp import web

from tests.gateway.test_api_server_runs import _make_adapter, _create_runs_app
from tools.send_message_tool import send_message_tool

def _interactive_app(adapter):
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    return app


class PublishingAgent:
    session_prompt_tokens = session_completion_tokens = session_total_tokens = 0

    def __init__(self, buttons=None, metadata=None):
        self.buttons = buttons
        self.metadata = metadata
        self.results = []

    def run_conversation(self, **kwargs):
        args = {"target": "current", "message": kwargs["user_message"]}
        if self.buttons is not None:
            args["reply_markup"] = {"inline_keyboard": self.buttons}
        if self.metadata is not None:
            args["metadata"] = self.metadata
        self.results.append(json.loads(send_message_tool(args)))
        return {"final_response": "done"}


def context(account="paper-a"):
    return {"version": 1, "mode": "paper", "account_id": account}


async def settle(adapter, run_id):
    task = adapter._active_run_tasks.get(run_id)
    if task is not None:
        await task
    assert adapter._run_statuses[run_id]["status"] == "completed"


@pytest.mark.asyncio
async def test_current_message_reaches_sse_with_original_keyboard_and_bound_context():
    adapter = _make_adapter()
    agent = PublishingAgent([[{"text": "Review", "callback_data": "tc:a7:review"}]])
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={
                "input": "Review this Paper order", "interaction_context": context(),
            })
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            await settle(adapter, run_id)
            assert agent.results[0].get("success") is True
            stream = await (await client.get(f"/v1/runs/{run_id}/events")).text()
            events = [json.loads(line[5:]) for line in stream.splitlines() if line.startswith("data:")]
            cards = [event for event in events if event.get("event") == "message.interactive"]
            assert len(cards) == 1
            assert cards[0]["message"]["text"] == "Review this Paper order"
            assert cards[0]["message"]["reply_markup"]["inline_keyboard"] == agent.buttons
            assert cards[0]["context"] == context()
            assert cards[0]["run_id"] == run_id
            assert cards[0]["message_id"] == agent.results[0]["message_id"]


@pytest.mark.asyncio
async def test_plain_current_message_does_not_require_a_terminal_account():
    adapter = _make_adapter()
    agent = PublishingAgent()
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={"input": "Good morning"})
            run_id = (await response.json())["run_id"]
            await settle(adapter, run_id)
            assert agent.results[0].get("success") is True
            assert "reply_markup" not in agent.results[0]["message"]

@pytest.mark.asyncio
async def test_host_evidence_is_bound_to_one_run_and_oversized_context_is_rejected():
    adapter = _make_adapter()
    agent = PublishingAgent()
    bound = {**context(), "host_data": {"asOf": "2026-10-13", "positions": [{"marketKey": "BTC"}]}}
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={"input": "Review", "interaction_context": bound})
            assert response.status == 202
            await settle(adapter, (await response.json())["run_id"])
            assert agent.results[0]["context"] == bound
            denied = await client.post("/v1/runs", json={"input": "Review", "interaction_context": {**context(), "host_data": {"tooLarge": "x" * 32768}}})
            assert denied.status == 400


@pytest.mark.asyncio
async def test_host_metadata_is_separate_from_telegram_presentation_and_round_trips():
    adapter = _make_adapter()
    metadata = {"actions": {"review": {"kind": "place_order", "request": {"quantity": "0.01"}}}}
    agent = PublishingAgent([[{"text": "Review", "callback_data": "review"}]], metadata)
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={"input": "A proposal", "interaction_context": context()})
            run_id = (await response.json())["run_id"]
            await settle(adapter, run_id)
            stream = await (await client.get(f"/v1/runs/{run_id}/events")).text()
            events = [json.loads(line[5:]) for line in stream.splitlines() if line.startswith("data:")]
            message = next(event for event in events if event.get("event") == "message.interactive")
            assert message["metadata"] == metadata
            assert "metadata" not in message["message"]
            assert agent.results[0]["metadata"] == metadata


@pytest.mark.asyncio
@pytest.mark.parametrize("button", [
    {"text": "Long", "callback_data": "🐱" * 17},
    {"text": "Both", "callback_data": "x", "url": "https://example.com"},
    {"text": "Bad link", "url": "javascript:alert(1)"},
])
async def test_invalid_keyboard_does_not_publish_an_interactive_message(button):
    adapter = _make_adapter()
    agent = PublishingAgent([[button]])
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={"input": "invalid"})
            run_id = (await response.json())["run_id"]
            await settle(adapter, run_id)
            assert "inline keyboard" in agent.results[0].get("error", "").lower()
            stream = await (await client.get(f"/v1/runs/{run_id}/events")).text()
            assert "message.interactive" not in stream


def test_current_destination_outside_a_run_fails_without_cross_channel_delivery():
    result = json.loads(send_message_tool({"target": "current", "message": "hello"}))
    assert "current conversation" in result.get("error", "").lower()


@pytest.mark.asyncio
async def test_invalid_mode_is_rejected_before_any_agent_runs():
    adapter = _make_adapter()
    agent = PublishingAgent()
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={
                "input": "hello", "interaction_context": {**context(), "mode": "both"},
            })
            assert response.status == 400
            assert agent.results == []


@pytest.mark.asyncio
async def test_tool_workers_keep_each_run_context_and_do_not_leak_after_completion():
    from tools.thread_context import propagate_context_to_thread
    from gateway.interactive_messages import current_interaction_context
    adapter = _make_adapter()
    barrier = threading.Barrier(2)

    class ConcurrentAgent(PublishingAgent):
        def run_conversation(self, **kwargs):
            barrier.wait(timeout=5)
            with ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(propagate_context_to_thread(lambda: send_message_tool({
                    "target": "current", "message": kwargs["user_message"],
                    "reply_markup": {"inline_keyboard": [[{"text": "UTF-8", "callback_data": "🐱" * 16}]]},
                }))).result()
            self.results.append(json.loads(result))
            return {"final_response": "done"}

    agent = ConcurrentAgent()
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            responses = await asyncio.gather(*[client.post("/v1/runs", json={
                "input": account, "session_id": account, "interaction_context": context(account),
            }) for account in ["paper-a", "paper-b"]])
            run_ids = [(await response.json())["run_id"] for response in responses]
            await asyncio.gather(*[settle(adapter, run_id) for run_id in run_ids])
    assert {result["message"]["text"]: result["context"]["account_id"] for result in agent.results} == {
        "paper-a": "paper-a", "paper-b": "paper-b",
    }
    assert current_interaction_context() is None


@pytest.mark.asyncio
async def test_clarify_answer_is_bound_to_original_run_and_stale_answer_is_rejected():
    from tools.clarify_gateway import get_pending_for_session, register, clear_session
    adapter = _make_adapter()
    first_id, second_id = "run_first", "run_second"
    for run_id in [first_id, second_id]:
        adapter._run_statuses[run_id] = {"status": "running"}
        adapter._run_owners[run_id] = adapter._run_idempotency_scope(None)
    first = register("question-a", first_id, "Which market?", ["BTC", "ETH"])
    second = register("question-b", second_id, "Which market?", ["BTC", "ETH"])
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    try:
        async with TestClient(TestServer(app)) as client:
            wrong = await client.post(f"/v1/runs/{second_id}/clarify", json={
                "clarify_id": "question-a", "response": "BTC",
            })
            assert wrong.status == 409
            assert not first.event.is_set() and not second.event.is_set()
            response = await client.post(f"/v1/runs/{first_id}/clarify", json={
                "clarify_id": "question-a", "response": "ETH",
            })
            assert response.status == 200
            assert first.response == "ETH" and first.event.is_set()
            duplicate = await client.post(f"/v1/runs/{first_id}/clarify", json={
                "clarify_id": "question-a", "response": "BTC",
            })
            assert duplicate.status == 409
            assert first.response == "ETH"
            assert get_pending_for_session(second_id, include_choice_prompts=True).clarify_id == "question-b"
    finally:
        clear_session(first_id)
        clear_session(second_id)

@pytest.mark.asyncio
@pytest.mark.parametrize('detach_stream', [False, True])
async def test_real_run_clarifies_and_resumes_with_the_original_answer(detach_stream):
    from tools import clarify_gateway
    adapter = _make_adapter()
    loop = asyncio.get_running_loop()
    ready = asyncio.Event()
    entries = []
    original_register = clarify_gateway.register

    def record(*args, **kwargs):
        entry = original_register(*args, **kwargs)
        entries.append(entry)
        loop.call_soon_threadsafe(ready.set)
        return entry

    class AskingAgent(PublishingAgent):
        def run_conversation(self, **kwargs):
            answer = self.clarify_callback("Which market?", ["BTC", "ETH"])
            self.results.append(answer)
            return {"final_response": answer}

    agent = AskingAgent()
    with patch.object(adapter, "_create_agent", return_value=agent), patch.object(clarify_gateway, "register", side_effect=record):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", json={"input": "Help me choose", "interaction_context": context()})
            run_id = (await response.json())["run_id"]
            await asyncio.wait_for(ready.wait(), 5)
            status = await client.get(f'/v1/runs/{run_id}')
            assert (await status.json())['pending_clarify_id'] == entries[0].clarify_id
            if detach_stream:
                adapter._run_streams.pop(run_id, None)
            answer = await client.post(f"/v1/runs/{run_id}/clarify", json={"clarify_id": entries[0].clarify_id, "response": "ETH"})
            assert answer.status == 200
            await settle(adapter, run_id)
            assert agent.results == ["ETH"]
            status = await client.get(f'/v1/runs/{run_id}')
            assert (await status.json())['pending_clarify_id'] is None
            if detach_stream:
                return
            stream = await (await client.get(f"/v1/runs/{run_id}/events")).text()
            events = [json.loads(line[5:]) for line in stream.splitlines() if line.startswith("data:")]
            card = next(event for event in events if event.get("event") == "message.interactive")
            assert card["clarify_id"] == entries[0].clarify_id
            buttons = [button for row in card["message"]["reply_markup"]["inline_keyboard"] for button in row]
            assert next(button for button in buttons if button['callback_data'] == f'cl:{entries[0].clarify_id}:1')['text'] == 'ETH'
            assert card["context"] == context()
            resolved = next(event for event in events if event.get('event') == 'message.clarify_resolved')
            assert resolved['clarify_id'] == entries[0].clarify_id
            assert resolved['reason'] == 'answered'
            assert clarify_gateway.get_pending_for_session(run_id, include_choice_prompts=True) is None

@pytest.mark.parametrize("metadata", [{"secret": float("nan")}, {"large": "a" * 32769}, ["not an object"]])
def test_invalid_host_metadata_does_not_publish(metadata):
    from gateway.interactive_messages import current_message_scope
    sent = []
    with current_message_scope(lambda *args: sent.append(args)):
        result = json.loads(send_message_tool({"target": "current", "message": "hello", "metadata": metadata}))
    assert "metadata" in result.get("error", "").lower()
    assert sent == []

@pytest.mark.asyncio
async def test_stop_releases_an_actual_pending_clarification():
    from tools import clarify_gateway
    adapter = _make_adapter()
    loop = asyncio.get_running_loop()
    ready = asyncio.Event()
    original_register = clarify_gateway.register
    def record(*args, **kwargs):
        entry = original_register(*args, **kwargs)
        loop.call_soon_threadsafe(ready.set)
        return entry
    class WaitingAgent(PublishingAgent):
        def interrupt(self, *args, **kwargs):
            pass
        def run_conversation(self, **kwargs):
            self.clarify_callback("Type an answer")
            return {"final_response": "unexpected"}
    with patch.object(adapter, "_create_agent", return_value=WaitingAgent()), patch.object(clarify_gateway, "register", side_effect=record), patch.object(clarify_gateway, "get_clarify_timeout", return_value=0):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post('/v1/runs', json={"input": "Question"})
            run_id = (await response.json())["run_id"]
            await asyncio.wait_for(ready.wait(), 5)
            try:
                assert (await client.post(f'/v1/runs/{run_id}/stop')).status == 200
                task = adapter._active_run_tasks.get(run_id)
                if task is not None:
                    await asyncio.wait_for(asyncio.shield(task), 1)
                assert adapter._run_statuses[run_id]["status"] == 'cancelled'
                assert clarify_gateway.get_pending_for_session(run_id, include_choice_prompts=True) is None
            finally:
                clarify_gateway.clear_session(run_id)
                task=adapter._active_run_tasks.get(run_id)
                if task: await task

@pytest.mark.asyncio
async def test_detached_stream_cannot_report_current_message_delivery_success():
    adapter = _make_adapter()
    gate = threading.Event()
    loop = asyncio.get_running_loop()
    ready = asyncio.Event()
    class PausedAgent(PublishingAgent):
        def run_conversation(self, **kwargs):
            loop.call_soon_threadsafe(ready.set)
            gate.wait(timeout=5)
            return super().run_conversation(**kwargs)
    agent = PausedAgent()
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post('/v1/runs', json={"input": "A late card"})
            run_id = (await response.json())["run_id"]
            await asyncio.wait_for(ready.wait(), 5)
            adapter._sweep_orphaned_runs_once(adapter._run_streams_created[run_id] + adapter._RUN_STREAM_TTL + 1)
            gate.set()
            await settle(adapter, run_id)
            assert not agent.results[0].get('success')
            assert 'delivery' in agent.results[0].get('error','').lower()


def test_current_message_uses_real_tool_registry_and_cannot_target_another_channel():
    from tools.registry import discover_builtin_tools, registry
    from gateway.interactive_messages import current_message_scope
    from model_tools import get_tool_definitions, handle_function_call
    discover_builtin_tools()
    definitions=get_tool_definitions(enabled_toolsets=['api_interactions'], quiet_mode=True, skip_tool_search_assembly=True)
    names={definition['function']['name'] for definition in definitions}
    assert {'send_message','clarify'} <= names
    sent=[]
    with current_message_scope(lambda *args: sent.append(args), context()):
        result=json.loads(handle_function_call('send_message', {'target':'current','message':'hello'}, enabled_toolsets=['api_interactions']))
        denied=json.loads(handle_function_call('send_message', {'target':'telegram','message':'must not send'}, enabled_toolsets=['api_interactions']))
    assert result['success'] is True and len(sent)==1
    assert not denied.get('success')

@pytest.mark.asyncio
async def test_shutdown_cancellation_releases_clarify_before_finishing_hosted_residency():
    from tools import clarify_gateway
    from unittest.mock import AsyncMock
    adapter = _make_adapter()
    loop = asyncio.get_running_loop()
    ready = asyncio.Event()
    original_register = clarify_gateway.register
    def record(*args, **kwargs):
        entry = original_register(*args, **kwargs)
        loop.call_soon_threadsafe(ready.set)
        return entry
    class Lease:
        active = True
        finish = AsyncMock()
    lease = Lease()
    class WaitingAgent(PublishingAgent):
        def interrupt(self, *args, **kwargs):
            pass
        def run_conversation(self, **kwargs):
            self.clarify_callback('A question while hosted')
            return {'final_response': 'unexpected'}
    with patch.object(adapter, '_create_agent', return_value=WaitingAgent()), patch.object(clarify_gateway, 'register', side_effect=record), patch.object(clarify_gateway, 'get_clarify_timeout', return_value=0), patch('gateway.platform_activity.begin_platform_activity', new=AsyncMock(return_value=lease)):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post('/v1/runs', json={'input':'Question'})
            run_id = (await response.json())['run_id']
            await asyncio.wait_for(ready.wait(), 5)
            task = adapter._active_run_tasks[run_id]
            try:
                task.cancel()
                done, _ = await asyncio.wait([task], timeout=1)
                assert task in done, 'Shutdown must release the waiting worker before finishing residency'
                assert clarify_gateway.get_pending_for_session(run_id, include_choice_prompts=True) is None
                lease.finish.assert_awaited_once()
            finally:
                clarify_gateway.clear_session(run_id)
                try:
                    await task
                except asyncio.CancelledError:
                    pass

@pytest.mark.parametrize("name",["terminal","execute_code","browser_click","delegate_task","cronjob","skill_manage","mcp_live_order","vision_analyze","video_analyze"])
def test_paper_scope_blocks_out_of_band_execution_even_when_registered(name):
    from tools.registry import ToolRegistry
    from gateway.interactive_messages import current_message_scope
    calls=[]
    r=ToolRegistry()
    r.register(name=name,toolset='custom',schema={'name':name,'parameters':{'type':'object','properties':{}}},handler=lambda args,**kwargs:calls.append(args) or json.dumps({'ok':True}))
    with current_message_scope(lambda *args:None,{'version':1,'mode':'paper','account_id':'account'}):
        result=r.dispatch(name,{'command':'trade on Live'})
    assert 'proposal_only' in str(result)
    assert calls==[]
    assert json.loads(r.dispatch(name,{}))=={'ok':True}

def test_paper_scope_keeps_research_and_memory_and_does_not_leak_into_normal_chat():
    from tools.registry import ToolRegistry
    from gateway.interactive_messages import current_message_scope
    r=ToolRegistry()
    for name in ['web_search','memory']:
        r.register(name=name,toolset='custom',schema={'name':name,'parameters':{'type':'object','properties':{}}},handler=lambda args,**kwargs:json.dumps({'result':'normal Agent response'}))
    with current_message_scope(lambda *args:None,{'version':1,'mode':'paper','account_id':'account'}):
        assert json.loads(r.dispatch('web_search',{}))=={'result':'normal Agent response'}
        assert json.loads(r.dispatch('memory',{}))=={'result':'normal Agent response'}
    assert json.loads(r.dispatch('memory',{}))=={'result':'normal Agent response'}

def test_paper_scope_blocks_tool_search_bridges_and_dispatch_middleware_before_execution():
    from gateway.interactive_messages import current_message_scope
    from model_tools import handle_function_call
    with current_message_scope(lambda *args:None,{'version':1,'mode':'paper','account_id':'account'}):
        for name in ['tool_call','tool_search','terminal']:
            assert json.loads(handle_function_call(name,{'tool':'terminal','arguments':{'command':'Live trade'}}))['error_type']=='proposal_only'


@pytest.mark.asyncio
@pytest.mark.parametrize('accepted', [True, False])
async def test_publication_ack_waits_for_authenticated_registration_before_delivery(accepted):
    adapter, agent = _make_adapter('test-key'), PublishingAgent(metadata={'coachCard': {'private': 'marker'}})
    headers = {'Authorization': 'Bearer test-key'}
    with patch.object(adapter, '_create_agent', return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post('/v1/runs', headers=headers, json={
                'input': 'Publish this reply', 'publication_ack': True,
            })
            assert response.status == 202
            run_id = (await response.json())['run_id']
            stream = await client.get(f'/v1/runs/{run_id}/events', headers=headers)
            try:
                while True:
                    line = await asyncio.wait_for(stream.content.readline(), 2)
                    assert line, 'Native run ended without registration'
                    if not line.startswith(b'data:'):
                        continue
                    event = json.loads(line[5:])
                    assert event.get('event') != 'message.interactive', 'Published before registration'
                    if event.get('event') == 'host_tool.request':
                        break
                assert event['name'] == '__publish_current_message'
                assert agent.results == []
                publication = event['arguments']
                result = {'status': 'ready' if accepted else 'blocked',
                          'publication': {'status': 'registered' if accepted else 'rejected',
                                          'messageId': publication['message_id'], 'runId': '00000000-0000-4000-8000-000000000001',
                                          'sessionId': '00000000-0000-4000-8000-000000000002', 'hash': 'b' * 64},
                          'registered': {'coachCard': {'version': 1, 'id': 'card-id', 'kind': 'paper_practice_invite'},
                                         'resources': [{'kind': 'playbook', 'id': 'resource-id'}]}}
                route = f"/v1/runs/{run_id}/host-tools/{event['callId']}/result"
                wire = {'requestHash': event['requestHash'], 'result': result}
                assert (await client.post(route, json=wire)).status == 401
                assert (await client.post(route, headers=headers, json={**wire, 'requestHash': 'wrong'})).status == 409
                assert (await client.post(route, headers=headers, json=wire)).status == 200
                await settle(adapter, run_id)
                rest = await stream.text()
                if accepted:
                    assert 'message.interactive' in rest
                    assert agent.results[0]['coachCard'] == result['registered']['coachCard']
                    # The saved tool result keeps the whole acknowledgement; the
                    # visible message carries only the registered presentation.
                    assert agent.results[0]['registered'] == result['registered']
                    shown = next(json.loads(line[5:]) for line in rest.splitlines()
                                 if line.startswith('data:') and '"message.interactive"' in line)
                    assert shown['coachCard'] == result['registered']['coachCard']
                    assert shown['context'] is None
                    assert 'registered' not in shown and 'resources' not in shown
                else:
                    assert 'message.interactive' not in rest
                    assert 'error' in agent.results[0]
            finally:
                await client.post(f'/v1/runs/{run_id}/stop', headers=headers)
                stream.release()


@pytest.mark.asyncio
@pytest.mark.parametrize('flag', [True, 'true', 1])
async def test_publication_ack_requires_configured_auth_and_a_boolean_flag(flag):
    adapter = _make_adapter('' if flag is True else 'test-key')
    with patch.object(adapter, '_create_agent', return_value=PublishingAgent()):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post('/v1/runs', headers={'Authorization': 'Bearer test-key'},
                                         json={'input': 'Publish', 'publication_ack': flag})
            assert response.status == 400
            assert not adapter._active_run_tasks


@pytest.mark.asyncio
async def test_stop_cancels_publication_registration_without_delivery_or_another_channel():
    adapter, agent = _make_adapter('test-key'), PublishingAgent()
    headers = {'Authorization': 'Bearer test-key'}
    with patch.object(adapter, '_create_agent', return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post('/v1/runs', headers=headers,
                                         json={'input': 'Publish', 'publication_ack': True})
            run_id = (await response.json())['run_id']
            stream = await client.get(f'/v1/runs/{run_id}/events', headers=headers)
            try:
                while True:
                    line = await asyncio.wait_for(stream.content.readline(), 2)
                    if line.startswith(b'data:') and json.loads(line[5:]).get('event') == 'host_tool.request':
                        break
                task = adapter._active_run_tasks[run_id]
                assert (await client.post(f'/v1/runs/{run_id}/stop', headers=headers)).status == 200
                await asyncio.wait_for(task, 2)
                assert 'error' in agent.results[0]
                assert 'message.interactive' not in await stream.text()
            finally:
                stream.release()
