"""Authenticated publication registration through real native HTTP/SSE paths."""
import asyncio
import json
from unittest.mock import patch
from uuid import uuid4

import pytest
from aiohttp.test_utils import TestClient, TestServer

from tests.gateway.test_api_server_interactive_messages import PublishingAgent, _interactive_app, settle
from tests.gateway.test_api_server_runs import _make_adapter
from gateway.publication_receipts import PUBLICATION_OPERATION

CARD = {"coachCard": {"version": 1, "kind": "paper_practice_invite", "title": "Practice"}}
HEADERS = {"Authorization": "Bearer test-key"}


async def request_event(stream):
    while True:
        line = await asyncio.wait_for(stream.content.readline(), 5)
        assert line, "Run ended before registration request"
        if line.startswith(b"data:"):
            event = json.loads(line[5:])
            if event.get("event") == "host_tool.request":
                return event


@pytest.mark.asyncio
@pytest.mark.parametrize("accepted", [True, False])
async def test_host_ack_precedes_visible_card_and_tool_success(accepted):
    adapter, agent = _make_adapter("test-key"), PublishingAgent(metadata=CARD)
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            caps = await (await client.get("/v1/capabilities", headers=HEADERS)).json()
            assert caps["features"]["publication_ack_v1"] is True
            assert PUBLICATION_OPERATION not in caps["features"]["host_tool_names"]
            response = await client.post("/v1/runs", headers=HEADERS, json={
                "input": "中" * 4096, "publication_ack": True})
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            stream = await client.get(f"/v1/runs/{run_id}/events", headers=HEADERS)
            event = await request_event(stream)
            assert event["name"] == PUBLICATION_OPERATION
            assert agent.results == []
            assert event["arguments"]["metadata"] == CARD
            result = {"status": "ready", "publication": {"status": "registered",
                "messageId": event["arguments"]["message_id"], "runId": str(uuid4()),
                "sessionId": str(uuid4()), "hash": "b" * 64}} if accepted else {
                "status": "blocked", "reason": "CARD_ACTION_UNAVAILABLE", "retrySameInput": False}
            route = f"/v1/runs/{run_id}/host-tools/{event['callId']}/result"
            reply = {"requestHash": event["requestHash"], "result": result}
            assert (await client.post(route, json=reply)).status == 401
            assert (await client.post(route, headers=HEADERS, json={**reply, "requestHash": "wrong"})).status == 409
            assert (await client.post(route, headers=HEADERS, json=reply)).status == 200
            await settle(adapter, run_id)
            text = await (await client.get(f"/v1/runs/{run_id}/events", headers=HEADERS)).text()
            visible = [json.loads(line[5:]) for line in text.splitlines()
                       if line.startswith("data:") and json.loads(line[5:]).get("event") == "message.interactive"]
            assert len(visible) == int(accepted)
            assert agent.results[0]["success"] is accepted
            if accepted:
                assert visible[0]["message_id"] == agent.results[0]["message_id"] == event["arguments"]["message_id"]
                assert agent.results[0]["publication"]["status"] == "registered"
            else:
                assert agent.results[0]["error"] == "CARD_ACTION_UNAVAILABLE"
            stream.release()


@pytest.mark.asyncio
async def test_opt_in_requires_boolean_and_configured_auth_before_start():
    for key, value in [("", True), ("test-key", "true"), ("test-key", 1)]:
        adapter = _make_adapter(key)
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", headers=HEADERS,
                json={"input": "Try Paper", "publication_ack": value})
            assert response.status == 400
            assert not adapter._active_run_tasks


@pytest.mark.asyncio
async def test_closed_broker_cannot_ack_or_deliver():
    adapter, agent = _make_adapter("test-key"), PublishingAgent(metadata=CARD)
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_interactive_app(adapter))) as client:
            response = await client.post("/v1/runs", headers=HEADERS,
                json={"input": "Try Paper", "publication_ack": True})
            run_id = (await response.json())["run_id"]
            stream = await client.get(f"/v1/runs/{run_id}/events", headers=HEADERS)
            await request_event(stream)
            adapter._run_host_tools[run_id].close()
            await settle(adapter, run_id)
            assert agent.results[0]["error"] == "HOST_CALL_CANCELLED"
            assert agent.results[0]["success"] is False
            text = await (await client.get(f"/v1/runs/{run_id}/events", headers=HEADERS)).text()
            assert '"event": "message.interactive"' not in text
            stream.release()
