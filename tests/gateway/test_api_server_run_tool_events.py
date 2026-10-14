"""Run SSE preserves native tool identity, results and safe replay."""

import asyncio
import json
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


def _events(body):
    return [
        json.loads(line[5:].strip())
        for line in body.splitlines()
        if line.startswith("data:")
    ]


def _runs_app(adapter):
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}/events", adapter._handle_run_events)
    return app


async def _run_with_tools(calls, *, errors=None, complete_only=False):
    adapter = APIServerAdapter(PlatformConfig(enabled=True))

    def construct(**callbacks):
        agent = MagicMock()
        agent.session_prompt_tokens = 0
        agent.session_completion_tokens = 0
        agent.session_total_tokens = 0

        def run_conversation(**_inputs):
            progress = callbacks["tool_progress_callback"]
            start = callbacks.get("tool_start_callback")
            complete = callbacks.get("tool_complete_callback")
            # The engine reports legacy progress alongside the exact callbacks.
            # Two simultaneous calls to the same tool finish in reverse order.
            if not complete_only:
                for call_id, name, args, _result in calls:
                    progress("tool.started", name, "loading", args)
                    if start is not None:
                        start(call_id, name, args)
            for call_id, name, args, result in reversed(calls):
                metadata = {"duration": None if complete_only else 0.01, "result": result}
                if errors is not None:
                    metadata["is_error"] = errors[call_id]
                progress("tool.completed", name, None, None, **metadata)
                if complete is not None:
                    complete(call_id, name, args, result)
            progress("reasoning.available", "_thinking", "Checking evidence")
            progress("subagent.complete", "delegate_task", "Research done",
                     child_session_id="child-session", status="completed")
            return {"final_response": "done"}

        agent.run_conversation.side_effect = run_conversation
        return agent

    # Keep the real HTTP handler and agent builder; replace only model execution
    # and provider selection, so no live model or credentials are required.
    with ExitStack() as stack:
        stack.enter_context(patch("run_agent.AIAgent", side_effect=construct))
        stack.enter_context(patch("gateway.run._resolve_runtime_agent_kwargs", return_value={
            "api_key": "test-key", "base_url": None, "provider": None,
            "api_mode": None, "command": None, "args": [],
        }))
        stack.enter_context(patch("gateway.run._resolve_gateway_model", return_value="test/model"))
        stack.enter_context(patch("gateway.run._load_gateway_config", return_value={}))
        async with TestClient(TestServer(_runs_app(adapter))) as client:
            body = {"input": "inspect market evidence"}
            headers = {"Idempotency-Key": "tool-events-test"}
            response = await client.post("/v1/runs", json=body, headers=headers)
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            task = adapter._active_run_tasks.get(run_id)
            if task is not None:
                await asyncio.wait_for(task, timeout=5)
            initial_response = await client.get(f"/v1/runs/{run_id}/events")
            initial_body = await initial_response.text()
            initial_events = _events(initial_body)
            first_tool = next((event for event in initial_events if event["event"].startswith("tool.")), None)
            replay_response = await client.get(
                f"/v1/runs/{run_id}/events",
                headers={"Last-Event-ID": str(first_tool["seq"] if first_tool else -1)},
            )
            replay_body = await replay_response.text()
            repeated = await client.post("/v1/runs", json=body, headers=headers)
            assert repeated.status == 202
            assert (await repeated.json())["run_id"] == run_id

    if adapter._session_db is not None:
        adapter._session_db.close()
    adapter._run_idempotency_store.close()
    return initial_events, _events(replay_body), initial_body + replay_body


@pytest.mark.asyncio
async def test_runs_correlate_same_name_tools_with_results_and_replay():
    events, replay, _body = await _run_with_tools([
        ("call-price", "skill_view", {"name": "hyperliquid"}, '{"success":true,"content":"price reference"}'),
        ("call-funding", "skill_view", {"name": "orderly", "file_path": "references/missing.md"},
         '{"success":false,"error":"Reference not found"}'),
    ])
    tools = [event for event in events if event["event"].startswith("tool.")]
    assert [(event["event"], event.get("tool_call_id")) for event in tools] == [
        ("tool.started", "call-price"),
        ("tool.started", "call-funding"),
        ("tool.completed", "call-funding"),
        ("tool.completed", "call-price"),
    ]
    assert tools[0]["args"] == {"name": "hyperliquid"}
    assert tools[2]["args"] == {"name": "orderly", "file_path": "references/missing.md"}
    assert tools[2]["result"] == '{"success":false,"error":"Reference not found"}'
    assert tools[2]["error"] is True
    assert tools[3]["result"] == '{"success":true,"content":"price reference"}'
    assert tools[3]["error"] is False
    assert all(event["duration"] >= 0 for event in tools if event["event"] == "tool.completed")
    assert replay == [event for event in events if event["seq"] > tools[0]["seq"]]
    assert any(event["event"] == "reasoning.available" and event["text"] == "Checking evidence"
               for event in events)
    assert any(event["event"] == "subagent.complete" and event["child_session_id"] == "child-session"
               for event in events)


@pytest.mark.asyncio
async def test_run_tool_payloads_redact_secrets_and_report_terminal_failure(monkeypatch):
    monkeypatch.setenv("HERMES_REDACT_SECRETS", "false")
    secret = "sk-proj-testonly1234567890testonly1234567890"
    events, _replay, body = await _run_with_tools([
        ("call-command", "terminal", {"command": f"read --token {secret}",
                                     "url": "https://source.example/?code=fixture-oauth-code",
                                     "params": '{"password":"fixture-nested-secret"}'},
         {"exit_code": 1, "output": [{"price": "42.5", "api_key": secret}],
          "error": "Request rejected", "password": "fixture-password-only"}),
    ])
    tools = [event for event in events if event["event"].startswith("tool.")]
    assert len(tools) == 2
    assert tools[0].get("tool_call_id") == tools[1].get("tool_call_id") == "call-command"
    assert secret not in body
    assert "fixture-password-only" not in body
    assert "fixture-oauth-code" not in body
    assert "fixture-nested-secret" not in body
    assert "--token" in tools[0]["args"]["command"]
    assert tools[1]["result"]["output"][0]["price"] == "42.5"
    assert tools[1]["result"]["exit_code"] == 1
    assert tools[1]["error"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("credentials", [
    {"client_secret": "opaque-client-value", "authorization": "opaque-auth-value",
     "private_key": "opaque-private-value"},
    {"password": 987654321, "token": ["opaque-token-one", "opaque-token-two"]},
    {"password": 'opaque-quote-"-value\nsecond-line'},
])
async def test_run_tool_credentials_redact_by_key_without_losing_events(credentials):
    events, _replay, body = await _run_with_tools([
        ("call-secrets", "fixture_tool", {"nested": credentials, "instrument": "ETH"},
         {"success": True, "nested": credentials, "price": "42.5"}),
    ])
    tools = [event for event in events if event["event"].startswith("tool.")]
    assert len(tools) == 2
    assert tools[0]["args"]["nested"] == {key: "***" for key in credentials}
    assert tools[1]["result"]["nested"] == {key: "***" for key in credentials}
    assert tools[0]["args"]["instrument"] == "ETH"
    assert tools[1]["result"]["price"] == "42.5"
    assert tools[1]["error"] is False
    assert "opaque-" not in body
    assert "987654321" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "result"), [
    ("exec_command", "[exit 1]\ncommand failed"),
    ("apply_patch", "Patch rejected"),
    ("dynamic_tool", {"success": False}),
])
async def test_run_tool_error_preserves_native_failure_metadata(name, result):
    events, _replay, _body = await _run_with_tools([
        ("call-ok", name, {"input": "one"}, "Completed"),
        ("call-failed", name, {"input": "two"}, result),
    ], errors={"call-ok": False, "call-failed": True})
    completed = [event for event in events if event["event"] == "tool.completed"]
    assert [(event["tool_call_id"], event["error"]) for event in completed] == [
        ("call-failed", True), ("call-ok", False),
    ]
    assert completed[0]["result"] == result


@pytest.mark.asyncio
async def test_run_preserves_identified_completion_without_start():
    events, _replay, _body = await _run_with_tools([
        ("call-fast", "exec_command", {"command": "inspect"}, "[exit 1]\ncommand failed"),
    ], errors={"call-fast": True}, complete_only=True)
    tools = [event for event in events if event["event"].startswith("tool.")]
    assert len(tools) == 1
    assert tools[0]["event"] == "tool.completed"
    assert tools[0]["tool_call_id"] == "call-fast"
    assert tools[0]["args"] == {"command": "inspect"}
    assert tools[0]["error"] is True
    assert tools[0]["duration"] >= 0


@pytest.mark.asyncio
@pytest.mark.parametrize(("payload", "expected"), [
    ({"client_secret": "fixture-log-secret", "private_key": "fixture-log-key",
      "authorization": "fixture-log-auth"},
     {"client_secret": "***", "private_key": "***", "authorization": "***"}),
    ({"body": {"authorization": "fixture-log-nested"},
      "clientSecret": "fixture-log-camel", "privateKey": "fixture-log-private"},
     {"body": {"authorization": "***"}, "clientSecret": "***", "privateKey": "***"}),
    ({"client_secret": 'fixture-log-escaped-"-secret\nsecond-line',
      "message": 'Ordinary "quoted" message\nkeeps its newline'},
     {"client_secret": "***", "message": 'Ordinary "quoted" message\nkeeps its newline'}),
])
async def test_run_redacts_credential_fields_in_prefixed_stdout(payload, expected):
    stdout = "HTTP response body: " + json.dumps({**payload, "price": "42.5"}) + "\nrequest completed"
    events, _replay, body = await _run_with_tools([
        ("call-stdout", "terminal", {"command": "inspect response"},
         {"exit_code": 0, "output": stdout}),
    ])
    tools = [event for event in events if event["event"].startswith("tool.")]
    assert len(tools) == 2
    assert tools[1]["tool_call_id"] == "call-stdout"
    assert tools[1]["error"] is False
    output = tools[1]["result"]["output"]
    assert output.startswith("HTTP response body: ")
    assert output.endswith("\nrequest completed")
    parsed = json.loads(output.removeprefix("HTTP response body: ").removesuffix("\nrequest completed"))
    assert parsed == {**expected, "price": "42.5"}
    assert "fixture-log-" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize(("response", "expected"), [
    (json.dumps({"client_secret": "opaque-nested-stdout-secret", "price": "42.5"}),
     json.dumps({"client_secret": "***", "price": "42.5"})),
    ({"chunks": [json.dumps({"private_key": 'opaque-nested-quote-"-secret\nnext',
                             "message": "normal response"}),
                 {"rows": [1, {"authorization": "opaque-nested-array-secret"}]}]},
     {"chunks": [json.dumps({"private_key": "***", "message": "normal response"}),
                 {"rows": [1, {"authorization": "***"}]}]}),
])
async def test_run_redacts_encoded_json_in_prefixed_stdout_initial_and_replay(response, expected):
    prefix, suffix = "HTTP response body: ", "\nrequest completed"
    stdout = prefix + json.dumps({"response": response, "price": "42.5"}) + suffix
    events, replay, body = await _run_with_tools([
        ("call-nested-stdout", "terminal", {"command": "inspect response"},
         {"exit_code": 0, "output": stdout}),
    ])
    for stream in (events, replay):
        completed = [event for event in stream if event["event"] == "tool.completed"]
        assert len(completed) == 1
        assert completed[0]["tool_call_id"] == "call-nested-stdout"
        assert completed[0]["error"] is False
        output = completed[0]["result"]["output"]
        assert isinstance(output, str)
        assert output.startswith(prefix) and output.endswith(suffix)
        parsed = json.loads(output.removeprefix(prefix).removesuffix(suffix))
        assert parsed == {"response": expected, "price": "42.5"}
        assert type(parsed["response"]) is type(response)
    assert "opaque-nested-" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("representation", ["structured", "prefixed", "nested_json_string"])
async def test_run_shared_credential_classification_masks_secrets_preserves_metadata(representation):
    payload = {
        "secret_key": "opaque-classification-key",
        "bearerToken": "opaque-classification-bearer",
        "db_password": "opaque-classification-db",
        "apiSecret": "opaque-classification-api",
        "token_count": 7, "tokenType": "Bearer", "auth_scope": "read",
        "authorized": True, "secret_source": "env", "client_id": "public-client",
        "agentKeyId": "public-agent-reference", "price": "42.5",
    }
    expected = {
        "secret_key": "***", "bearerToken": "***", "db_password": "***", "apiSecret": "***",
        "token_count": 7, "tokenType": "Bearer", "auth_scope": "read",
        "authorized": True, "secret_source": "env", "client_id": "public-client",
        "agentKeyId": "public-agent-reference", "price": "42.5",
    }
    if representation == "structured":
        result = {"success": True, "data": payload}
    else:
        output_data = payload if representation == "prefixed" else {"response": json.dumps(payload)}
        result = {"success": True, "output": "HTTP response body: " + json.dumps(output_data)}
    events, replay, body = await _run_with_tools([
        ("call-classification", "fixture_tool", {"data": payload}, result),
    ])
    for stream in (events, replay):
        completed = [event for event in stream if event["event"] == "tool.completed"]
        assert len(completed) == 1
        assert completed[0]["args"]["data"] == expected
        assert completed[0]["error"] is False
        output = completed[0]["result"]
        if representation == "structured":
            assert output["data"] == expected
        else:
            parsed = json.loads(output["output"].removeprefix("HTTP response body: "))
            if representation == "nested_json_string":
                assert isinstance(parsed["response"], str)
                parsed = json.loads(parsed["response"])
            assert parsed == expected
    assert "opaque-classification-" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("representation", ["structured", "nested_json_string"])
async def test_run_public_market_wallet_identity_survives_secret_redaction(representation):
    public_key = "04" + "11" * 64
    payload = {
        "market_key": "BTC-PERP", "marketKey": "ETH-PERP",
        "public_key": public_key, "publicKey": public_key,
        "private_key": "opaque-identity-private-key",
        "nested": [{"marketKey": "SOL-PERP", "publicKey": public_key,
                    "privateKey": "opaque-nested-identity-private-key"}],
    }
    expected = {
        "market_key": "BTC-PERP", "marketKey": "ETH-PERP",
        "public_key": public_key, "publicKey": public_key, "private_key": "***",
        "nested": [{"marketKey": "SOL-PERP", "publicKey": public_key, "privateKey": "***"}],
    }
    result = ({"data": payload} if representation == "structured" else {
        "output": "HTTP response body: " + json.dumps({"response": json.dumps(payload)}),
    })
    events, replay, body = await _run_with_tools([
        ("call-public-identity", "fixture_tool", {"data": payload}, result),
    ])
    for stream in (events, replay):
        completed = [event for event in stream if event["event"] == "tool.completed"]
        assert len(completed) == 1
        assert completed[0]["args"]["data"] == expected
        output = completed[0]["result"]
        if representation == "structured":
            assert output["data"] == expected
        else:
            decoded = json.loads(output["output"].removeprefix("HTTP response body: "))
            assert json.loads(decoded["response"]) == expected
    assert "opaque-identity-" not in body
    assert "opaque-nested-identity-" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding_depth", [2, 3, 5])
async def test_run_recursively_redacts_multiple_json_string_layers(encoding_depth):
    response = {
        "client_secret": 'opaque-depth-secret-"quoted"\nnext-line',
        "price": "42.5", "message": 'Normal "quoted" message\nkeeps its newline',
    }
    for _ in range(encoding_depth):
        response = json.dumps(response)
    prefix, suffix = "HTTP response body: ", "\nrequest completed"
    stdout = prefix + json.dumps({"response": response}) + suffix
    events, replay, body = await _run_with_tools([
        ("call-encoded-depth", "terminal", {"command": "inspect response"},
         {"exit_code": 0, "output": stdout}),
    ])
    for stream in (events, replay):
        completed = [event for event in stream if event["event"] == "tool.completed"]
        assert len(completed) == 1
        assert completed[0]["tool_call_id"] == "call-encoded-depth"
        assert completed[0]["error"] is False
        output = completed[0]["result"]["output"]
        assert output.startswith(prefix) and output.endswith(suffix)
        parsed = json.loads(output.removeprefix(prefix).removesuffix(suffix))["response"]
        for _ in range(encoding_depth):
            assert isinstance(parsed, str)
            parsed = json.loads(parsed)
        assert parsed == {
            "client_secret": "***", "price": "42.5",
            "message": 'Normal "quoted" message\nkeeps its newline',
        }
    assert "opaque-depth-secret" not in body
