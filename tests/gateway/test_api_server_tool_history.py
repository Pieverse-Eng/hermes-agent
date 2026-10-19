"""Client history and native SSE share tool redaction, without rewriting model state."""
import base64
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.platforms.api_server import APIServerAdapter
from hermes_state import SessionDB
from tests.gateway.test_api_server_runs import _make_adapter
from tests.gateway.test_api_server_run_tool_events import _run_with_tools


@pytest.mark.asyncio
@pytest.mark.parametrize("representation", ["json", "stdout", "nested"])
@pytest.mark.parametrize("cursor_payload", [
    {"v": "pc1", "at": "2026-10-18T12:00:00.123456Z", "id": "42", "q": []},
    {"hash": "0123456789abcdef" * 4, "at": "2026-10-19T04:03:04.123456Z",
     "id": "11111111-1111-4111-8111-111111111111"},
], ids=["keyset", "paper-facts"])
async def test_native_history_matches_sse_redaction_and_keeps_raw_state(tmp_path, representation, cursor_payload):
    cursor = base64.urlsafe_b64encode(json.dumps(cursor_payload).encode()).decode().rstrip("=")
    payload = {
        "scopeKey": "wallet:USDC", "marketKey": "hyperliquid:perp:BTC",
        "commandKey": "paper:11111111-1111-4111-8111-111111111111:1",
        "nextCursor": cursor, "publicKey": "04" + "11" * 64,
        "api_key": 'opaque-history-"quoted"\nsecret', "key": {"value": "opaque-key"},
        "nested": [json.dumps({"scopeKey": "wallet:USDC", "client_secret": "opaque-nested"})],
        "message": "Keep  meaningful spaces\n and trailing space ", "token_count": 7,
    }
    encoded = json.dumps(payload)
    if representation == "stdout":
        encoded = "HTTP response body: " + encoded + "\nrequest completed"
    elif representation == "nested":
        encoded = json.dumps({"response": json.dumps(encoded)})
    db = SessionDB(tmp_path / "sessions.db")
    db.create_session("history", "api_server")
    calls = [{"id": "native-call", "type": "function", "function": {
        "name": "paper_read", "arguments": json.dumps(payload),
    }}]
    db.append_message("history", "assistant", None, tool_calls=calls)
    db.append_message("history", "tool", encoded, tool_name="paper_read", tool_call_id="native-call")
    original = db.get_messages("history")
    adapter = _make_adapter(api_key="test-history-key")
    adapter._session_db = db
    app = web.Application()
    app.router.add_get("/api/sessions/{session_id}/messages", adapter._handle_session_messages)
    try:
        async with TestClient(TestServer(app)) as client:
            response = await client.get("/api/sessions/history/messages", headers={
                "Authorization": "Bearer test-history-key",
            })
            assert response.status == 200
            history = (await response.json())["data"]
        args = json.loads(history[0]["tool_calls"][0]["function"]["arguments"])
        assert args["api_key"] == "***"
        assert args["key"] == "***"
        assert json.loads(args["nested"][0]) == {"scopeKey": "wallet:USDC", "client_secret": "***"}
        for name in ("scopeKey", "marketKey", "commandKey", "nextCursor", "publicKey", "message", "token_count"):
            assert args[name] == payload[name]
        assert "opaque-" not in json.dumps(history)
        assert history[0]["tool_calls"][0]["id"] == history[1]["tool_call_id"] == "native-call"
        assert db.get_messages("history") == original
        assert json.loads(db.get_messages_as_conversation("history")[0]["tool_calls"][0]["function"]["arguments"]) == payload
        events, replay, _ = await _run_with_tools([("native-call", "paper_read", payload, encoded)])
        for stream in (events, replay):
            completed = next(event for event in stream if event["event"] == "tool.completed")
            assert completed["result"] == history[1]["content"]
            assert completed["args"] == args
    finally:
        db.close()
        adapter._run_idempotency_store.close()


@pytest.mark.parametrize("content", ['{ "scopeKey" : "wallet:USDC", "message":"  untouched  " }\n', "plain  result\n "])
def test_client_tool_history_preserves_unaffected_bytes_and_terminal_transcript(content):
    call = {"id": "native-call", "type": "function", "function": {
        "name": "paper_read", "arguments": '{ "operation" : "account" }',
    }}
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [call]},
        {"role": "tool", "content": content, "tool_call_id": "native-call"},
    ]
    for message in messages:
        assert APIServerAdapter._message_response(message) == message
    transcript = APIServerAdapter._turn_transcript_messages([], "read", {"messages": messages})
    assert transcript == messages


def test_terminal_transcript_redacts_tools_without_mutating_model_messages():
    content = '{"scopeKey":"wallet:USDC","api_key":"opaque-terminal-secret"}'
    message = {"role": "tool", "content": content, "tool_call_id": "native-call"}
    transcript = APIServerAdapter._turn_transcript_messages([], "read", {"messages": [message]})
    assert json.loads(transcript[0]["content"]) == {"scopeKey": "wallet:USDC", "api_key": "***"}
    assert message["content"] == content


@pytest.mark.parametrize("changes", [
    {"hash": "not-a-query-digest"},
    {"hash": "0123456789abcdef" * 4 + "x"},
    {"id": "not-a-cycle-id"},
    {"at": "not-a-timestamp"},
    {"token": "opaque-pagination-secret"},
    {"sub": "credential-subject", "exp": 9999999999},
])
def test_paper_cursor_allowlist_does_not_preserve_unproven_or_credential_payloads(changes):
    from gateway.platforms.api_server_tool_payloads import safe_tool_value

    payload = {"hash": "0123456789abcdef" * 4, "at": "2026-10-19T04:03:04.123456Z",
               "id": "11111111-1111-4111-8111-111111111111", **changes}
    cursor = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    result = safe_tool_value({"nextCursor": cursor, "token": cursor})
    assert result["nextCursor"] != cursor
    assert result["token"] == "***"


@pytest.mark.parametrize("payload", [
    '{"hash":"sk-proj-hidden-cursor-credential1234567890",'
    '"hash":"' + "0123456789abcdef" * 4 + '",'
    '"at":"2026-10-19T04:03:04.123456Z","id":"11111111-1111-4111-8111-111111111111"}',
    '{"v":"pc1","at":"2026-10-19T04:03:04.123456Z","id":"42",'
    '"q":["sk-proj-hidden-cursor-credential1234567890"],"q":[]}',
], ids=["paper-facts", "keyset"])
def test_cursor_allowlist_does_not_return_encoded_credentials_hidden_by_duplicate_keys(payload):
    from gateway.platforms.api_server_tool_payloads import safe_tool_value

    cursor = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    assert safe_tool_value({"nextCursor": cursor})["nextCursor"] != cursor


@pytest.mark.parametrize("payload", [
    {"hash": "0123456789abcdef" * 4, "at": "2026-10-19T04:03:04.123456Z",
     "id": "11111111-1111-4111-8111-111111111111"},
    {"v": "pc", "at": "2026-10-19T04:03:04.123456Z", "id": "42", "q": []},
], ids=["paper-facts", "keyset"])
@pytest.mark.parametrize("tamper", [None, "credential-suffix", "whitespace", "extra-padding"])
def test_cursor_projection_accepts_only_exact_padded_or_unpadded_base64(payload, tamper):
    from gateway.platforms.api_server_tool_payloads import safe_tool_value

    cursor = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    assert cursor.endswith("=")
    if tamper is None:
        unpadded = cursor.rstrip("=")
        assert safe_tool_value({"cursor": cursor, "nextCursor": unpadded}) == {
            "cursor": cursor, "nextCursor": unpadded,
        }
        return
    secret = "sk-proj-testonly1234567890testonly1234567890"
    if tamper == "credential-suffix":
        invalid = cursor + secret
    elif tamper == "whitespace":
        invalid = cursor[:20] + " " + cursor[20:]
    else:
        invalid = cursor + "="
    result = safe_tool_value({"nextCursor": invalid})["nextCursor"]
    assert result != invalid
    assert secret not in result
