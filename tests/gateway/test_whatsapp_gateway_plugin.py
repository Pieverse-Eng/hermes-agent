"""Contract tests for the Hermes WhatsApp Gateway plugin."""

from __future__ import annotations

import asyncio
import importlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import SendResult
from tests.gateway._plugin_adapter_loader import load_plugin_adapter


_whatsapp_gateway = load_plugin_adapter("whatsapp_gateway")
_plugin_entrypoint = importlib.import_module("plugins.platforms.whatsapp_gateway")


def _config() -> PlatformConfig:
    return PlatformConfig(
        enabled=True,
        token="tenant-token",
        extra={
            "instance_id": "instance-123",
            "gateway_url": "http://channel-gateway.openclaw-system.svc",
            "webhook_port": 8788,
        },
    )


class _FakeResponse:
    def __init__(self, status: int, body: str | BaseException = '{"ok":true}'):
        self.status = status
        self._body = body

    async def text(self) -> str:
        if isinstance(self._body, BaseException):
            raise self._body
        return self._body


class _FakeRequestContext:
    def __init__(self, action):
        self._action = action

    async def __aenter__(self):
        if isinstance(self._action, BaseException):
            raise self._action
        return self._action

    async def __aexit__(self, _exc_type, _exc, _traceback):
        return False


class _ScriptedClient:
    def __init__(self, actions):
        self._actions = list(actions)
        self.calls = []

    def post(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        if not self._actions:
            raise AssertionError("Unexpected WhatsApp Gateway request")
        return _FakeRequestContext(self._actions.pop(0))


def _connector_error() -> aiohttp.ClientConnectorError:
    connection_key = SimpleNamespace(host="channel-gateway", port=80, ssl=False)
    return aiohttp.ClientConnectorError(
        connection_key,
        OSError(111, "connection refused"),
    )


def _adapter_with_client(actions):
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())
    adapter._client = _ScriptedClient(actions)
    return adapter


def test_dynamic_platform_identity_and_config_contract():
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())

    assert adapter.platform is Platform("whatsapp_gateway")
    assert adapter.authorization_is_upstream is True
    assert adapter._port == 8788
    assert _whatsapp_gateway.validate_config(_config()) is True
    assert _whatsapp_gateway.validate_config(PlatformConfig(enabled=True)) is False


def test_normalized_envelope_validation():
    valid = {
        "version": 1,
        "channel": "whatsapp",
        "event": "message",
        "message": {
            "id": "wamid.1",
            "chatId": "15551234567",
            "senderId": "15551234567",
            "type": "text",
            "text": "hello",
            "timestampMs": 1_700_000_000_000,
        },
    }

    assert _whatsapp_gateway._parse_envelope(valid) == valid
    assert _whatsapp_gateway._parse_envelope({**valid, "version": 2}) is None
    assert (
        _whatsapp_gateway._parse_envelope({
            **valid,
            "message": {**valid["message"], "timestampMs": float("inf")},
        })
        is None
    )
    assert (
        _whatsapp_gateway._parse_envelope({
            **valid,
            "message": {**valid["message"], "type": "text", "text": None},
        })
        is None
    )


def test_outbound_text_chunking_is_bounded():
    chunks = _whatsapp_gateway._split_text("x" * 8_100)

    assert "".join(chunks) == "x" * 8_100
    assert all(0 < len(chunk) <= _whatsapp_gateway.MAX_TEXT_LENGTH for chunk in chunks)


def test_registration_uses_plugin_platform_contract():
    ctx = MagicMock()

    assert _plugin_entrypoint.__all__ == ["register"]
    _plugin_entrypoint.register(ctx)

    ctx.register_platform.assert_called_once()
    kwargs = ctx.register_platform.call_args.kwargs
    assert kwargs["name"] == "whatsapp_gateway"
    assert kwargs["validate_config"](_config()) is True
    assert kwargs["is_connected"](_config()) is True
    assert kwargs["allow_update_command"] is False


@pytest.mark.asyncio
async def test_repeated_gateway_delivery_is_dispatched_once():
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())
    adapter.handle_message = AsyncMock()
    payload = {
        "version": 1,
        "channel": "whatsapp",
        "event": "message",
        "message": {
            "id": "wamid.duplicate",
            "chatId": "15551234567",
            "senderId": "15551234567",
            "type": "text",
            "text": "hello",
        },
    }

    request = MagicMock()
    request.headers = {_whatsapp_gateway.TENANT_TOKEN_HEADER: "tenant-token"}
    request.content_length = None
    request.read = AsyncMock(return_value=json.dumps(payload).encode())

    first = await adapter._handle_webhook(request)
    second = await adapter._handle_webhook(request)

    assert first.status == 200
    assert second.status == 200
    adapter.handle_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_gateway_delivery_can_be_retried():
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())
    adapter.handle_message = AsyncMock(
        side_effect=[RuntimeError("dispatch failed"), None],
    )
    payload = {
        "version": 1,
        "channel": "whatsapp",
        "event": "message",
        "message": {
            "id": "wamid.retryable",
            "chatId": "15551234567",
            "senderId": "15551234567",
            "type": "text",
            "text": "hello",
        },
    }

    request = MagicMock()
    request.headers = {_whatsapp_gateway.TENANT_TOKEN_HEADER: "tenant-token"}
    request.content_length = None
    request.read = AsyncMock(return_value=json.dumps(payload).encode())

    with pytest.raises(RuntimeError, match="dispatch failed"):
        await adapter._handle_webhook(request)

    retry = await adapter._handle_webhook(request)
    duplicate = await adapter._handle_webhook(request)

    assert retry.status == 200
    assert duplicate.status == 200
    assert adapter.handle_message.await_count == 2


@pytest.mark.asyncio
async def test_repeated_gateway_delivery_waits_for_in_flight_dispatch():
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())
    dispatch_started = asyncio.Event()
    release_dispatch = asyncio.Event()

    async def handle_message(_event):
        dispatch_started.set()
        await release_dispatch.wait()

    adapter.handle_message = AsyncMock(side_effect=handle_message)
    payload = {
        "version": 1,
        "channel": "whatsapp",
        "event": "message",
        "message": {
            "id": "wamid.in-flight",
            "chatId": "15551234567",
            "senderId": "15551234567",
            "type": "text",
            "text": "hello",
        },
    }
    request = MagicMock()
    request.headers = {_whatsapp_gateway.TENANT_TOKEN_HEADER: "tenant-token"}
    request.content_length = None
    request.read = AsyncMock(return_value=json.dumps(payload).encode())

    first = asyncio.create_task(adapter._handle_webhook(request))
    await dispatch_started.wait()
    duplicate = asyncio.create_task(adapter._handle_webhook(request))
    await asyncio.sleep(0)

    assert first.done() is False
    assert duplicate.done() is False
    adapter.handle_message.assert_awaited_once()

    release_dispatch.set()
    first_response, duplicate_response = await asyncio.gather(first, duplicate)

    assert first_response.status == 200
    assert duplicate_response.status == 200
    adapter.handle_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_in_flight_failure_is_returned_to_every_duplicate_waiter():
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())
    dispatch_started = asyncio.Event()
    release_dispatch = asyncio.Event()

    async def handle_message(_event):
        dispatch_started.set()
        await release_dispatch.wait()
        raise RuntimeError("dispatch failed")

    adapter.handle_message = AsyncMock(side_effect=handle_message)
    payload = {
        "version": 1,
        "channel": "whatsapp",
        "event": "message",
        "message": {
            "id": "wamid.in-flight-failure",
            "chatId": "15551234567",
            "senderId": "15551234567",
            "type": "text",
            "text": "hello",
        },
    }
    request = MagicMock()
    request.headers = {_whatsapp_gateway.TENANT_TOKEN_HEADER: "tenant-token"}
    request.content_length = None
    request.read = AsyncMock(return_value=json.dumps(payload).encode())

    first = asyncio.create_task(adapter._handle_webhook(request))
    await dispatch_started.wait()
    duplicate = asyncio.create_task(adapter._handle_webhook(request))
    await asyncio.sleep(0)
    release_dispatch.set()

    results = await asyncio.gather(first, duplicate, return_exceptions=True)

    assert all(
        isinstance(result, RuntimeError) and str(result) == "dispatch failed"
        for result in results
    )
    adapter.handle_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_connect_error_retries_only_current_chunk(monkeypatch):
    adapter = _adapter_with_client([
        _connector_error(),
        _FakeResponse(200),
    ])
    sleep = AsyncMock()
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", sleep)

    result = await adapter.send("15551234567", "hello")

    assert result.success is True
    assert [call[1]["json"]["text"] for call in adapter._client.calls] == [
        "hello",
        "hello",
    ]
    sleep.assert_awaited_once()


@pytest.mark.asyncio
async def test_read_timeout_is_not_retried(monkeypatch):
    adapter = _adapter_with_client([
        _FakeResponse(200, aiohttp.SocketTimeoutError("read timed out")),
    ])
    sleep = AsyncMock()
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", sleep)

    result = await adapter.send("15551234567", "hello")

    assert result.success is False
    assert result.retryable is False
    assert len(adapter._client.calls) == 1
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_connect_errors_stop_after_three_current_chunk_attempts(monkeypatch):
    adapter = _adapter_with_client([
        _connector_error(),
        _connector_error(),
        _connector_error(),
    ])
    sleep = AsyncMock()
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", sleep)

    result = await adapter.send("15551234567", "hello")

    assert result.success is False
    assert result.retryable is False
    assert len(adapter._client.calls) == 3
    assert sleep.await_count == 2


@pytest.mark.asyncio
async def test_explicit_meta_503_retries_current_chunk(monkeypatch):
    adapter = _adapter_with_client([
        _FakeResponse(
            502,
            json.dumps({"upstreamStatus": 503, "permanent": False}),
        ),
        _FakeResponse(200),
    ])
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", AsyncMock())

    result = await adapter.send("15551234567", "hello")

    assert result.success is True
    assert len(adapter._client.calls) == 2


@pytest.mark.asyncio
async def test_gateway_transport_502_without_upstream_status_is_not_retried(
    monkeypatch,
):
    adapter = _adapter_with_client([
        _FakeResponse(
            502, json.dumps({"permanent": False, "error": "transport failure"})
        ),
    ])
    sleep = AsyncMock()
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", sleep)

    result = await adapter.send("15551234567", "hello")

    assert result.success is False
    assert result.retryable is False
    assert len(adapter._client.calls) == 1
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_second_chunk_connect_error_does_not_replay_first_chunk(monkeypatch):
    first_chunk = "a" * _whatsapp_gateway.MAX_TEXT_LENGTH
    second_chunk = "b" * 10
    adapter = _adapter_with_client([
        _FakeResponse(200),
        _connector_error(),
        _FakeResponse(200),
    ])
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", AsyncMock())

    result = await adapter.send("15551234567", first_chunk + second_chunk)

    assert result.success is True
    assert [call[1]["json"]["text"] for call in adapter._client.calls] == [
        first_chunk,
        second_chunk,
        second_chunk,
    ]


@pytest.mark.asyncio
async def test_unknown_second_chunk_result_stops_without_replaying_first(monkeypatch):
    first_chunk = "a" * _whatsapp_gateway.MAX_TEXT_LENGTH
    second_chunk = "b" * 10
    adapter = _adapter_with_client([
        _FakeResponse(200),
        aiohttp.ServerDisconnectedError("response disconnected"),
    ])
    sleep = AsyncMock()
    monkeypatch.setattr(_whatsapp_gateway.asyncio, "sleep", sleep)

    result = await adapter.send("15551234567", first_chunk + second_chunk)

    assert result.success is False
    assert result.retryable is False
    assert [call[1]["json"]["text"] for call in adapter._client.calls] == [
        first_chunk,
        second_chunk,
    ]
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_with_retry_bypasses_base_retries_and_fallbacks():
    adapter = _whatsapp_gateway.WhatsAppGatewayAdapter(_config())
    adapter.send = AsyncMock(
        return_value=SendResult(
            success=False,
            error="result unknown",
            retryable=True,
        )
    )

    result = await adapter._send_with_retry(
        "15551234567",
        "hello",
        max_retries=99,
        base_delay=0,
    )

    assert result.success is False
    adapter.send.assert_awaited_once_with(
        chat_id="15551234567",
        content="hello",
        reply_to=None,
        metadata=None,
    )
