"""Tests for LINE platform integration."""

import asyncio
import base64
import hashlib
import hmac
import os
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
pytest.importorskip("aiohttp")
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import GatewayConfig, Platform, PlatformConfig, _apply_env_overrides
from gateway.platforms.line import LineAdapter
from gateway.platforms.base import MessageType


def _signature(secret: str, body: bytes) -> str:
    return base64.b64encode(hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()).decode("ascii")


def _create_app(adapter: LineAdapter) -> web.Application:
    app = web.Application()
    app.router.add_get("/health", adapter._health)
    app.router.add_post(adapter._path, adapter._handle_webhook)
    return app


class TestLineConfig:
    def test_line_platform_enum_exists(self):
        assert Platform.LINE.value == "line"

    def test_env_overrides_create_line_config(self):
        config = GatewayConfig()
        env = {
            "LINE_CHANNEL_ACCESS_TOKEN": "line-token",
            "LINE_CHANNEL_SECRET": "line-secret",
            "LINE_API_BASE_URL": "http://channel-gateway/line",
            "LINE_WEBHOOK_HOST": "0.0.0.0",
            "LINE_WEBHOOK_PORT": "18789",
            "LINE_WEBHOOK_PATH": "/line/webhook",
            "LINE_HOME_CHANNEL": "Uhome",
        }

        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        pc = config.platforms[Platform.LINE]
        assert pc.enabled is True
        assert pc.token == "line-token"
        assert pc.extra["channel_secret"] == "line-secret"
        assert pc.extra["api_base_url"] == "http://channel-gateway/line"
        assert pc.extra["webhook_port"] == 18789
        assert pc.home_channel.chat_id == "Uhome"

    def test_connected_platforms_requires_token_and_secret(self):
        missing_secret = GatewayConfig(
            platforms={Platform.LINE: PlatformConfig(enabled=True, token="line-token")}
        )
        configured = GatewayConfig(
            platforms={
                Platform.LINE: PlatformConfig(
                    enabled=True,
                    token="line-token",
                    extra={"channel_secret": "line-secret"},
                )
            }
        )

        assert Platform.LINE not in missing_secret.get_connected_platforms()
        assert Platform.LINE in configured.get_connected_platforms()


class TestLineAdapter:
    def test_verify_signature_accepts_valid_line_hmac(self):
        adapter = LineAdapter(
            PlatformConfig(enabled=True, token="line-token", extra={"channel_secret": "line-secret"})
        )
        body = b'{"events":[]}'

        assert adapter._verify_signature(_signature("line-secret", body), body) is True
        assert adapter._verify_signature(_signature("wrong-secret", body), body) is False

    def test_message_event_from_text_webhook_event(self):
        adapter = LineAdapter(
            PlatformConfig(enabled=True, token="line-token", extra={"channel_secret": "line-secret"})
        )

        event = adapter._to_message_event(
            {
                "type": "message",
                "webhookEventId": "evt-1",
                "source": {"type": "user", "userId": "U123"},
                "message": {"id": "msg-1", "type": "text", "text": "hello"},
            }
        )

        assert event is not None
        assert event.text == "hello"
        assert event.message_type == MessageType.TEXT
        assert event.source.platform == Platform.LINE
        assert event.source.chat_id == "U123"
        assert event.source.user_id == "U123"
        assert event.message_id == "msg-1"

    def test_group_message_is_ignored_with_log(self, caplog):
        adapter = LineAdapter(
            PlatformConfig(enabled=True, token="line-token", extra={"channel_secret": "line-secret"})
        )

        with caplog.at_level(logging.INFO):
            event = adapter._to_message_event(
                {
                    "type": "message",
                    "webhookEventId": "evt-group",
                    "source": {"type": "group", "groupId": "G123"},
                    "message": {"id": "msg-1", "type": "text", "text": "hello"},
                }
            )

        assert event is None
        assert any("without direct user context" in record.message for record in caplog.records)

    @pytest.mark.asyncio
    async def test_webhook_http_signature_smoke(self):
        adapter = LineAdapter(
            PlatformConfig(enabled=True, token="line-token", extra={"channel_secret": "line-secret"})
        )
        captured = []

        async def _capture(event):
            captured.append(event)

        adapter.handle_message = _capture
        body = json.dumps(
            {
                "events": [
                    {
                        "type": "message",
                        "webhookEventId": "evt-1",
                        "source": {"type": "user", "userId": "U123"},
                        "message": {"id": "msg-1", "type": "text", "text": "hello"},
                    }
                ]
            }
        ).encode("utf-8")

        async with TestClient(TestServer(_create_app(adapter))) as cli:
            bad = await cli.post(
                "/line/webhook",
                data=body,
                headers={"Content-Type": "application/json", "x-line-signature": "bad-signature"},
            )
            assert bad.status == 401

            good = await cli.post(
                "/line/webhook",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "x-line-signature": _signature("line-secret", body),
                },
            )
            assert good.status == 200
            assert await good.json() == {"ok": True}

        assert len(captured) == 1
        assert captured[0].text == "hello"

    @pytest.mark.asyncio
    async def test_send_smoke_uses_fake_line_api_server(self):
        pushed = []

        async def _push(request):
            pushed.append(
                {
                    "authorization": request.headers.get("Authorization"),
                    "json": await request.json(),
                }
            )
            return web.json_response({"sentMessages": [{"id": "msg-out"}]})

        app = web.Application()
        app.router.add_post("/line/v2/bot/message/push", _push)

        async with TestClient(TestServer(app)) as cli:
            adapter = LineAdapter(
                PlatformConfig(
                    enabled=True,
                    token="line-token",
                    extra={
                        "channel_secret": "line-secret",
                        "api_base_url": str(cli.make_url("/line")).rstrip("/"),
                    },
                )
            )
            adapter._client = httpx.AsyncClient(timeout=30.0)

            try:
                result = await adapter.send("U123", "hello")
            finally:
                await adapter._client.aclose()
                adapter._client = None

        assert result.success is True
        assert result.message_id == "msg-out"
        assert pushed == [
            {
                "authorization": "Bearer line-token",
                "json": {"to": "U123", "messages": [{"type": "text", "text": "hello"}]},
            }
        ]

    @pytest.mark.asyncio
    async def test_send_uses_configured_line_api_base_url(self):
        adapter = LineAdapter(
            PlatformConfig(
                enabled=True,
                token="line-token",
                extra={
                    "channel_secret": "line-secret",
                    "api_base_url": "http://channel-gateway/line",
                },
            )
        )
        calls = []

        class FakeClient:
            async def post(self, url, headers=None, json=None):
                calls.append({"url": url, "headers": headers, "json": json})
                return SimpleNamespace(
                    status_code=200,
                    content=b"{}",
                    json=lambda: {"sentMessages": [{"id": "msg-out"}]},
                )

        adapter._client = FakeClient()

        result = await adapter.send("U123", "hello")

        assert result.success is True
        assert result.message_id == "msg-out"
        assert calls[0]["url"] == "http://channel-gateway/line/v2/bot/message/push"
        assert calls[0]["headers"]["Authorization"] == "Bearer line-token"
        assert calls[0]["json"] == {"to": "U123", "messages": [{"type": "text", "text": "hello"}]}


class TestLineAuthorization:
    def test_line_allowed_users_authorizes_sender(self):
        from gateway.run import GatewayRunner

        gw = GatewayRunner.__new__(GatewayRunner)
        gw.config = GatewayConfig()
        gw.pairing_store = MagicMock()
        gw.pairing_store.is_approved.return_value = False

        source = SimpleNamespace(
            platform=Platform.LINE,
            chat_id="U123",
            chat_type="dm",
            user_id="U123",
            user_name="U123",
        )

        with patch.dict(os.environ, {"LINE_ALLOWED_USERS": "U123"}, clear=True):
            assert gw._is_user_authorized(source) is True


class TestLineSendMessage:
    def test_line_routes_via_sender(self):
        from tools.send_message_tool import _send_to_platform

        send = AsyncMock(return_value={"success": True, "platform": "line", "chat_id": "U123"})
        with patch("tools.send_message_tool._send_line", send):
            result = asyncio.run(
                _send_to_platform(
                    Platform.LINE,
                    SimpleNamespace(enabled=True, token="line-token", extra={}),
                    "U123",
                    "hello from hermes",
                )
            )

        assert result["success"] is True
        send.assert_awaited_once()
