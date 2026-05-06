"""LINE Messaging API platform adapter."""

import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional

import httpx

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult

logger = logging.getLogger(__name__)

DEFAULT_WEBHOOK_HOST = "0.0.0.0"
DEFAULT_WEBHOOK_PORT = 18789
DEFAULT_WEBHOOK_PATH = "/line/webhook"
DEFAULT_LINE_API_BASE_URL = "https://api.line.me"


def check_line_requirements() -> bool:
    """Check if LINE webhook dependencies are available."""
    return AIOHTTP_AVAILABLE


class LineAdapter(BasePlatformAdapter):
    """LINE Messaging API adapter using webhooks for inbound events."""

    MAX_MESSAGE_LENGTH = 5000

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.LINE)
        extra = config.extra or {}
        self._channel_access_token = (
            config.token
            or extra.get("channel_access_token")
            or os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
        )
        self._channel_secret = extra.get("channel_secret") or os.getenv("LINE_CHANNEL_SECRET", "")
        self._api_base_url = (
            extra.get("api_base_url")
            or os.getenv("LINE_API_BASE_URL")
            or DEFAULT_LINE_API_BASE_URL
        ).rstrip("/")
        self._host = extra.get("webhook_host") or os.getenv("LINE_WEBHOOK_HOST", DEFAULT_WEBHOOK_HOST)
        self._port = int(extra.get("webhook_port") or os.getenv("LINE_WEBHOOK_PORT", DEFAULT_WEBHOOK_PORT))
        self._path = extra.get("webhook_path") or os.getenv("LINE_WEBHOOK_PATH", DEFAULT_WEBHOOK_PATH)
        if not self._path.startswith("/"):
            self._path = f"/{self._path}"

        self._app: Optional["web.Application"] = None
        self._runner: Optional["web.AppRunner"] = None
        self._site: Optional["web.TCPSite"] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> bool:
        if not AIOHTTP_AVAILABLE:
            self._set_fatal_error("line_missing_aiohttp", "aiohttp is not installed", retryable=False)
            return False
        if not self._channel_access_token:
            self._set_fatal_error(
                "line_missing_token",
                "LINE_CHANNEL_ACCESS_TOKEN is required",
                retryable=False,
            )
            return False
        if not self._channel_secret:
            self._set_fatal_error(
                "line_missing_secret",
                "LINE_CHANNEL_SECRET is required",
                retryable=False,
            )
            return False

        try:
            self._client = httpx.AsyncClient(timeout=30.0)
            self._app = web.Application()
            self._app.router.add_get("/health", self._health)
            self._app.router.add_post(self._path, self._handle_webhook)
            self._runner = web.AppRunner(self._app)
            await self._runner.setup()
            self._site = web.TCPSite(self._runner, self._host, self._port)
            await self._site.start()
            self._mark_connected()
            logger.info("[%s] LINE webhook listening on %s:%s%s", self.name, self._host, self._port, self._path)
            return True
        except Exception as exc:
            await self.disconnect()
            self._set_fatal_error("line_webhook_start_failed", str(exc), retryable=True)
            return False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self._site = None
        self._app = None
        self._mark_disconnected()

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if not self._client:
            return SendResult(success=False, error="Not connected")

        chunks = self.truncate_message(content, self.MAX_MESSAGE_LENGTH)
        last_message_id = None
        for chunk in chunks:
            try:
                response = await self._client.post(
                    f"{self._api_base_url}/v2/bot/message/push",
                    headers={
                        "Authorization": f"Bearer {self._channel_access_token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "to": chat_id,
                        "messages": [{"type": "text", "text": chunk}],
                    },
                )
                if response.status_code >= 400:
                    return SendResult(
                        success=False,
                        error=f"LINE API error ({response.status_code}): {response.text}",
                    )
                data = response.json() if response.content else {}
                sent_messages = data.get("sentMessages") or []
                if sent_messages:
                    last_message_id = sent_messages[0].get("id")
            except httpx.ConnectError as exc:
                return SendResult(success=False, error=str(exc), retryable=True)
            except Exception as exc:
                return SendResult(success=False, error=str(exc))

        return SendResult(success=True, message_id=last_message_id)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        if not self._client:
            return
        try:
            await self._client.post(
                f"{self._api_base_url}/v2/bot/chat/loading/start",
                headers={
                    "Authorization": f"Bearer {self._channel_access_token}",
                    "Content-Type": "application/json",
                },
                json={"chatId": chat_id, "loadingSeconds": 5},
            )
        except Exception:
            pass

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"id": chat_id, "name": chat_id, "type": "dm"}

    async def _health(self, request: "web.Request") -> "web.Response":
        return web.json_response({"ok": True, "platform": "line"})

    async def _handle_webhook(self, request: "web.Request") -> "web.Response":
        body = await request.read()
        if not self._verify_signature(request.headers.get("x-line-signature", ""), body):
            return web.json_response({"ok": False, "error": "Invalid signature"}, status=401)

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

        for event in payload.get("events", []):
            message_event = self._to_message_event(event)
            if message_event:
                await self.handle_message(message_event)

        return web.json_response({"ok": True})

    def _verify_signature(self, signature: str, body: bytes) -> bool:
        if not signature:
            return False
        expected = base64.b64encode(
            hmac.new(self._channel_secret.encode("utf-8"), body, hashlib.sha256).digest()
        ).decode("ascii")
        return hmac.compare_digest(signature, expected)

    def _to_message_event(self, event: Dict[str, Any]) -> Optional[MessageEvent]:
        if event.get("type") != "message":
            return None

        source = event.get("source") or {}
        source_type = source.get("type", "user")
        user_id = source.get("userId")
        chat_id = self._chat_id_from_source(source)
        if source_type != "user":
            logger.info("[%s] Ignoring LINE %s message without direct user context", self.name, source_type)
            return None
        if not user_id or not chat_id:
            logger.info("[%s] Ignoring LINE message with incomplete user context", self.name)
            return None

        line_message = event.get("message") or {}
        message_type = line_message.get("type", "")
        text = line_message.get("text") if message_type == "text" else f"[LINE {message_type} message]"

        return MessageEvent(
            text=text,
            message_type=self._message_type(message_type),
            source=self.build_source(
                chat_id=chat_id,
                chat_name=chat_id,
                chat_type="dm" if source_type == "user" else "group",
                user_id=user_id,
                user_name=user_id,
            ),
            raw_message=event,
            message_id=line_message.get("id") or event.get("webhookEventId"),
        )

    @staticmethod
    def _chat_id_from_source(source: Dict[str, Any]) -> Optional[str]:
        source_type = source.get("type")
        if source_type == "user":
            return source.get("userId")
        if source_type == "group":
            return source.get("groupId")
        if source_type == "room":
            return source.get("roomId")
        return None

    @staticmethod
    def _message_type(line_type: str) -> MessageType:
        return {
            "text": MessageType.TEXT,
            "image": MessageType.PHOTO,
            "video": MessageType.VIDEO,
            "audio": MessageType.AUDIO,
            "file": MessageType.DOCUMENT,
            "sticker": MessageType.STICKER,
        }.get(line_type, MessageType.TEXT)
