"""Channel Gateway-managed WhatsApp adapter for hosted Hermes runtimes.

This adapter deliberately contains no Meta Cloud API or WhatsApp Web logic.
Channel Gateway owns Meta webhook verification, pairing, deduplication, and
Graph API credentials. Hermes receives a versioned internal event over an
authenticated in-cluster webhook and sends replies through a tenant-scoped
Channel Gateway endpoint.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import math
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import quote

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

logger = logging.getLogger(__name__)

PLATFORM_NAME = "whatsapp_gateway"
DEFAULT_WEBHOOK_HOST = "0.0.0.0"
DEFAULT_WEBHOOK_PORT = 8788
DEFAULT_WEBHOOK_PATH = "/whatsapp/webhook"
DEFAULT_GATEWAY_URL = "http://channel-gateway.openclaw-system.svc"
TENANT_TOKEN_HEADER = "x-pieverse-channel-gateway-token"
MAX_WEBHOOK_BODY_BYTES = 64 * 1024
MAX_TEXT_LENGTH = 4000
MAX_TIMESTAMP_MS = 253_402_300_799_000
MAX_SEEN_MESSAGE_IDS = 10_000
MAX_CHUNK_SEND_ATTEMPTS = 3
SAFE_RETRY_DELAYS_SECONDS = (0.25, 0.75)


def _extra_string(config: PlatformConfig, key: str, default: str = "") -> str:
    value = config.extra.get(key, default)
    return str(value).strip() if value is not None else default


def _resolve_tenant_token(config: PlatformConfig) -> str:
    return (
        str(config.token or "").strip()
        or os.getenv("CHANNEL_GATEWAY_TENANT_TOKEN", "").strip()
    )


def _resolve_instance_id(config: PlatformConfig) -> str:
    return _extra_string(config, "instance_id") or os.getenv("INSTANCE_ID", "").strip()


def _normalize_gateway_url(value: str) -> str:
    return value.strip().rstrip("/")


def validate_config(config: PlatformConfig) -> bool:
    """Require only the per-instance bridge identity, never Meta credentials."""
    return bool(
        _resolve_tenant_token(config)
        and _resolve_instance_id(config)
        and _normalize_gateway_url(
            _extra_string(config, "gateway_url")
            or os.getenv("CHANNEL_GATEWAY_URL", "")
            or DEFAULT_GATEWAY_URL
        )
    )


def check_requirements() -> bool:
    try:
        import aiohttp  # noqa: F401

        return True
    except ImportError:
        return False


def _parse_envelope(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    if (
        value.get("version") != 1
        or value.get("channel") != "whatsapp"
        or value.get("event") != "message"
    ):
        return None
    message = value.get("message")
    if not isinstance(message, dict):
        return None
    if not all(
        isinstance(message.get(key), str)
        for key in ("id", "chatId", "senderId", "type")
    ):
        return None
    if message["type"] not in {"text", "unsupported"}:
        return None
    if message["type"] == "text" and not isinstance(message.get("text"), str):
        return None
    timestamp_ms = message.get("timestampMs")
    if timestamp_ms is not None and (
        isinstance(timestamp_ms, bool)
        or not isinstance(timestamp_ms, (int, float))
        or not math.isfinite(timestamp_ms)
        or timestamp_ms < 0
        or timestamp_ms > MAX_TIMESTAMP_MS
    ):
        return None
    return value


def _split_text(content: str) -> list[str]:
    text = str(content or "").strip()
    if not text:
        return []
    chunks: list[str] = []
    while text:
        if len(text) <= MAX_TEXT_LENGTH:
            chunks.append(text)
            break
        newline = text.rfind("\n", 0, MAX_TEXT_LENGTH)
        space = text.rfind(" ", 0, MAX_TEXT_LENGTH)
        cut = max(newline, space)
        if cut < MAX_TEXT_LENGTH // 2:
            cut = MAX_TEXT_LENGTH
        chunks.append(text[:cut].rstrip())
        text = text[cut:].lstrip()
    return chunks


def _parse_gateway_error_body(body: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


class WhatsAppGatewayAdapter(BasePlatformAdapter):
    """Authenticated bridge between Hermes and Channel Gateway."""

    splits_long_messages = True

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform(PLATFORM_NAME))
        self._host = _extra_string(config, "webhook_host", DEFAULT_WEBHOOK_HOST)
        self._port = int(
            _extra_string(config, "webhook_port", str(DEFAULT_WEBHOOK_PORT))
        )
        path = _extra_string(config, "webhook_path", DEFAULT_WEBHOOK_PATH)
        self._path = path if path.startswith("/") else f"/{path}"
        self._gateway_url = _normalize_gateway_url(
            _extra_string(config, "gateway_url")
            or os.getenv("CHANNEL_GATEWAY_URL", "")
            or DEFAULT_GATEWAY_URL
        )
        self._instance_id = _resolve_instance_id(config)
        self._tenant_token = _resolve_tenant_token(config)
        self._runner = None
        self._site = None
        self._client = None
        self._seen_message_ids: dict[str, None] = {}

    @property
    def authorization_is_upstream(self) -> bool:
        """Pairing and sender authorization were enforced by Channel Gateway."""
        return True

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        del is_reconnect
        if not validate_config(self.config):
            logger.error(
                "[whatsapp_gateway] missing instance id, gateway URL, or tenant token"
            )
            return False

        from aiohttp import ClientSession, ClientTimeout, web

        if self._runner is not None:
            return True

        self._client = ClientSession(timeout=ClientTimeout(total=10))
        app = web.Application(client_max_size=MAX_WEBHOOK_BODY_BYTES)
        app.router.add_post(self._path, self._handle_webhook)
        app.router.add_get("/", self._handle_health)
        app.router.add_get(f"{self._path}/health", self._handle_health)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        await self._site.start()
        self._mark_connected()
        logger.info(
            "[whatsapp_gateway] listening on %s:%s%s",
            self._host,
            self._port,
            self._path,
        )
        return True

    async def disconnect(self) -> None:
        self._mark_disconnected()
        if self._site is not None:
            await self._site.stop()
            self._site = None
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def _handle_health(self, _request):
        from aiohttp import web

        return web.json_response({"ok": True, "platform": PLATFORM_NAME})

    async def _handle_webhook(self, request):
        from aiohttp import web

        received_token = request.headers.get(TENANT_TOKEN_HEADER, "")
        if not self._tenant_token or not hmac.compare_digest(
            received_token, self._tenant_token
        ):
            logger.warning(
                "[whatsapp_gateway] rejected unauthenticated gateway delivery"
            )
            return web.json_response({"ok": False}, status=401)

        if (
            request.content_length is not None
            and request.content_length > MAX_WEBHOOK_BODY_BYTES
        ):
            return web.json_response({"ok": False}, status=413)

        try:
            raw = await request.read()
            if len(raw) > MAX_WEBHOOK_BODY_BYTES:
                return web.json_response({"ok": False}, status=413)
            envelope = _parse_envelope(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            envelope = None

        if envelope is None:
            return web.json_response({"ok": False}, status=400)

        message = envelope["message"]
        message_id = message["id"]
        if message_id in self._seen_message_ids:
            return web.json_response({"ok": True, "duplicate": True})
        if len(self._seen_message_ids) >= MAX_SEEN_MESSAGE_IDS:
            self._seen_message_ids.pop(next(iter(self._seen_message_ids)))
        self._seen_message_ids[message_id] = None

        if message["type"] != "text" or not message.get("text"):
            return web.json_response({"ok": True, "ignored": True})

        timestamp = message.get("timestampMs")
        source = self.build_source(
            chat_id=message["chatId"],
            chat_name=message["chatId"],
            chat_type="dm",
            user_id=message["senderId"],
            user_name=message["senderId"],
            message_id=message["id"],
        )
        event = MessageEvent(
            text=message["text"],
            message_type=MessageType.TEXT,
            source=source,
            raw_message=envelope,
            message_id=message["id"],
            timestamp=(
                datetime.fromtimestamp(
                    timestamp / 1000,
                    tz=timezone.utc,
                )
                if isinstance(timestamp, (int, float))
                else datetime.now(timezone.utc)
            ),
            metadata={"central_gateway": True},
        )
        try:
            await self.handle_message(event)
        except BaseException:
            self._seen_message_ids.pop(message_id, None)
            raise
        return web.json_response({"ok": True})

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        del reply_to, metadata
        if self._client is None:
            return SendResult(
                success=False,
                error="WhatsApp Gateway client is not connected",
                retryable=False,
            )

        endpoint = (
            f"{self._gateway_url}/internal/tenants/"
            f"{quote(self._instance_id, safe='')}/whatsapp/send"
        )
        last_message_id = None
        for index, chunk in enumerate(_split_text(content), start=1):
            result = await self._send_chunk_with_retry(
                endpoint=endpoint,
                chat_id=str(chat_id),
                chunk=chunk,
                chunk_index=index,
            )
            if not result.success:
                # This adapter has already exhausted every retry that is safe
                # for the current chunk. Never ask Hermes Base to replay the
                # complete content from chunk one.
                result.retryable = False
                return result
            last_message_id = result.message_id
        return SendResult(success=True, message_id=last_message_id)

    async def _send_chunk_with_retry(
        self,
        *,
        endpoint: str,
        chat_id: str,
        chunk: str,
        chunk_index: int,
    ) -> SendResult:
        result = SendResult(success=False, error="WhatsApp chunk was not sent")
        for attempt in range(1, MAX_CHUNK_SEND_ATTEMPTS + 1):
            result = await self._send_chunk_once(
                endpoint=endpoint,
                chat_id=chat_id,
                chunk=chunk,
                chunk_index=chunk_index,
            )
            if result.success:
                return result
            if not result.retryable or attempt >= MAX_CHUNK_SEND_ATTEMPTS:
                result.retryable = False
                return result

            delay = SAFE_RETRY_DELAYS_SECONDS[attempt - 1]
            logger.warning(
                "[whatsapp_gateway] safe retry for chunk %d "
                "(attempt %d/%d in %.2fs): %s",
                chunk_index,
                attempt + 1,
                MAX_CHUNK_SEND_ATTEMPTS,
                delay,
                result.error,
            )
            await asyncio.sleep(delay)

        result.retryable = False
        return result

    async def _send_chunk_once(
        self,
        *,
        endpoint: str,
        chat_id: str,
        chunk: str,
        chunk_index: int,
    ) -> SendResult:
        import aiohttp

        try:
            async with self._client.post(
                endpoint,
                headers={
                    TENANT_TOKEN_HEADER: self._tenant_token,
                    "content-type": "application/json",
                },
                json={"chatId": chat_id, "text": chunk},
            ) as response:
                body = await response.text()
                if response.status >= 400:
                    error_body = _parse_gateway_error_body(body)
                    upstream_status = error_body.get("upstreamStatus")
                    permanent = error_body.get("permanent") is True
                    retryable = (
                        response.status >= 500
                        and not permanent
                        and isinstance(upstream_status, int)
                        and not isinstance(upstream_status, bool)
                        and upstream_status >= 500
                    )
                    return SendResult(
                        success=False,
                        error=(
                            f"Channel Gateway send failed ({response.status}): "
                            f"{body[:200]}"
                        ),
                        raw_response=error_body,
                        retryable=retryable,
                    )
        except (aiohttp.ClientConnectorError, aiohttp.ConnectionTimeoutError) as exc:
            # The connection was never established, so Channel Gateway could
            # not have forwarded this chunk to Meta.
            return SendResult(success=False, error=str(exc), retryable=True)
        except (
            aiohttp.SocketTimeoutError,
            aiohttp.ServerDisconnectedError,
            aiohttp.ClientPayloadError,
            TimeoutError,
        ) as exc:
            # Once a connection exists, timeout/disconnect errors leave the
            # Meta result unknown. Retrying could duplicate a delivered chunk.
            return SendResult(success=False, error=str(exc), retryable=False)
        except Exception as exc:
            # Unknown transport failures are fail-closed for delivery: prefer
            # a missing reply over a duplicate WhatsApp message.
            logger.warning("[whatsapp_gateway] outbound send failed: %s", exc)
            return SendResult(success=False, error=str(exc), retryable=False)

        return SendResult(
            success=True,
            message_id=f"gateway-{int(time.time() * 1000)}-{chunk_index}",
        )

    async def _send_with_retry(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Any = None,
        max_retries: int = 2,
        base_delay: float = 2.0,
    ) -> SendResult:
        """Use only the chunk-scoped retry policy implemented by ``send``."""
        del max_retries, base_delay
        return await self.send(
            chat_id=chat_id,
            content=content,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"id": str(chat_id), "name": str(chat_id), "type": "dm"}


def _build_adapter(config: PlatformConfig) -> WhatsAppGatewayAdapter:
    return WhatsAppGatewayAdapter(config)


def _is_connected(config: PlatformConfig) -> bool:
    return validate_config(config)


def register(ctx) -> None:
    ctx.register_platform(
        name=PLATFORM_NAME,
        label="WhatsApp (Channel Gateway-managed)",
        adapter_factory=_build_adapter,
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=_is_connected,
        required_env=[],
        install_hint="pip install aiohttp",
        max_message_length=MAX_TEXT_LENGTH,
        emoji="💬",
        pii_safe=True,
        allow_update_command=False,
    )
