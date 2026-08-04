"""Tests for Telegram document-size cap."""

import sys
from unittest.mock import MagicMock

from gateway.config import PlatformConfig


def _ensure_telegram_mock():
    if "telegram" in sys.modules and hasattr(sys.modules["telegram"], "__file__"):
        return

    telegram_mod = MagicMock()
    telegram_mod.ext.ContextTypes.DEFAULT_TYPE = type(None)
    telegram_mod.constants.ParseMode.MARKDOWN_V2 = "MarkdownV2"
    telegram_mod.constants.ChatType.GROUP = "group"
    telegram_mod.constants.ChatType.SUPERGROUP = "supergroup"
    telegram_mod.constants.ChatType.CHANNEL = "channel"
    telegram_mod.constants.ChatType.PRIVATE = "private"

    for name in ("telegram", "telegram.ext", "telegram.constants", "telegram.request"):
        sys.modules.setdefault(name, telegram_mod)


_ensure_telegram_mock()

from plugins.platforms.telegram.adapter import TelegramAdapter  # noqa: E402


def test_max_doc_bytes_defaults_to_20mb_without_base_url():
    adapter = TelegramAdapter(PlatformConfig(enabled=True, token="***", extra={}))
    assert adapter._max_doc_bytes == 20 * 1024 * 1024


def test_max_doc_bytes_stays_at_20mb_for_custom_base_url_without_local_mode():
    adapter = TelegramAdapter(
        PlatformConfig(
            enabled=True,
            token="***",
            extra={"base_url": "http://localhost:8081/bot"},
        )
    )
    assert adapter._max_doc_bytes == 20 * 1024 * 1024


def test_max_doc_bytes_raised_to_2gb_for_local_bot_api_mode():
    adapter = TelegramAdapter(
        PlatformConfig(
            enabled=True,
            token="***",
            extra={
                "base_url": "http://localhost:8081/bot",
                "local_mode": True,
            },
        )
    )
    assert adapter._max_doc_bytes == 2 * 1024 * 1024 * 1024


def test_max_doc_bytes_local_mode_without_custom_base_url_keeps_default():
    adapter = TelegramAdapter(
        PlatformConfig(
            enabled=True,
            token="***",
            extra={"local_mode": True},
        )
    )
    assert adapter._max_doc_bytes == 20 * 1024 * 1024


def test_max_doc_bytes_empty_base_url_keeps_default():
    """An empty/falsy `base_url` should not flip the cap — only a real URL does."""
    adapter = TelegramAdapter(
        PlatformConfig(enabled=True, token="***", extra={"base_url": ""}),
    )
    assert adapter._max_doc_bytes == 20 * 1024 * 1024
