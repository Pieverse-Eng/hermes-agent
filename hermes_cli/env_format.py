"""Shared decoding and encoding for hosted literal environment files.

Ordinary profiles keep their existing dotenv parsers. Literal profiles use
the same format at startup, during credential reads, and when saving values.
"""

from __future__ import annotations

import json
import os
import re


def literal_env_values_enabled() -> bool:
    """Whether the launcher selected the hosted, opaque-value format."""
    return os.environ.get("HERMES_ENV_LITERAL_VALUES") == "1"


def _validate_literal_value(value: str) -> None:
    if not isinstance(value, str) or "\0" in value:
        raise ValueError("Invalid literal environment value")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Invalid literal environment value") from None


def parse_literal_env(text: str) -> dict[str, str]:
    """Decode KEY=JSON-string assignments without changing any environment.

    Unquoted values remain supported verbatim. Only physical LF/CRLF record
    boundaries split assignments: Unicode separators inside a JSON string
    are value data. Validate the entire file before callers install values.
    """
    values: dict[str, str] = {}
    for line in text.split("\n"):
        line = line.removesuffix("\r").lstrip(" \t")
        if not line.strip() or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        if not separator or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
            raise ValueError("Malformed literal environment assignment")
        value = json.loads(raw) if raw.startswith('"') else raw
        _validate_literal_value(value)
        values[key] = value
    return values


def quote_literal_env_value(value: str) -> str:
    """Encode one opaque UTF-8 value for an exact read/write round trip."""
    _validate_literal_value(value)
    return json.dumps(value, ensure_ascii=False)
