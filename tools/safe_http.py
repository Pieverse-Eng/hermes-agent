"""Bounded, redirect-safe HTTP for untrusted remote URLs.

This module is the strict server-side network boundary for URLs supplied by
models, messaging providers, and provider API responses.  It deliberately does
not honor ``security.allow_private_urls``: these callers handle untrusted URLs
inside long-lived gateway/provider processes, where private-network access is
never required.

The default transport resolves every hop itself, rejects the entire answer set
if any address is non-public, and connects to one of those already-validated IP
addresses while retaining the original hostname for HTTP Host and TLS SNI / certificate
validation.  Redirects are manual so the same policy runs before every new
connection and sensitive headers can be stripped on an unapproved host.
"""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional, Sequence, cast
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog"})
_DEFAULT_SENSITIVE_HEADERS = frozenset({
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
})
_DENIED_SPECIAL_NETWORKS = (
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


class SafeHttpError(ValueError):
    """A fail-closed URL, destination, redirect, or response-policy error."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class SafeHttpTransportResponse:
    """One no-follow transport response, exposed for deterministic tests."""

    status_code: int
    headers: Mapping[str, str]
    content: bytes = b""


@dataclass(frozen=True)
class SafeHttpResponse:
    """Validated final response returned by :func:`safe_http_request`."""

    status_code: int
    headers: Mapping[str, str]
    content: bytes
    url: str
    redirects: int

    def raise_for_status(self) -> None:
        if 200 <= self.status_code < 300:
            return
        raise SafeHttpError(
            "HTTP_STATUS",
            f"HTTP {self.status_code} from {_safe_url_label(self.url)}",
        )


SafeHttpResolver = Callable[[str, int], Sequence[str]]
SafeHttpTransport = Callable[
    [str, str, str, Mapping[str, str], Optional[bytes], float, int],
    SafeHttpTransportResponse,
]


def _safe_url_label(url: str) -> str:
    """Return a query/credential-free URL label for logs and exceptions."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "<unknown>"
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or "/"
        return f"{parsed.scheme}://{host}{port}{path}"[:240]
    except Exception:
        return "<invalid URL>"


def _parse_url(url: str) -> tuple[SplitResult, str, int]:
    try:
        parsed = urlsplit(str(url).strip())
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise SafeHttpError("INVALID_URL", "Invalid HTTP URL") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise SafeHttpError("UNSUPPORTED_SCHEME", "Only HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise SafeHttpError("URL_CREDENTIALS", "Credentials in URLs are not allowed")

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise SafeHttpError("INVALID_URL", "URL hostname is required")
    if host in _METADATA_HOSTS:
        raise SafeHttpError("METADATA_HOST", "Cloud metadata host is not allowed")

    expected_port = 443 if scheme == "https" else 80
    effective_port = port or expected_port
    if effective_port != expected_port:
        raise SafeHttpError(
            "PORT_NOT_ALLOWED",
            f"Only the default {scheme.upper()} port is allowed",
        )
    return parsed, host, effective_port


def _normalized_host_set(values: Optional[Iterable[str]]) -> frozenset[str]:
    return frozenset(
        value.strip().lower().rstrip(".")
        for value in (values or ())
        if isinstance(value, str) and value.strip()
    )


def _host_allowed(
    host: str,
    *,
    allowed_hosts: Optional[Iterable[str]],
    allowed_host_suffixes: Optional[Iterable[str]],
) -> bool:
    exact = _normalized_host_set(allowed_hosts)
    suffixes = _normalized_host_set(allowed_host_suffixes)
    if not exact and not suffixes:
        return True
    if host in exact:
        return True
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)


def _public_ip(value: str) -> str:
    candidate = value.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise SafeHttpError(
            "DNS_INVALID_ADDRESS", "DNS returned an invalid IP address"
        ) from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        not address.is_global
        or address.is_reserved
        or address.is_multicast
        or any(address in network for network in _DENIED_SPECIAL_NETWORKS)
    ):
        raise SafeHttpError(
            "ADDRESS_NOT_PUBLIC", "Destination resolved to a non-public address"
        )
    return str(address)


def _default_resolver(host: str, port: int) -> Sequence[str]:
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SafeHttpError(
            "DNS_LOOKUP_FAILED", "Destination DNS lookup failed"
        ) from exc
    addresses: list[str] = []
    for _family, _socktype, _proto, _canonname, sockaddr in infos:
        value = str(sockaddr[0])
        if value not in addresses:
            addresses.append(value)
    return addresses


def _validated_addresses(
    host: str,
    port: int,
    resolver: SafeHttpResolver,
    timeout: float,
) -> list[str]:
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        results: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                results.put((True, resolver(host, port)))
            except BaseException as exc:  # propagate resolver failures to caller
                results.put((False, exc))

        # ``socket.getaddrinfo`` has no per-call timeout. A daemon thread keeps
        # the request deadline enforceable even if the system resolver stalls;
        # the transport cannot start until a result passes validation.
        threading.Thread(target=resolve, daemon=True).start()
        try:
            succeeded, value = results.get(timeout=max(timeout, 0.0))
        except queue.Empty as exc:
            raise SafeHttpError(
                "DEADLINE_EXCEEDED", "HTTP deadline exceeded during DNS lookup"
            ) from exc
        if not succeeded:
            if isinstance(value, SafeHttpError):
                raise value
            if isinstance(value, BaseException):
                raise SafeHttpError(
                    "DNS_LOOKUP_FAILED", "Destination DNS lookup failed"
                ) from value
            raise SafeHttpError("DNS_LOOKUP_FAILED", "Destination DNS lookup failed")
        raw_addresses = cast(Sequence[str], value)
    else:
        raw_addresses = [str(literal)]
    if not raw_addresses:
        raise SafeHttpError(
            "DNS_NO_RESULTS", "Destination DNS lookup returned no addresses"
        )
    # Validate every answer before selecting one.  A mixed public/private set
    # is rejected rather than letting answer ordering choose the policy.
    return [_public_ip(str(value)) for value in raw_addresses]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host=host, port=port, timeout=timeout)
        self._safe_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._safe_address, self.port),
            timeout=self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        context = ssl.create_default_context()
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            context=context,
        )
        self._safe_address = address
        self._safe_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._safe_address, self.port),
            timeout=self.timeout,
        )
        self.sock = self._safe_context.wrap_socket(
            raw_socket, server_hostname=self.host
        )


def _request_target(parsed: SplitResult) -> str:
    return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))


def _read_limited(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            break
    return b"".join(chunks)


def _default_transport(
    method: str,
    url: str,
    address: str,
    headers: Mapping[str, str],
    data: Optional[bytes],
    timeout: float,
    max_bytes: int,
) -> SafeHttpTransportResponse:
    parsed, host, port = _parse_url(url)
    connection_type = (
        _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    )
    connection = connection_type(host, address, port, timeout)
    request_headers = dict(headers)
    request_headers.setdefault("Connection", "close")
    try:
        connection.request(
            method,
            _request_target(parsed),
            body=data,
            headers=request_headers,
        )
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        if method == "HEAD" or response.status in _REDIRECT_STATUSES:
            content = b""
        else:
            content = _read_limited(response, max_bytes)
        return SafeHttpTransportResponse(response.status, response_headers, content)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise SafeHttpError("REQUEST_FAILED", "Validated HTTP request failed") from exc
    finally:
        connection.close()


def _proxy_transport(proxy_url: str) -> SafeHttpTransport:
    """Return a no-follow proxy transport.

    The target is still resolved and policy-checked locally on every hop.  The
    proxy is treated as explicitly configured transport infrastructure. The
    request URL itself uses the validated IP, while ``Host`` and TLS SNI retain
    the original hostname, so the proxy cannot perform a second target lookup.
    """

    def request(
        method: str,
        url: str,
        address: str,
        headers: Mapping[str, str],
        data: Optional[bytes],
        timeout: float,
        max_bytes: int,
    ) -> SafeHttpTransportResponse:
        try:
            import httpx

            parsed, host, port = _parse_url(url)
            pinned_host = f"[{address}]" if ":" in address else address
            pinned_url = urlunsplit(parsed._replace(netloc=f"{pinned_host}:{port}"))
            request_headers = dict(headers)
            request_headers["Host"] = f"[{host}]" if ":" in host else host

            with httpx.Client(
                proxy=proxy_url,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    method,
                    pinned_url,
                    headers=request_headers,
                    content=data,
                    extensions={"sni_hostname": host},
                ) as response:
                    response_headers = {
                        key.lower(): value for key, value in response.headers.items()
                    }
                    if method == "HEAD" or response.status_code in _REDIRECT_STATUSES:
                        content = b""
                    else:
                        chunks: list[bytes] = []
                        total = 0
                        for chunk in response.iter_raw():
                            chunks.append(chunk)
                            total += len(chunk)
                            if total > max_bytes:
                                break
                        content = b"".join(chunks)
                    return SafeHttpTransportResponse(
                        response.status_code,
                        response_headers,
                        content,
                    )
        except SafeHttpError:
            raise
        except Exception as exc:
            raise SafeHttpError(
                "REQUEST_FAILED", "Validated proxied request failed"
            ) from exc

    return request


def _content_type_allowed(value: str, allowed: Iterable[str]) -> bool:
    normalized = value.split(";", 1)[0].strip().lower()
    for entry in allowed:
        rule = entry.strip().lower()
        if not rule:
            continue
        if rule.endswith("/") and normalized.startswith(rule):
            return True
        if normalized == rule:
            return True
    return False


def _validate_final_response(
    response: SafeHttpTransportResponse,
    *,
    method: str,
    max_bytes: int,
    allowed_content_types: Optional[Iterable[str]],
    allow_missing_content_type: bool,
) -> None:
    headers = {key.lower(): value for key, value in response.headers.items()}
    content_length = headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise SafeHttpError(
                "CONTENT_LENGTH_INVALID", "Invalid Content-Length"
            ) from exc
        if declared < 0:
            raise SafeHttpError("CONTENT_LENGTH_INVALID", "Invalid Content-Length")
        if declared > max_bytes:
            raise SafeHttpError("RESPONSE_TOO_LARGE", "Response exceeds the byte limit")
    if len(response.content) > max_bytes:
        raise SafeHttpError("RESPONSE_TOO_LARGE", "Response exceeds the byte limit")
    if method == "HEAD" or not 200 <= response.status_code < 300:
        return
    encoding = headers.get("content-encoding", "").strip().lower()
    if encoding and encoding != "identity":
        raise SafeHttpError(
            "CONTENT_ENCODING_NOT_ALLOWED",
            "Compressed HTTP response bodies are not allowed",
        )
    if allowed_content_types is not None:
        content_type = headers.get("content-type", "")
        if not content_type and allow_missing_content_type:
            return
        if not content_type or not _content_type_allowed(
            content_type, allowed_content_types
        ):
            raise SafeHttpError(
                "CONTENT_TYPE_NOT_ALLOWED",
                "Response Content-Type is not allowed",
            )


def _canonical_url(
    parsed: SplitResult, host: str, port: int
) -> tuple[str, str, int, str, str]:
    return (parsed.scheme.lower(), host, port, parsed.path or "/", parsed.query)


def safe_http_request(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: float = 30.0,
    max_bytes: int,
    max_redirects: int = 5,
    allowed_content_types: Optional[Iterable[str]] = None,
    allow_missing_content_type: bool = False,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_host_suffixes: Optional[Iterable[str]] = None,
    credential_hosts: Optional[Iterable[str]] = None,
    sensitive_headers: Optional[Iterable[str]] = None,
    proxy_url: Optional[str] = None,
    resolver: Optional[SafeHttpResolver] = None,
    transport: Optional[SafeHttpTransport] = None,
) -> SafeHttpResponse:
    """Perform one strict, bounded HTTP request.

    ``transport`` and ``resolver`` are dependency-injection seams for tests;
    production callers use the DNS-pinned default transport.  Sensitive
    headers are allowed on the initial HTTPS host and stripped before any
    cross-host redirect unless ``credential_hosts`` explicitly authorizes the
    new host.
    """
    normalized_method = method.strip().upper()
    if normalized_method not in {"GET", "HEAD", "PUT"}:
        raise SafeHttpError("METHOD_NOT_ALLOWED", "Only GET, HEAD, and PUT are allowed")
    if timeout <= 0:
        raise SafeHttpError("INVALID_TIMEOUT", "Timeout must be positive")
    if max_bytes <= 0:
        raise SafeHttpError("INVALID_SIZE_LIMIT", "max_bytes must be positive")
    if max_redirects < 0:
        raise SafeHttpError(
            "INVALID_REDIRECT_LIMIT", "max_redirects cannot be negative"
        )

    initial_parsed, initial_host, _initial_port = _parse_url(url)
    base_headers = {str(key): str(value) for key, value in (headers or {}).items()}
    if any(key.lower() == "host" for key in base_headers):
        raise SafeHttpError(
            "HOST_HEADER_NOT_ALLOWED", "Caller-supplied Host is not allowed"
        )
    sensitive = _DEFAULT_SENSITIVE_HEADERS | _normalized_host_set(sensitive_headers)
    has_sensitive_headers = any(key.lower() in sensitive for key in base_headers)
    authorized_hosts = _normalized_host_set(credential_hosts)
    if has_sensitive_headers and not authorized_hosts:
        authorized_hosts = frozenset({initial_host})
    if has_sensitive_headers and initial_parsed.scheme.lower() != "https":
        raise SafeHttpError(
            "SENSITIVE_HEADERS_REQUIRE_TLS",
            "Sensitive headers may only be sent over HTTPS",
        )
    if has_sensitive_headers and initial_host not in authorized_hosts:
        raise SafeHttpError(
            "SENSITIVE_HEADERS_NOT_AUTHORIZED",
            "Initial destination is not authorized for sensitive headers",
        )

    request_transport = transport or (
        _proxy_transport(proxy_url) if proxy_url else _default_transport
    )
    request_resolver = resolver or _default_resolver
    deadline = time.monotonic() + timeout
    current_url = urlunsplit(initial_parsed._replace(fragment=""))
    current_method = normalized_method
    current_data = data
    redirects = 0
    visited: set[tuple[str, str, int, str, str]] = set()

    while True:
        parsed, host, port = _parse_url(current_url)
        if not _host_allowed(
            host,
            allowed_hosts=allowed_hosts,
            allowed_host_suffixes=allowed_host_suffixes,
        ):
            raise SafeHttpError(
                "HOST_NOT_ALLOWED", "Destination host is not allowlisted"
            )
        canonical = _canonical_url(parsed, host, port)
        if canonical in visited:
            raise SafeHttpError("REDIRECT_LOOP", "Redirect loop detected")
        visited.add(canonical)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeHttpError("DEADLINE_EXCEEDED", "HTTP deadline exceeded")
        addresses = _validated_addresses(host, port, request_resolver, remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeHttpError("DEADLINE_EXCEEDED", "HTTP deadline exceeded")

        hop_headers = {
            key: value
            for key, value in base_headers.items()
            if key.lower() not in sensitive
            or (parsed.scheme.lower() == "https" and host in authorized_hosts)
        }
        hop_headers.setdefault("Accept-Encoding", "identity")
        last_request_error: Optional[SafeHttpError] = None
        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SafeHttpError("DEADLINE_EXCEEDED", "HTTP deadline exceeded")
            try:
                raw = request_transport(
                    current_method,
                    current_url,
                    address,
                    hop_headers,
                    current_data,
                    remaining,
                    max_bytes,
                )
                break
            except SafeHttpError as exc:
                if exc.code != "REQUEST_FAILED":
                    raise
                last_request_error = exc
        else:
            assert last_request_error is not None
            raise last_request_error
        if time.monotonic() > deadline:
            raise SafeHttpError("DEADLINE_EXCEEDED", "HTTP deadline exceeded")

        response_headers = {key.lower(): value for key, value in raw.headers.items()}
        if raw.status_code in _REDIRECT_STATUSES:
            location = response_headers.get("location")
            if not location:
                raise SafeHttpError(
                    "REDIRECT_LOCATION_MISSING", "Redirect is missing Location"
                )
            if redirects >= max_redirects:
                raise SafeHttpError("TOO_MANY_REDIRECTS", "Redirect limit exceeded")
            if current_method not in {"GET", "HEAD"} and raw.status_code not in {
                307,
                308,
            }:
                raise SafeHttpError(
                    "UNSAFE_METHOD_REDIRECT",
                    "Only 307/308 redirects are allowed for upload requests",
                )
            current_url = urljoin(current_url, location)
            redirects += 1
            continue

        _validate_final_response(
            raw,
            method=current_method,
            max_bytes=max_bytes,
            allowed_content_types=allowed_content_types,
            allow_missing_content_type=allow_missing_content_type,
        )
        return SafeHttpResponse(
            status_code=raw.status_code,
            headers=response_headers,
            content=raw.content,
            url=current_url,
            redirects=redirects,
        )


async def safe_http_request_async(*args, **kwargs) -> SafeHttpResponse:
    """Async wrapper over the same strict implementation and policy."""
    timeout = float(kwargs.get("timeout", 30.0))
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(safe_http_request, *args, **kwargs),
            timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        raise SafeHttpError("DEADLINE_EXCEEDED", "HTTP deadline exceeded") from exc


__all__ = [
    "SafeHttpError",
    "SafeHttpResponse",
    "SafeHttpTransportResponse",
    "safe_http_request",
    "safe_http_request_async",
]
