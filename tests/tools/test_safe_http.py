"""Contract tests for the strict, address-pinned outbound HTTP boundary."""

from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

from tools.safe_http import (
    SafeHttpError,
    SafeHttpTransportResponse,
    safe_http_request,
)


PUBLIC_A = "93.184.216.34"
PUBLIC_B = "93.184.216.35"


def _resolver(mapping):
    def resolve(host: str, _port: int):
        return mapping[host]

    return resolve


def _ok_transport(
    calls=None, *, content=b"ok", content_type="application/octet-stream"
):
    def request(method, url, address, headers, data, timeout, max_bytes):
        if calls is not None:
            calls.append((
                method,
                url,
                address,
                dict(headers),
                data,
                timeout,
                max_bytes,
            ))
        return SafeHttpTransportResponse(
            200,
            {"content-type": content_type, "content-length": str(len(content))},
            content,
        )

    return request


@pytest.mark.parametrize(
    ("url", "answers", "code"),
    [
        ("https://private.example/data", ["10.0.0.8"], "ADDRESS_NOT_PUBLIC"),
        (
            "https://mixed.example/data",
            [PUBLIC_A, "192.168.1.8"],
            "ADDRESS_NOT_PUBLIC",
        ),
        ("https://[::1]/data", None, "ADDRESS_NOT_PUBLIC"),
        ("https://[64:ff9b::7f00:1]/data", None, "ADDRESS_NOT_PUBLIC"),
        ("https://224.0.0.1/data", None, "ADDRESS_NOT_PUBLIC"),
        ("https://192.0.0.9/data", None, "ADDRESS_NOT_PUBLIC"),
    ],
)
def test_rejects_non_public_or_mixed_destinations_before_transport(url, answers, code):
    calls = []
    resolver = (lambda _host, _port: answers) if answers is not None else None
    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            url,
            max_bytes=1024,
            resolver=resolver,
            transport=_ok_transport(calls),
        )
    assert excinfo.value.code == code
    assert calls == []


def test_rejects_metadata_hostname_before_dns_or_transport():
    called = False

    def should_not_run(*_args):
        nonlocal called
        called = True
        raise AssertionError("protected I/O must not start")

    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "https://metadata.google.internal/computeMetadata/v1/",
            max_bytes=1024,
            resolver=should_not_run,
            transport=should_not_run,
        )
    assert excinfo.value.code == "METADATA_HOST"
    assert called is False


def test_public_to_private_redirect_rejects_before_second_transport():
    calls = []

    def transport(method, url, address, headers, data, timeout, max_bytes):
        calls.append((url, address))
        return SafeHttpTransportResponse(
            302,
            {"location": "https://internal.example/secret"},
        )

    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "https://public.example/start",
            max_bytes=1024,
            resolver=_resolver({
                "public.example": [PUBLIC_A],
                "internal.example": ["169.254.169.254"],
            }),
            transport=transport,
        )
    assert excinfo.value.code == "ADDRESS_NOT_PUBLIC"
    assert calls == [("https://public.example/start", PUBLIC_A)]


def test_transport_receives_the_validated_address_for_each_hop():
    calls = []
    response = safe_http_request(
        "GET",
        "https://media.example/file",
        max_bytes=1024,
        resolver=_resolver({"media.example": [PUBLIC_B]}),
        transport=_ok_transport(calls),
    )
    assert response.content == b"ok"
    assert calls[0][2] == PUBLIC_B


def test_transport_falls_back_across_validated_public_addresses():
    calls = []

    def transport(method, url, address, headers, data, timeout, max_bytes):
        calls.append(address)
        if address == PUBLIC_A:
            raise SafeHttpError("REQUEST_FAILED", "first address unavailable")
        return SafeHttpTransportResponse(200, {}, b"ok")

    response = safe_http_request(
        "GET",
        "https://media.example/file",
        max_bytes=1024,
        resolver=_resolver({"media.example": [PUBLIC_A, PUBLIC_B]}),
        transport=transport,
    )
    assert response.content == b"ok"
    assert calls == [PUBLIC_A, PUBLIC_B]


def test_redirect_loop_and_limit_are_bounded():
    def loop_transport(method, url, address, headers, data, timeout, max_bytes):
        return SafeHttpTransportResponse(302, {"location": url})

    with pytest.raises(SafeHttpError) as loop_exc:
        safe_http_request(
            "GET",
            "https://loop.example/a",
            max_bytes=1024,
            resolver=_resolver({"loop.example": [PUBLIC_A]}),
            transport=loop_transport,
        )
    assert loop_exc.value.code == "REDIRECT_LOOP"

    def chain_transport(method, url, address, headers, data, timeout, max_bytes):
        next_path = "/b" if url.endswith("/a") else "/c"
        return SafeHttpTransportResponse(302, {"location": next_path})

    with pytest.raises(SafeHttpError) as limit_exc:
        safe_http_request(
            "GET",
            "https://chain.example/a",
            max_bytes=1024,
            max_redirects=1,
            resolver=_resolver({"chain.example": [PUBLIC_A]}),
            transport=chain_transport,
        )
    assert limit_exc.value.code == "TOO_MANY_REDIRECTS"


def test_deadline_expiry_after_dns_rejects_before_transport():
    calls = []

    def slow_resolver(_host, _port):
        time.sleep(0.2)
        return [PUBLIC_A]

    started = time.monotonic()
    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "https://slow.example/file",
            timeout=0.01,
            max_bytes=1024,
            resolver=slow_resolver,
            transport=_ok_transport(calls),
        )
    elapsed = time.monotonic() - started
    assert excinfo.value.code == "DEADLINE_EXCEEDED"
    assert elapsed < 0.1
    assert calls == []


@pytest.mark.parametrize(
    ("headers", "content", "allowed_types", "code"),
    [
        ({"content-length": "9"}, b"123456789", None, "RESPONSE_TOO_LARGE"),
        ({"content-length": "bogus"}, b"x", None, "CONTENT_LENGTH_INVALID"),
        (
            {"content-type": "text/html"},
            b"html",
            ("image/",),
            "CONTENT_TYPE_NOT_ALLOWED",
        ),
        (
            {"content-type": "image/png", "content-encoding": "gzip"},
            b"png",
            ("image/",),
            "CONTENT_ENCODING_NOT_ALLOWED",
        ),
    ],
)
def test_response_size_type_and_decompression_policy(
    headers, content, allowed_types, code
):
    def transport(*_args):
        return SafeHttpTransportResponse(200, headers, content)

    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "https://media.example/file",
            max_bytes=8,
            allowed_content_types=allowed_types,
            resolver=_resolver({"media.example": [PUBLIC_A]}),
            transport=transport,
        )
    assert excinfo.value.code == code


def test_sensitive_headers_are_removed_on_cross_host_redirect():
    calls = []

    def transport(method, url, address, headers, data, timeout, max_bytes):
        calls.append((url, {key.lower(): value for key, value in headers.items()}))
        if url.startswith("https://api.example"):
            return SafeHttpTransportResponse(
                302,
                {"location": "https://cdn.example/file"},
            )
        return SafeHttpTransportResponse(200, {"content-type": "image/png"}, b"png")

    safe_http_request(
        "GET",
        "https://api.example/start",
        headers={"Authorization": "Bearer secret", "X-Provider-Token": "secret-2"},
        sensitive_headers=("X-Provider-Token",),
        credential_hosts=("api.example",),
        max_bytes=1024,
        resolver=_resolver({"api.example": [PUBLIC_A], "cdn.example": [PUBLIC_B]}),
        transport=transport,
    )
    assert calls[0][1]["authorization"] == "Bearer secret"
    assert calls[0][1]["x-provider-token"] == "secret-2"
    assert "authorization" not in calls[1][1]
    assert "x-provider-token" not in calls[1][1]


def test_sensitive_headers_require_tls_before_transport():
    calls = []
    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "http://api.example/start",
            headers={"Authorization": "Bearer secret"},
            max_bytes=1024,
            resolver=_resolver({"api.example": [PUBLIC_A]}),
            transport=_ok_transport(calls),
        )
    assert excinfo.value.code == "SENSITIVE_HEADERS_REQUIRE_TLS"
    assert calls == []


def test_sensitive_headers_reject_an_unapproved_initial_host():
    calls = []
    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "https://attacker.example/file",
            headers={"Authorization": "Bearer secret"},
            credential_hosts=("files.slack.com",),
            max_bytes=1024,
            resolver=_resolver({"attacker.example": [PUBLIC_A]}),
            transport=_ok_transport(calls),
        )
    assert excinfo.value.code == "SENSITIVE_HEADERS_NOT_AUTHORIZED"
    assert calls == []


def test_sensitive_headers_are_removed_on_same_host_tls_downgrade():
    calls = []

    def transport(method, url, address, headers, data, timeout, max_bytes):
        calls.append((url, {key.lower(): value for key, value in headers.items()}))
        if url.startswith("https://"):
            return SafeHttpTransportResponse(
                302, {"location": "http://api.example/file"}
            )
        return SafeHttpTransportResponse(200, {}, b"ok")

    safe_http_request(
        "GET",
        "https://api.example/start",
        headers={"Authorization": "Bearer secret"},
        max_bytes=1024,
        resolver=_resolver({"api.example": [PUBLIC_A]}),
        transport=transport,
    )
    assert "authorization" in calls[0][1]
    assert "authorization" not in calls[1][1]


def test_caller_cannot_override_validated_host_header():
    calls = []
    with pytest.raises(SafeHttpError) as excinfo:
        safe_http_request(
            "GET",
            "https://public.example/file",
            headers={"Host": "internal.example"},
            max_bytes=1024,
            resolver=_resolver({"public.example": [PUBLIC_A]}),
            transport=_ok_transport(calls),
        )
    assert excinfo.value.code == "HOST_HEADER_NOT_ALLOWED"
    assert calls == []


def test_proxy_transport_uses_validated_ip_with_original_host_and_sni(monkeypatch):
    seen = {}

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "image/png", "content-length": "3"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_raw(self):
            yield b"png"

    class FakeClient:
        def __init__(self, **kwargs):
            seen["client"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def stream(self, method, url, **kwargs):
            seen["request"] = (method, str(url), kwargs)
            return FakeResponse()

    monkeypatch.setattr("httpx.Client", FakeClient)
    response = safe_http_request(
        "GET",
        "https://media.example/file",
        proxy_url="http://proxy.example:8080",
        max_bytes=1024,
        resolver=_resolver({"media.example": [PUBLIC_B]}),
    )

    assert response.content == b"png"
    method, pinned_url, kwargs = seen["request"]
    assert method == "GET"
    assert pinned_url == f"https://{PUBLIC_B}:443/file"
    assert kwargs["headers"]["Host"] == "media.example"
    assert kwargs["extensions"] == {"sni_hostname": "media.example"}


def test_qq_put_host_allowlist_and_redirect_method_policy():
    calls = []
    resolver = _resolver({
        "bucket.cos.ap-shanghai.myqcloud.com": [PUBLIC_A],
        "next.cos.ap-shanghai.myqcloud.com": [PUBLIC_B],
        "attacker.example": [PUBLIC_A],
    })

    with pytest.raises(SafeHttpError) as host_exc:
        safe_http_request(
            "PUT",
            "https://attacker.example/upload",
            data=b"part",
            max_bytes=1024,
            allowed_host_suffixes=("myqcloud.com",),
            resolver=resolver,
            transport=_ok_transport(calls),
        )
    assert host_exc.value.code == "HOST_NOT_ALLOWED"
    assert calls == []

    def unsafe_redirect(method, url, address, headers, data, timeout, max_bytes):
        return SafeHttpTransportResponse(
            302,
            {"location": "https://next.cos.ap-shanghai.myqcloud.com/upload"},
        )

    with pytest.raises(SafeHttpError) as method_exc:
        safe_http_request(
            "PUT",
            "https://bucket.cos.ap-shanghai.myqcloud.com/upload",
            data=b"part",
            max_bytes=1024,
            allowed_host_suffixes=("myqcloud.com",),
            resolver=resolver,
            transport=unsafe_redirect,
        )
    assert method_exc.value.code == "UNSAFE_METHOD_REDIRECT"

    calls.clear()

    def safe_redirect(method, url, address, headers, data, timeout, max_bytes):
        calls.append((method, url, address, data))
        if "bucket." in url:
            return SafeHttpTransportResponse(
                307,
                {"location": "https://next.cos.ap-shanghai.myqcloud.com/upload"},
            )
        return SafeHttpTransportResponse(200, {}, b"")

    response = safe_http_request(
        "PUT",
        "https://bucket.cos.ap-shanghai.myqcloud.com/upload",
        data=b"part",
        max_bytes=1024,
        allowed_host_suffixes=("myqcloud.com",),
        resolver=resolver,
        transport=safe_redirect,
    )
    assert response.status_code == 200
    assert calls == [
        (
            "PUT",
            "https://bucket.cos.ap-shanghai.myqcloud.com/upload",
            PUBLIC_A,
            b"part",
        ),
        (
            "PUT",
            "https://next.cos.ap-shanghai.myqcloud.com/upload",
            PUBLIC_B,
            b"part",
        ),
    ]


def _function_calls(path: str, function_name: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    ]
    assert len(matches) == 1, f"expected one {function_name} in {path}"
    calls = set()
    for node in ast.walk(matches[0]):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            calls.add(node.func.attr)
    return calls


@pytest.mark.parametrize(
    ("path", "function_name", "required_call"),
    [
        ("agent/image_gen_provider.py", "save_url_image", "safe_http_request"),
        (
            "plugins/image_gen/openai/__init__.py",
            "_load_image_bytes",
            "safe_http_request",
        ),
        (
            "gateway/platforms/base.py",
            "cache_image_from_url",
            "_safe_download_remote_media",
        ),
        (
            "gateway/platforms/base.py",
            "cache_audio_from_url",
            "_safe_download_remote_media",
        ),
        (
            "plugins/platforms/wecom/adapter.py",
            "_download_remote_bytes",
            "safe_http_request_async",
        ),
        (
            "plugins/platforms/feishu/adapter.py",
            "_download_remote_document",
            "safe_http_request_async",
        ),
        (
            "plugins/platforms/slack/adapter.py",
            "send_multiple_images",
            "safe_http_request_async",
        ),
        ("plugins/platforms/slack/adapter.py", "send_image", "safe_http_request_async"),
        (
            "plugins/platforms/slack/adapter.py",
            "_download_slack_file",
            "safe_http_request_async",
        ),
        (
            "plugins/platforms/slack/adapter.py",
            "_download_slack_file_bytes",
            "safe_http_request_async",
        ),
        (
            "plugins/platforms/discord/adapter.py",
            "send_multiple_images",
            "_safe_download_remote_media",
        ),
        (
            "plugins/platforms/discord/adapter.py",
            "send_image",
            "_safe_download_remote_media",
        ),
        (
            "plugins/platforms/discord/adapter.py",
            "send_animation",
            "_safe_download_remote_media",
        ),
        (
            "plugins/platforms/discord/adapter.py",
            "_cache_discord_document",
            "_safe_download_remote_media",
        ),
        (
            "gateway/platforms/qqbot/chunked_upload.py",
            "_put_to_presigned_url",
            "_safe_request",
        ),
    ],
)
def test_cited_remote_path_uses_shared_boundary(path, function_name, required_call):
    assert required_call in _function_calls(path, function_name)


def test_qq_default_upload_path_binds_shared_safe_request():
    source = Path("gateway/platforms/qqbot/chunked_upload.py").read_text(
        encoding="utf-8"
    )
    assert "from tools.safe_http import safe_http_request_async" in source
