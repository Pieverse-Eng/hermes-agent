import json

import pytest

from plugins import pieai


VALID_KEY = "sk-pv-" + ("a" * 48)


class _Response:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


def test_plain_key_message_rewrites_to_pieverse_byok_command():
    assert pieai._pre_gateway_dispatch(
        event=type("Event", (), {"text": VALID_KEY})()
    ) == {
        "action": "rewrite",
        "text": f"/pieverse-byok {VALID_KEY}",
    }


def test_unrelated_text_does_not_rewrite():
    assert (
        pieai._pre_gateway_dispatch(event=type("Event", (), {"text": "hello there"})())
        is None
    )
    assert (
        pieai._pre_gateway_dispatch(event=type("Event", (), {"text": "/new"})()) is None
    )


def test_invalid_key_returns_usage_without_network(monkeypatch):
    called = False

    def fake_save_key(_key):
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(pieai, "_save_key", fake_save_key)

    assert pieai._handle_pieverse_byok_sync("sk_abcd0123").startswith(
        "Usage: /pieverse-byok"
    )
    assert called is False


def test_command_calls_platform_api(monkeypatch):
    captured = {}
    monkeypatch.setenv("INSTANCE_ID", "00000000-0000-4000-8000-000000000001")
    monkeypatch.setenv("WALLET_API_URL", "http://api-server")
    monkeypatch.setenv("WALLET_API_TOKEN", "instance-token")

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["headers"] = dict(req.header_items())
        return _Response({"ok": True, "data": {"key": "sk-pv-aaaa...aaaa"}})

    monkeypatch.setattr(pieai.urllib.request, "urlopen", fake_urlopen)

    message = pieai._handle_pieverse_byok_sync(VALID_KEY)

    assert "Saved your Pieverse AI Gateway key (sk-pv-aaaa...aaaa)" in message
    assert captured["url"] == (
        "http://api-server/v1/instances/"
        "00000000-0000-4000-8000-000000000001/ai-gateway-key"
    )
    assert captured["timeout"] == 15
    assert captured["body"] == {"apiKey": VALID_KEY}
    assert captured["headers"]["Authorization"] == "Bearer instance-token"


def test_success_schedules_restart_when_platform_requires_it(monkeypatch):
    scheduled = []
    monkeypatch.setattr(
        pieai,
        "_save_key",
        lambda _key: {
            "ok": True,
            "data": {"key": "sk-pv-aaaa...aaaa", "restartRequired": True},
        },
    )
    monkeypatch.setattr(
        pieai, "_schedule_gateway_restart", lambda: scheduled.append(True)
    )

    message = pieai._handle_pieverse_byok_sync(VALID_KEY)

    assert scheduled == [True]
    assert "refreshing now" in message


def test_runtime_sync_pending_does_not_schedule_restart(monkeypatch):
    scheduled = []
    monkeypatch.setattr(
        pieai,
        "_save_key",
        lambda _key: {
            "ok": True,
            "data": {"key": "sk-pv-aaaa...aaaa", "runtimeSyncPending": True},
        },
    )
    monkeypatch.setattr(
        pieai, "_schedule_gateway_restart", lambda: scheduled.append(True)
    )

    message = pieai._handle_pieverse_byok_sync(VALID_KEY)

    assert scheduled == []
    assert "after the next runtime refresh" in message


def test_schedule_gateway_restart_waits_before_signalling(monkeypatch):
    calls = []

    class FakeTimer:
        daemon = False

        def __init__(self, delay, target):
            calls.append(("init", delay, target))

        def start(self):
            calls.append(("start", self.daemon))

    monkeypatch.setattr(pieai.threading, "Timer", FakeTimer)

    pieai._schedule_gateway_restart()

    assert calls[0][0] == "init"
    assert calls[0][1] == 5.0
    assert calls[1] == ("start", True)


def test_restart_gateway_from_pid_file(monkeypatch, tmp_path):
    killed = []
    home = tmp_path / "home"
    home.mkdir()
    (home / "gateway.pid").write_text(json.dumps({"pid": 1234}), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(pieai.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    pieai._restart_gateway_from_pid_file()

    assert killed == [(1234, pieai.signal.SIGUSR1)]


@pytest.mark.asyncio
async def test_async_handler_runs_sync_path(monkeypatch):
    monkeypatch.setattr(pieai, "_handle_pieverse_byok_sync", lambda raw: f"ok:{raw}")

    assert await pieai._handle_pieverse_byok("abc") == "ok:abc"


def test_register_uses_current_plugin_command_api():
    calls = {}

    class _Context:
        def register_hook(self, name, handler):
            calls["hook"] = (name, handler)

        def register_command(self, name, **kwargs):
            calls["command"] = (name, kwargs)

    pieai.register(_Context())

    assert calls["hook"] == ("pre_gateway_dispatch", pieai._pre_gateway_dispatch)
    assert calls["command"][0] == "pieverse-byok"
    assert calls["command"][1]["handler"] is pieai._handle_pieverse_byok
    assert calls["command"][1]["args_hint"] == "[sk-pv-key]"
    assert calls["command"][1]["platforms"] == ("telegram", "line", "slack")
