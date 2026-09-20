from __future__ import annotations

import http.client
from types import SimpleNamespace

import pytest

from gateway.adaptive_model import (
    AdaptiveResolutionError,
    AdaptiveScoringUnavailable,
    _adaptive_url,
    _post_json,
    build_adaptive_request,
    is_adaptive_model,
    resolve_adaptive_model,
)
from gateway.turn_context import TurnContext


class _MetadataStore:
    def __init__(self):
        self.values = {}

    def get_session_metadata(self, session_key, key, default=None):
        return self.values.get((session_key, key), default)

    def set_session_metadata(self, session_key, key, value):
        self.values[(session_key, key)] = value
        return True


def _ctx(**overrides):
    values = dict(
        message="Explain the failure",
        history=[
            {"role": "tool", "content": "secret raw output"},
            {"role": "user", "content": "u" * 9000},
            {"role": "assistant", "content": "prior answer"},
        ],
        context_prompt="system context",
        session_id="session-1",
        session_key="discord:1",
        event_message_id="event-9",
        run_generation=3,
        enabled_toolsets=["terminal"],
        native_modalities=("text", "image"),
    )
    values.update(overrides)
    return TurnContext(**values)


def test_request_projects_bounded_semantic_history_and_native_identity():
    request = build_adaptive_request(_ctx(), max_output_tokens=4096)

    assert request["taskId"] == "hermes:session-1:event-9"
    assert request["sessionId"] == "session-1"
    assert request["goal"] == "Explain the failure"
    assert request["history"] == [
        {"role": "user", "content": "u" * 8000},
        {"role": "assistant", "content": "prior answer"},
    ]
    assert request["modalities"] == ["text", "image"]
    assert request["requiresTools"] is True
    assert request["contextTokens"] > 0


def test_context_tokens_accounts_for_full_history_without_transmitting_tool_payloads():
    small = build_adaptive_request(_ctx(history=[]), max_output_tokens=4096)
    request = build_adaptive_request(
        _ctx(
            history=[
                {"role": "tool", "content": "x" * 100_000},
                *[
                    {"role": "user", "content": f"old-{index}"}
                    for index in range(20)
                ],
            ]
        ),
        max_output_tokens=4096,
    )

    assert len(request["history"]) == 12
    assert all(item["role"] == "user" for item in request["history"])
    assert "x" * 100 not in str(request["history"])
    assert 32_768 + 30_000 < request["contextTokens"] < 32_768 + 35_000
    assert request["contextTokens"] > small["contextTokens"] + 30_000


def test_context_tokens_estimates_ascii_and_multibyte_text_in_token_units():
    ascii_request = build_adaptive_request(
        _ctx(message="a" * 3000, history=[]), max_output_tokens=4096
    )
    multibyte_request = build_adaptive_request(
        _ctx(message="猫" * 1000, history=[]), max_output_tokens=4096
    )

    # Both inputs occupy 3,000 UTF-8 bytes, so the documented UTF-8/3
    # estimate should put them at the same scale above the native reserve.
    assert 33_760 <= ascii_request["contextTokens"] <= 33_800
    assert abs(ascii_request["contextTokens"] - multibyte_request["contextTokens"]) <= 4


def test_resolution_persists_request_before_network_and_replays_decision():
    store = _MetadataStore()
    calls = []

    def post(url, key, payload):
        assert (
            store.get_session_metadata("discord:1", "adaptive_model_task")["request"]
            == payload
        )
        calls.append((url, key, payload))
        return {
            "taskId": payload["taskId"],
            "sessionId": payload["sessionId"],
            "model": "strong-model",
            "provider": "pieverse",
            "policyVersion": 1,
            "rubricVersion": 2,
            "tier": "strong",
            "reason": "scored",
            "decidedAt": "2026-09-18T00:00:00Z",
        }

    first = resolve_adaptive_model(
        ctx=_ctx(),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=4096,
        post_json=post,
    )
    second = resolve_adaptive_model(
        ctx=_ctx(),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=4096,
        post_json=lambda *_: pytest.fail("replay must not reclassify"),
    )

    assert first == second
    assert first.model == "strong-model"
    assert calls[0][0] == "https://ai.example/v1/adaptive/resolve"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_scoring_http_unavailability_persists_auto_paid_and_replays(status):
    store = _MetadataStore()
    calls = 0

    def post(_url, _key, _payload):
        nonlocal calls
        calls += 1
        raise AdaptiveScoringUnavailable(f"http_{status}")

    first = resolve_adaptive_model(
        ctx=_ctx(),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
        post_json=post,
    )
    restored = resolve_adaptive_model(
        ctx=_ctx(message="", event_message_id=None, history=[]),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
        post_json=lambda *_: pytest.fail("fallback must replay without scoring"),
    )

    assert first == restored
    assert first.model == "auto/paid"
    assert first.decision["localFallback"] == "scoring_unavailable"
    assert first.decision["taskId"] == "hermes:session-1:event-9"
    assert first.decision["sessionId"] == "session-1"
    assert calls == 1


def test_scoring_network_unavailability_is_task_local_and_new_task_scores_again():
    store = _MetadataStore()
    calls = 0

    def post(_url, _key, payload):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise AdaptiveScoringUnavailable("network")
        return {
            "taskId": payload["taskId"],
            "sessionId": payload["sessionId"],
            "model": "model-a",
            "provider": "pieverse",
            "policyVersion": 1,
            "rubricVersion": 1,
            "tier": "normal",
            "reason": "scored",
            "decidedAt": "now",
        }

    fallback = resolve_adaptive_model(
        ctx=_ctx(), session_store=store, base_url="https://ai.example/v1",
        api_key="sk-pv-test", max_output_tokens=1000, post_json=post,
    )
    selected = resolve_adaptive_model(
        ctx=_ctx(event_message_id="event-10"), session_store=store,
        base_url="https://ai.example/v1", api_key="sk-pv-test",
        max_output_tokens=1000, post_json=post,
    )

    assert fallback.model == "auto/paid"
    assert selected.model == "model-a"
    assert calls == 2


def test_fallback_log_is_emitted_only_after_durable_persistence(caplog):
    store = _MetadataStore()
    writes = 0

    def reject_decision(_session_key, _key, value):
        nonlocal writes
        writes += 1
        if writes == 2:
            return False
        store.values[("discord:1", "adaptive_model_task")] = value
        return True

    store.set_session_metadata = reject_decision
    with pytest.raises(AdaptiveResolutionError, match="persist the decision"):
        resolve_adaptive_model(
            ctx=_ctx(), session_store=store, base_url="https://ai.example/v1",
            api_key="sk-pv-test", max_output_tokens=1000,
            post_json=lambda *_: (_ for _ in ()).throw(AdaptiveScoringUnavailable("network")),
        )

    assert "using auto/paid" not in caplog.text


@pytest.mark.parametrize("status", [400, 401, 402, 403])
def test_transport_keeps_permission_and_request_failures_as_errors(monkeypatch, status):
    import urllib.error

    def fail(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://ai.example", status, "private", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fail)
    with pytest.raises(AdaptiveResolutionError):
        _post_json("https://ai.example", "sk-pv-test", {"taskId": "one"})


@pytest.mark.parametrize("status", [429, 500, 503])
def test_transport_classifies_only_scoring_availability_http_failures(monkeypatch, status):
    import urllib.error

    def fail(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://ai.example", status, "private", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fail)
    with pytest.raises(AdaptiveScoringUnavailable):
        _post_json("https://ai.example", "sk-pv-test", {"taskId": "one"})


@pytest.mark.parametrize(
    "error", [http.client.IncompleteRead(b"partial"), TimeoutError("body timeout")]
)
def test_transport_classifies_premature_body_disconnect_as_unavailable(
    monkeypatch, error
):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            raise error

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    with pytest.raises(AdaptiveScoringUnavailable):
        _post_json("https://ai.example", "sk-pv-test", {"taskId": "one"})


def test_premature_body_disconnect_persists_and_replays_local_fallback(monkeypatch):
    store = _MetadataStore()
    calls = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            raise http.client.IncompleteRead(b"partial")

    def urlopen(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    first = resolve_adaptive_model(
        ctx=_ctx(),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
    )
    replay = resolve_adaptive_model(
        ctx=_ctx(),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
    )

    assert first == replay
    assert first.model == "auto/paid"
    assert calls == 1


@pytest.mark.parametrize(
    "base_url", ["htts://gateway.test/v1", "https:///v1", "https://gateway.test:bad/v1"]
)
def test_adaptive_url_rejects_invalid_local_endpoint_config(base_url):
    with pytest.raises(AdaptiveResolutionError, match="Gateway URL"):
        _adaptive_url(base_url)


@pytest.mark.parametrize(
    "field,value", [("taskId", "other"), ("sessionId", "other"), ("provider", "openai")]
)
def test_resolution_rejects_wrong_reply_identity_or_provider(field, value):
    def post(_url, _key, payload):
        decision = {
            "taskId": payload["taskId"],
            "sessionId": payload["sessionId"],
            "model": "model-a",
            "provider": "pieverse",
            "policyVersion": 1,
            "rubricVersion": 1,
            "tier": "normal",
            "reason": "scored",
            "decidedAt": "now",
        }
        decision[field] = value
        return decision

    with pytest.raises(AdaptiveResolutionError):
        resolve_adaptive_model(
            ctx=_ctx(),
            session_store=_MetadataStore(),
            base_url="https://ai.example/v1",
            api_key="sk-pv-test",
            max_output_tokens=1000,
            post_json=post,
        )


@pytest.mark.parametrize(
    "alias",
    [
        "auto",
        "adaptive",
        "auto/adaptive",
        "pieverse/auto/adaptive",
        "auto/paid",
        "pieverse/auto/paid",
        "auto/smart",
        "pieverse/auto/smart",
    ],
)
def test_resolution_rejects_every_auto_alias(alias):
    def post(_url, _key, payload):
        return {
            "taskId": payload["taskId"],
            "sessionId": payload["sessionId"],
            "model": alias,
            "provider": "pieverse",
            "policyVersion": 1,
            "rubricVersion": 1,
            "tier": "normal",
            "reason": "scored",
            "decidedAt": "now",
        }

    with pytest.raises(AdaptiveResolutionError, match="concrete model"):
        resolve_adaptive_model(
            ctx=_ctx(),
            session_store=_MetadataStore(),
            base_url="https://ai.example/v1",
            api_key="sk-pv-test",
            max_output_tokens=1000,
            post_json=post,
        )


def test_native_turn_seam_resolves_before_route_and_disables_fallback(monkeypatch):
    from gateway.run import TurnRunner

    events = []
    runner = SimpleNamespace(
        session_store=_MetadataStore(),
        _resolve_turn_agent_config=lambda message, model, runtime: (
            events.append(("route", model, runtime["provider"]))
            or {"model": model, "runtime": runtime}
        ),
    )
    ctx = _ctx()
    turn = TurnRunner(runner, ctx)

    def fake_resolve(**kwargs):
        events.append(("adaptive", kwargs["ctx"].message))
        return SimpleNamespace(model="model-strong", decision={"tier": "strong"})

    monkeypatch.setattr("gateway.run.resolve_adaptive_model", fake_resolve)
    route = turn._resolve_native_turn_route(
        "auto/adaptive",
        {
            "provider": "openai",
            "base_url": "https://ai.example/v1",
            "api_key": "key",
            "max_tokens": 2048,
        },
    )

    assert events == [
        ("adaptive", "Explain the failure"),
        ("route", "model-strong", "openai"),
    ]
    assert route["model"] == "model-strong"
    assert ctx.adaptive_selection["tier"] == "strong"
    assert ctx.adaptive_disable_fallback is True


def test_native_turn_seam_fixed_model_bypasses_policy(monkeypatch):
    from gateway.run import TurnRunner

    runner = SimpleNamespace(
        session_store=_MetadataStore(),
        _resolve_turn_agent_config=lambda message, model, runtime: {
            "model": model,
            "runtime": runtime,
        },
    )
    monkeypatch.setattr(
        "gateway.run.resolve_adaptive_model",
        lambda **_: pytest.fail("fixed models bypass adaptive policy"),
    )
    ctx = _ctx()
    route = TurnRunner(runner, ctx)._resolve_native_turn_route(
        "fixed-model",
        {"provider": "openai", "base_url": "https://ai.example/v1", "api_key": "key"},
    )

    assert route["model"] == "fixed-model"
    assert ctx.adaptive_selection is None


def test_adaptive_cache_rejects_active_cooldown_fallback_identity():
    from gateway.run import TurnRunner

    selected_route = {
        "model": "selected-model",
        "runtime": {"provider": "openai"},
    }
    cached = SimpleNamespace(
        model="fallback-model",
        provider="anthropic",
        _primary_runtime={"model": "selected-model", "provider": "openai"},
        _fallback_activated=True,
        _rate_limited_until=float("inf"),
        _fallback_chain=[{"model": "fallback-model", "provider": "anthropic"}],
    )

    assert TurnRunner._adaptive_cached_agent_matches_route(cached, selected_route) is False

    cached.model = "selected-model"
    cached.provider = "openai"
    cached._fallback_activated = False
    assert TurnRunner._adaptive_cached_agent_matches_route(cached, selected_route) is True


def test_interrupted_continuation_reuses_latched_snapshot_at_native_route_seam(
    monkeypatch,
):
    from gateway.run import TurnRunner

    snapshot = {
        "request": {"taskId": "hermes:session-1:first"},
        "decision": {
            "taskId": "hermes:session-1:first",
            "sessionId": "session-1",
            "model": "selected-model",
            "provider": "pieverse",
        },
    }
    runner = SimpleNamespace(
        session_store=_MetadataStore(),
        _resolve_turn_agent_config=lambda message, model, runtime: {
            "model": model,
            "runtime": runtime,
        },
    )
    monkeypatch.setattr(
        "gateway.run.resolve_adaptive_model",
        lambda **_: pytest.fail("interrupted continuation must not reclassify"),
    )
    ctx = _ctx(event_message_id="interrupting-event", adaptive_snapshot=snapshot)

    route = TurnRunner(runner, ctx)._resolve_native_turn_route(
        "auto/adaptive",
        {"provider": "openai", "base_url": "https://ai.example/v1"},
    )

    assert route["model"] == "selected-model"
    assert ctx.adaptive_selection["taskId"] == "hermes:session-1:first"


def test_native_followup_only_pins_snapshot_for_interrupted_recursion():
    from gateway.run import TurnRunner

    snapshot = {"decision": {"model": "selected-model"}}
    ctx = _ctx(adaptive_snapshot=snapshot)

    assert (
        TurnRunner._adaptive_snapshot_for_followup({"interrupted": True}, ctx)
        is snapshot
    )
    assert (
        TurnRunner._adaptive_snapshot_for_followup({"interrupted": False}, ctx)
        is None
    )


@pytest.mark.parametrize("alias", ["auto", "adaptive", "auto/paid", "auto/smart"])
def test_only_canonical_adaptive_selector_is_recognized(alias):
    assert is_adaptive_model(alias) is False


def test_provider_qualified_canonical_selector_is_recognized_before_normalization():
    assert is_adaptive_model("auto/adaptive") is True
    assert is_adaptive_model("pieverse/auto/adaptive") is True


def test_adaptive_resolution_requires_pieverse_key():
    with pytest.raises(AdaptiveResolutionError, match="Pieverse API key"):
        resolve_adaptive_model(
            ctx=_ctx(),
            session_store=_MetadataStore(),
            base_url="https://ai.example/v1",
            api_key="unrelated-provider-key",
            max_output_tokens=1000,
            post_json=lambda *_: pytest.fail("must fail before network"),
        )


def test_empty_startup_restore_reuses_persisted_active_task_identity():
    store = _MetadataStore()

    def post(_url, _key, payload):
        return {
            "taskId": payload["taskId"],
            "sessionId": payload["sessionId"],
            "model": "model-a",
            "provider": "pieverse",
            "policyVersion": 1,
            "rubricVersion": 1,
            "tier": "normal",
            "reason": "scored",
            "decidedAt": "now",
        }

    original = resolve_adaptive_model(
        ctx=_ctx(),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
        post_json=post,
    )
    restored = resolve_adaptive_model(
        ctx=_ctx(message="", event_message_id=None, history=[]),
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
        post_json=lambda *_: pytest.fail("restore must replay persisted task"),
    )

    assert restored == original


def test_two_sessions_with_same_event_are_isolated():
    a = build_adaptive_request(
        _ctx(session_id="a", session_key="key-a"), max_output_tokens=100
    )
    b = build_adaptive_request(
        _ctx(session_id="b", session_key="key-b"), max_output_tokens=100
    )
    assert a["taskId"] != b["taskId"]


def test_independent_turns_can_select_simple_strong_simple():
    store = _MetadataStore()
    chosen = iter(["simple-model", "strong-model", "simple-model"])
    calls = []

    def post(_url, _key, payload):
        model = next(chosen)
        calls.append(payload["taskId"])
        return {
            "taskId": payload["taskId"],
            "sessionId": payload["sessionId"],
            "model": model,
            "provider": "pieverse",
            "policyVersion": 1,
            "rubricVersion": 1,
            "tier": "strong" if model == "strong-model" else "light",
            "reason": "scored",
            "decidedAt": "now",
        }

    models = [
        resolve_adaptive_model(
            ctx=_ctx(event_message_id=f"event-{number}"),
            session_store=store,
            base_url="https://ai.example/v1",
            api_key="sk-pv-test",
            max_output_tokens=1000,
            post_json=post,
        ).model
        for number in range(3)
    ]

    assert models == ["simple-model", "strong-model", "simple-model"]
    assert len(set(calls)) == 3


def test_adaptive_turn_exposes_gateway_correlation_headers():
    from gateway.adaptive_model import adaptive_observability_headers

    headers = adaptive_observability_headers({
        "taskId": "hermes:s:e",
        "sessionId": "session-1",
    })

    assert headers == {
        "x-pieverse-turn-id": "hermes:s:e",
        "x-pieverse-chat-id": "session-1",
    }
