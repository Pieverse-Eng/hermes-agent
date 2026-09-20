"""Adaptive receipts must agree with native SQLite restart and task boundaries."""

from datetime import datetime, timedelta
from functools import partial
from types import SimpleNamespace
import threading

import pytest

from gateway.adaptive_model import (
    AdaptiveResolutionError,
    AdaptiveScoringUnavailable,
    resolve_adaptive_model,
)
from gateway.config import GatewayConfig, Platform
from gateway.platforms.base import MessageEvent, _reply_anchor_for_event
from gateway.session import SessionSource, SessionStore
from gateway.turn_context import TurnContext


@pytest.fixture
def stores(tmp_path, monkeypatch):
    import hermes_state

    monkeypatch.setattr(hermes_state, "DEFAULT_DB_PATH", tmp_path / "state.db")
    opened = []

    def create():
        store = SessionStore(tmp_path / "sessions", GatewayConfig())
        assert store._db is not None
        opened.append(store)
        return store

    yield create
    for store in opened:
        store._db.close()


def source(platform=Platform.TELEGRAM):
    return SessionSource(
        platform=platform, chat_id="chat", chat_type="group", thread_id="topic"
    )


def context(entry, event):
    return TurnContext(
        session_key=entry.session_key,
        session_id=entry.session_id,
        source=event.source,
        message=event.text,
        history=[],
        run_generation=1,
        event_message_id=_reply_anchor_for_event(event),
        inbound_message_id=event.message_id,
    )


def decision(payload, model="model-a"):
    return dict(
        taskId=payload["taskId"],
        sessionId=payload["sessionId"],
        model=model,
        provider="pieverse",
        policyVersion=1,
        rubricVersion=1,
        tier="normal",
        reason="scored",
        decidedAt="now",
    )


def resolve(store, ctx, post):
    return resolve_adaptive_model(
        ctx=ctx,
        session_store=store,
        base_url="https://ai.example/v1",
        api_key="sk-pv-test",
        max_output_tokens=1000,
        post_json=post,
    )


@pytest.mark.parametrize("failure_phase", ["request", "decision"])
def test_primary_write_failure_never_publishes_or_replays_uncommitted_state(
    stores, monkeypatch, caplog, failure_phase
):
    store = stores()
    entry = store.get_or_create_session(source())
    ctx = context(entry, MessageEvent(text="task", source=source(), message_id="101"))
    before = store.get_session_metadata(entry.session_key, "adaptive_model_task")
    original_write = store._db.replace_gateway_routing_entries
    calls = []

    def fail_primary(*args, **kwargs):
        raise OSError("injected primary write failure")

    def post(*_):
        calls.append("scored")
        monkeypatch.setattr(store._db, "replace_gateway_routing_entries", fail_primary)
        raise AdaptiveScoringUnavailable("network")

    if failure_phase == "request":
        monkeypatch.setattr(store._db, "replace_gateway_routing_entries", fail_primary)
    with pytest.raises(AdaptiveResolutionError, match="persist"):
        resolve(store, ctx, post)
    saved = store.get_session_metadata(entry.session_key, "adaptive_model_task")
    if failure_phase == "request":
        assert saved == before
        assert calls == []
    else:
        assert "decision" not in saved
        assert calls == ["scored"]
    assert "using auto/paid" not in caplog.text
    monkeypatch.setattr(store._db, "replace_gateway_routing_entries", original_write)
    # A later unrelated write must not flush a failed in-memory decision.
    store.set_session_metadata(entry.session_key, "unrelated", True)
    restarted = stores()
    assert (
        restarted.get_session_metadata(entry.session_key, "adaptive_model_task")
        == saved
    )


def test_successful_fallback_survives_restart_without_scoring(stores):
    store = stores()
    entry = store.get_or_create_session(source())
    ctx = context(entry, MessageEvent(text="task", source=source(), message_id="101"))

    def unavailable(*_):
        raise AdaptiveScoringUnavailable("network")

    first = resolve(store, ctx, unavailable)
    restarted = stores()
    restored = context(entry, MessageEvent(text="", source=source()))
    second = resolve(restarted, restored, lambda *_: pytest.fail("must not rescore"))
    assert first == second
    assert first.model == "auto/paid"


@pytest.mark.parametrize("platform", [Platform.TELEGRAM, Platform.FEISHU])
def test_native_inbound_ids_do_not_collapse_shared_reply_anchors(stores, platform):
    store = stores()
    origin = source(platform)
    entry = store.get_or_create_session(origin)
    events = [
        MessageEvent(
            text=text, source=origin, message_id=str(n), reply_to_message_id="parent"
        )
        for n, text in [(101, "simple"), (102, "complex")]
    ]
    assert _reply_anchor_for_event(events[0]) == _reply_anchor_for_event(events[1])
    calls = []

    def post(_url, _key, payload):
        calls.append(payload)
        return decision(payload, f"model-{len(calls)}")

    first = resolve(store, context(entry, events[0]), post)
    second = resolve(store, context(entry, events[1]), post)
    assert first.decision["taskId"] != second.decision["taskId"]
    assert [x["goal"] for x in calls] == ["simple", "complex"]


def test_completed_no_id_tasks_get_fresh_durable_identity_across_restart(stores):
    store = stores()
    entry = store.get_or_create_session(source())
    event = MessageEvent(text="synthetic task", source=source())
    post = lambda _url, _key, payload: decision(payload)
    first = resolve(store, context(entry, event), post)
    restarted = stores()
    second = resolve(restarted, context(entry, event), post)
    assert first.decision["taskId"] != second.decision["taskId"]
    third_store = stores()
    assert (
        third_store.get_session_metadata(entry.session_key, "adaptive_model_task")[
            "decision"
        ]
        == second.decision
    )


@pytest.mark.parametrize("fallback", [False, True])
def test_real_user_resume_pending_reuses_saved_decision_before_routing(
    stores, monkeypatch, fallback
):
    from gateway import run

    store = stores()
    origin = source(Platform.DISCORD)
    entry = store.get_or_create_session(origin)
    calls = []

    def post(_url, _key, payload):
        calls.append(payload)
        if fallback:
            raise AdaptiveScoringUnavailable("network")
        return decision(payload)

    first = resolve(
        store,
        context(entry, MessageEvent(text="original", source=origin, message_id="101")),
        post,
    )
    store.mark_resume_pending(entry.session_key)
    restarted = stores()
    restarted._ensure_loaded()
    ctx = context(entry, MessageEvent(text="continue", source=origin, message_id="102"))
    runner = SimpleNamespace(
        session_store=restarted,
        _resolve_turn_agent_config=lambda message, model, runtime: {"model": model},
    )
    monkeypatch.setattr(
        run, "resolve_adaptive_model", partial(resolve_adaptive_model, post_json=post)
    )
    route = run.TurnRunner(runner, ctx)._resolve_native_turn_route(
        "auto/adaptive", {"base_url": "https://ai.example/v1", "api_key": "sk-pv-test"}
    )
    assert route["model"] == first.model
    assert ctx.adaptive_selection == first.decision
    assert len(calls) == 1


@pytest.mark.parametrize("invalid", ["stale", "different_session"])
def test_resume_marker_does_not_reuse_an_unrelated_or_stale_task(
    stores, monkeypatch, invalid
):
    from gateway import run

    store = stores()
    origin = source(Platform.DISCORD)
    entry = store.get_or_create_session(origin)
    calls = []

    def post(_url, _key, payload):
        calls.append(payload)
        return decision(payload)

    resolve(
        store,
        context(entry, MessageEvent(text="old", source=origin, message_id="101")),
        post,
    )
    store.mark_resume_pending(entry.session_key)
    ctx = context(entry, MessageEvent(text="new task", source=origin, message_id="102"))
    if invalid == "stale":
        old = datetime.now() - timedelta(days=30)
        entry.last_resume_marked_at = old
        ctx.history = [{"role": "user", "content": "old", "timestamp": old.timestamp()}]
    else:
        ctx.session_id = "replacement-session"
    runner = SimpleNamespace(
        session_store=store,
        _resolve_turn_agent_config=lambda message, model, runtime: {"model": model},
    )
    monkeypatch.setattr(
        run, "resolve_adaptive_model", partial(resolve_adaptive_model, post_json=post)
    )
    run.TurnRunner(runner, ctx)._resolve_native_turn_route(
        "auto/adaptive", {"base_url": "https://ai.example/v1", "api_key": "sk-pv-test"}
    )
    assert len(calls) == 2


def test_legacy_mirror_failure_does_not_undo_a_committed_receipt(stores, monkeypatch):
    store = stores()
    entry = store.get_or_create_session(source())
    ctx = context(entry, MessageEvent(text="task", source=source(), message_id="101"))

    def fail_mirror(*_):
        raise OSError("injected mirror failure")

    monkeypatch.setattr(store, "_save_sessions_json", fail_mirror)
    first = resolve(store, ctx, lambda _url, _key, payload: decision(payload))
    restarted = stores()
    replay = resolve(
        restarted,
        context(entry, MessageEvent(text="", source=source())),
        lambda *_: pytest.fail("committed decision must replay"),
    )
    assert replay == first


def test_fresh_resume_marker_wins_over_old_transcript_and_completed_recursion_starts_new_task(
    stores, monkeypatch
):
    from gateway import run

    store = stores()
    origin = source(Platform.DISCORD)
    entry = store.get_or_create_session(origin)
    calls = []

    def post(_url, _key, payload):
        calls.append(payload)
        return decision(payload)

    first = resolve(
        store, context(entry, MessageEvent(text="original", source=origin)), post
    )
    store.mark_resume_pending(entry.session_key)
    runner = SimpleNamespace(
        session_store=store,
        _resolve_turn_agent_config=lambda message, model, runtime: {"model": model},
    )
    monkeypatch.setattr(
        run, "resolve_adaptive_model", partial(resolve_adaptive_model, post_json=post)
    )
    runtime = {"base_url": "https://ai.example/v1", "api_key": "sk-pv-test"}
    resume = context(
        entry, MessageEvent(text="continue", source=origin, message_id="102")
    )
    resume.history = [{"role": "user", "content": "original", "timestamp": 1}]
    run.TurnRunner(runner, resume)._resolve_native_turn_route("auto/adaptive", runtime)
    assert resume.adaptive_selection == first.decision
    assert len(calls) == 1
    queued = context(
        entry,
        MessageEvent(text="independent queued work", source=origin, message_id="103"),
    )
    queued._interrupt_depth = 1
    run.TurnRunner(runner, queued)._resolve_native_turn_route("auto/adaptive", runtime)
    assert queued.adaptive_selection["taskId"] != first.decision["taskId"]
    assert len(calls) == 2


def test_failed_strict_decision_cannot_leak_through_an_older_delayed_snapshot(
    stores, monkeypatch
):
    store = stores()
    entry = store.get_or_create_session(source())
    request_receipt = {
        "request": {"taskId": "native-task", "sessionId": entry.session_id}
    }
    assert store.set_session_metadata(
        entry.session_key, "adaptive_model_task", request_receipt, require_primary=True
    )
    snapshot_taken = threading.Event()
    release_writer = threading.Event()
    writer_errors = []
    persist = store._persist_routing_data
    primary_write = store._db.replace_gateway_routing_entries

    def delayed_persist(data, generation, **kwargs):
        if threading.current_thread() is writer:
            snapshot_taken.set()
            if not release_writer.wait(10):
                raise TimeoutError("delayed writer was not released")
        return persist(data, generation, **kwargs)

    def save_entries():
        try:
            store._save_entries()
        except BaseException as exc:
            writer_errors.append(exc)

    def reject_primary(*args, **kwargs):
        raise OSError("injected strict decision write failure")

    monkeypatch.setattr(store, "_persist_routing_data", delayed_persist)
    writer = threading.Thread(target=save_entries)
    writer.start()
    try:
        assert snapshot_taken.wait(10), "writer did not capture its routing snapshot"
        monkeypatch.setattr(
            store._db, "replace_gateway_routing_entries", reject_primary
        )
        assert not store.set_session_metadata(
            entry.session_key,
            "adaptive_model_task",
            {**request_receipt, "decision": {"model": "rejected-model"}},
            require_primary=True,
        )
        assert (
            store.get_session_metadata(entry.session_key, "adaptive_model_task")
            == request_receipt
        )
    finally:
        monkeypatch.setattr(store._db, "replace_gateway_routing_entries", primary_write)
        release_writer.set()
        writer.join(10)
    assert not writer.is_alive(), "delayed writer did not finish"
    assert writer_errors == []
    restarted = stores()
    assert (
        restarted.get_session_metadata(entry.session_key, "adaptive_model_task")
        == request_receipt
    )
