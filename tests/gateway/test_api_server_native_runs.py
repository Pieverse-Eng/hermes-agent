"""Native run continuation and durable retry contracts (no model calls)."""
import asyncio
from unittest.mock import patch
import pytest
from aiohttp.test_utils import TestClient, TestServer
from tests.gateway.test_api_server_runs import _make_adapter, _create_runs_app
from hermes_state import SessionDB

async def settle(adapter, run_id):
    task = adapter._active_run_tasks.get(run_id)
    if task is not None:
        await task
    assert adapter._run_statuses[run_id]["status"] == "completed"

class RecordingAgent:
    session_prompt_tokens = session_completion_tokens = session_total_tokens = 0
    def __init__(self):
        self.histories = []
    def run_conversation(self, *, user_message, conversation_history, task_id, reload_session_history=False):
        self.histories.append(conversation_history)
        return {"final_response": "done"}

@pytest.mark.asyncio
async def test_native_history_preserves_tool_metadata(tmp_path):
    db = SessionDB(tmp_path / "state.db")
    db.create_session("chat", "api_server")
    calls = [{"id": "call1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}]
    db.append_message("chat", "user", "read it")
    db.append_message("chat", "assistant", None, tool_calls=calls)
    db.append_message("chat", "tool", "contents", tool_call_id="call1")
    adapter = _make_adapter()
    adapter._session_db = db
    agent = RecordingAgent()
    try:
        with patch.object(adapter, "_create_agent", return_value=agent):
            async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
                response = await cli.post("/v1/runs", json={"input": "continue", "session_id": "chat"})
                assert response.status == 202
                run = await response.json()
                await settle(adapter, run["run_id"])
                assert agent.histories == [db.get_messages_as_conversation("chat")]
    finally:
        db.close()

@pytest.mark.asyncio
async def test_retry_reuses_original_run_and_rejects_changed_payload():
    adapter = _make_adapter()
    agent = RecordingAgent()
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            headers = {"Idempotency-Key": "turn-one"}
            response = await cli.post("/v1/runs", json={"input": "hello"}, headers=headers)
            original = await response.json()
            await settle(adapter, original["run_id"])
            response = await cli.post("/v1/runs", json={"input": "hello"}, headers=headers)
            assert (await response.json())["run_id"] == original["run_id"]
            response = await cli.post("/v1/runs", json={"input": "different"}, headers=headers)
            assert response.status == 409
            assert len(agent.histories) == 1

@pytest.mark.asyncio
async def test_completed_events_reconnect_and_resume_cursor():
    adapter = _make_adapter()
    with patch.object(adapter, "_create_agent", return_value=RecordingAgent()):
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            response = await cli.post("/v1/runs", json={"input": "hello"})
            run_id = (await response.json())["run_id"]
            await settle(adapter, run_id)
            first = await cli.get(f"/v1/runs/{run_id}/events")
            text = await first.text()
            assert "run.completed" in text
            assert "id: 0" in text
            second = await cli.get(f"/v1/runs/{run_id}/events")
            assert second.status == 200
            assert "run.completed" in await second.text()
            resumed = await cli.get(f"/v1/runs/{run_id}/events", headers={"Last-Event-ID": "0"})
            assert "run.completed" not in await resumed.text()

@pytest.mark.asyncio
async def test_restart_pending_run_is_interrupted_and_never_dispatched(tmp_path):
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
    from types import SimpleNamespace
    adapter = _make_adapter()
    adapter._run_idempotency_store.close()
    path = str(tmp_path / "runs.db")
    store = RunIdempotencyStore(path)
    request = SimpleNamespace()
    scope = adapter._run_idempotency_scope(request)
    store.reserve(scope, "key", "fingerprint", "run_old", {"run_id": "run_old", "status": "running"}, owner_pid=0)
    store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(path)
    assert adapter._durable_run_status(request, "run_old")["status"] == "interrupted"
    adapter._run_idempotency_store.close()
    reopened = RunIdempotencyStore(path)
    assert reopened.status_for_run(scope, "run_old")["status"]["status"] == "interrupted"
    assert reopened.status_for_run("other-profile", "run_old") is None
    assert reopened.reserve(scope, "key", "fingerprint", "run_duplicate", {"status": "queued"})[0] == "reused"
    reopened.close()

def test_stale_approval_id_cannot_approve_next_request():
    from tools import approval
    entry = approval._ApprovalEntry({"command": "dangerous"})
    approval._gateway_queues["native-test"] = [entry]
    try:
        assert approval.resolve_gateway_approval("native-test", "once", request_id="stale") == 0
        assert not entry.event.is_set()
        assert approval.resolve_gateway_approval("native-test", "deny", request_id=entry.data["request_id"]) == 1
        assert entry.result == "deny"
    finally:
        approval.unregister_gateway_notify("native-test")

@pytest.mark.asyncio
@pytest.mark.parametrize("fork_marker", [None, "_branched_from", "_delegate_from"])
async def test_continuation_reads_compressed_tip(tmp_path, fork_marker):
    db = SessionDB(tmp_path / "state.db")
    config = {fork_marker: "origin"} if fork_marker else None
    db.create_session("origin", "api_server")
    db.create_session("parent", "api_server", parent_session_id="origin", model_config=config)
    db.append_message("parent", "user", "before compression")
    assert db.try_acquire_compression_lock("parent", "compressor")
    db.publish_compression_child(
        parent_session_id="parent", child_session_id="tip", source="api_server",
        messages=[{"role": "user", "content": "compressed context"}],
        model_config=config, compression_lock_holder="compressor",
    )
    db.release_compression_lock("parent", "compressor")
    adapter = _make_adapter()
    adapter._session_db = db
    agent = RecordingAgent()
    try:
        with patch.object(adapter, "_create_agent", return_value=agent):
            async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
                response = await cli.post("/v1/runs", json={"input": "continue", "session_id": "parent"})
                run_id = (await response.json())["run_id"]
                await settle(adapter, run_id)
                status = await (await cli.get(f"/v1/runs/{run_id}")).json()
                assert status["session_id"] == "tip"
                assert agent.histories == [db.get_messages_as_conversation("tip")]
    finally:
        db.close()


def test_stream_fans_out_and_bounds_slow_consumer():
    from gateway.platforms.api_server_runs import _RunStream, _RUN_STREAM_SUBSCRIBER_OVERFLOW
    stream = _RunStream()
    slow, _ = stream.attach()
    fast, _ = stream.attach()
    for index in range(stream.SUBSCRIBER_QUEUE_LIMIT + 1):
        event = {"event": "message.delta", "delta": str(index)}
        stream.put_nowait(event)
        assert fast.get_nowait() == (index, event)
    assert slow.get_nowait()[1] is _RUN_STREAM_SUBSCRIBER_OVERFLOW
    assert slow not in stream.subscribers
    for index in range(stream.BACKLOG_LIMIT + 1):
        stream.put_nowait({"event": "message.delta", "delta": str(index)})
    assert len(stream.backlog) == stream.BACKLOG_LIMIT
    stream.put_nowait(None)
    _, replay = stream.attach()
    assert replay[-1][1] is None


def test_idempotency_atomic_across_handles_and_survives_reopen(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
    path = str(tmp_path / "runs.db")
    stores = [RunIdempotencyStore(path), RunIdempotencyStore(path)]
    def reserve(index):
        return stores[index].reserve("scope", "key", "payload", f"run_{index}", {"status": "queued"})
    with ThreadPoolExecutor(2) as executor:
        results = list(executor.map(reserve, range(2)))
    assert sorted(result[0] for result in results) == ["created", "reused"]
    assert results[0][1]["run_id"] == results[1][1]["run_id"]
    run_id = results[0][1]["run_id"]
    stores[0].update_status(run_id, {"status": "completed", "output": "durable result"})
    for store in stores:
        store.close()
    reopened = RunIdempotencyStore(path)
    assert reopened.lookup("scope", "key", "payload")[1]["status"]["output"] == "durable result"
    assert reopened.lookup("scope", "key", "different")[0] == "conflict"
    assert reopened.lookup("other-scope", "key", "payload")[0] == "missing"
    reopened.close()

@pytest.mark.asyncio
async def test_unreadable_native_history_does_not_start_empty_turn(tmp_path):
    db = SessionDB(tmp_path / "state.db")
    db.create_session("chat", "api_server")
    adapter = _make_adapter()
    adapter._session_db = db
    agent = RecordingAgent()
    try:
        with patch.object(db, "get_messages_as_conversation", side_effect=RuntimeError("unreadable")), patch.object(adapter, "_create_agent", return_value=agent):
            async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
                response = await cli.post("/v1/runs", json={"input": "continue", "session_id": "chat"})
                assert response.status == 503
                assert agent.histories == []
    finally:
        for task in list(adapter._active_run_tasks.values()):
            await task
        db.close()

@pytest.mark.asyncio
async def test_lost_acceptance_retry_works_when_original_uses_last_slot():
    from tests.gateway.test_api_server_runs import _make_slow_agent
    adapter = _make_adapter()
    adapter._max_concurrent_runs = 1
    agent, ready, interrupted = _make_slow_agent()
    try:
        with patch.object(adapter, "_create_agent", return_value=agent):
            async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
                headers = {"Idempotency-Key": "busy-turn"}
                original = await (await cli.post("/v1/runs", json={"input": "hello"}, headers=headers)).json()
                assert await asyncio.to_thread(ready.wait, 2)
                blocked = await cli.post("/v1/runs", json={"input": "other"})
                assert blocked.status == 429
                replay = await cli.post("/v1/runs", json={"input": "hello"}, headers=headers)
                assert replay.status == 202
                assert (await replay.json())["run_id"] == original["run_id"]
    finally:
        interrupted.set()
        for task in list(adapter._active_run_tasks.values()):
            await task

@pytest.mark.asyncio
async def test_polling_foreign_run_refreshes_durable_completion(tmp_path):
    import os
    from gateway.status import get_process_start_time
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
    adapter = _make_adapter()
    adapter._run_idempotency_store.close()
    path = str(tmp_path / "runs.db")
    adapter._run_idempotency_store = RunIdempotencyStore(path)
    writer = RunIdempotencyStore(path)
    scope = adapter._run_idempotency_scope(None)
    writer.reserve(scope, "foreign", "payload", "run_foreign", {"run_id": "run_foreign", "status": "running"},
                   owner_pid=os.getpid(), owner_started=get_process_start_time(os.getpid()) or 0)
    try:
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            assert (await (await cli.get("/v1/runs/run_foreign")).json())["status"] == "running"
            writer.update_status("run_foreign", {"run_id": "run_foreign", "status": "completed", "output": "finished elsewhere"})
            refreshed = await (await cli.get("/v1/runs/run_foreign")).json()
            assert refreshed["status"] == "completed"
            assert refreshed["output"] == "finished elsewhere"
    finally:
        writer.close()
        adapter._run_idempotency_store.close()

@pytest.mark.asyncio
async def test_polling_foreign_run_detects_owner_death_after_first_read(tmp_path):
    import subprocess
    import sys
    from gateway.status import get_process_start_time
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
    owner = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    adapter = _make_adapter()
    adapter._run_idempotency_store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    scope = adapter._run_idempotency_scope(None)
    adapter._run_idempotency_store.reserve(scope, "foreign", "payload", "run_foreign", {"run_id": "run_foreign", "status": "running"},
        owner_pid=owner.pid, owner_started=get_process_start_time(owner.pid) or 0)
    try:
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            assert (await (await cli.get("/v1/runs/run_foreign")).json())["status"] == "running"
            owner.terminate()
            owner.wait(timeout=5)
            assert (await (await cli.get("/v1/runs/run_foreign")).json())["status"] == "interrupted"
    finally:
        if owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=5)
        adapter._run_idempotency_store.close()

@pytest.mark.asyncio
@pytest.mark.parametrize("history_source", ["explicit", "explicit_empty", "response", "native"])
async def test_real_agent_preserves_caller_context_and_reloads_native_after_admission(tmp_path, monkeypatch, history_source):
    from tests.run_agent.test_cross_process_turn_lease import _agent_with_db
    db = SessionDB(tmp_path / "state.db")
    db.create_session("chat", "api_server")
    db.append_message("chat", "user", "persisted context")
    adapter = _make_adapter()
    adapter._session_db = db
    observed = []
    caller_history = [] if history_source == "explicit_empty" else [{"role": "user", "content": "caller context"}]
    def create_agent(**kwargs):
        # Simulate the previous owner finishing between HTTP history loading and
        # this turn's durable admission. The actual AIAgent lease must reload it.
        db.append_message("chat", "assistant", "previous owner finished")
        agent = _agent_with_db(db, session_id=kwargs["session_id"], platform="api_server")
        agent.session_prompt_tokens = agent.session_completion_tokens = agent.session_total_tokens = 0
        return agent
    def conversation_loop(agent, message, system, history, *args, **kwargs):
        observed.append(history)
        return {"final_response": "done", "completed": True}
    monkeypatch.setattr(adapter, "_create_agent", create_agent)
    monkeypatch.setattr("agent.conversation_loop.run_conversation", conversation_loop)
    payload = {"input": "continue", "session_id": "chat"}
    if history_source in {"explicit", "explicit_empty"}:
        payload["conversation_history"] = caller_history
    elif history_source == "response":
        adapter._response_store.put("resp_previous", {"conversation_history": caller_history, "session_id": "chat"})
        payload["previous_response_id"] = "resp_previous"
    try:
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            response = await cli.post("/v1/runs", json=payload)
            assert response.status == 202
            await settle(adapter, (await response.json())["run_id"])
        expected = db.get_messages_as_conversation("chat", repair_alternation=True) if history_source == "native" else caller_history
        assert observed == [expected]
    finally:
        db.close()

@pytest.mark.asyncio
async def test_real_agent_lease_loss_is_interrupted_in_status_events_and_retry(tmp_path, monkeypatch):
    import threading
    from tests.run_agent.test_cross_process_turn_lease import _agent_with_db
    db = SessionDB(tmp_path / "state.db")
    successor = SessionDB(tmp_path / "state.db")
    db.create_session("chat", "api_server")
    db.append_message("chat", "user", "previous context")
    adapter = _make_adapter()
    adapter._session_db = db
    interrupted = threading.Event()
    def create_agent(**kwargs):
        agent = _agent_with_db(db, session_id=kwargs["session_id"], platform="api_server")
        agent.session_prompt_tokens = agent.session_completion_tokens = agent.session_total_tokens = 0
        agent._session_turn_lease_refresh_interval = 0.01
        def interrupt(message=None, hard_cancel=False):
            agent._interrupt_requested = True
            agent._interrupt_message = message
            interrupted.set()
        agent.interrupt = interrupt
        return agent
    def conversation_loop(agent, message, system, history, *args, **kwargs):
        holder = agent._active_session_turn_lease_holder
        db.release_session_turn_lease("chat", holder)
        assert successor.try_acquire_session_turn_lease("chat", "successor", ttl_seconds=30)
        assert interrupted.wait(2), "real lease refresher did not fence the stale agent"
        return {"completed": False, "interrupted": True, "interrupt_message": agent._interrupt_message, "final_response": "partial reply"}
    monkeypatch.setattr(adapter, "_create_agent", create_agent)
    monkeypatch.setattr("agent.conversation_loop.run_conversation", conversation_loop)
    try:
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            payload = {"input": "continue", "session_id": "chat"}
            headers = {"Idempotency-Key": "lease-loss"}
            response = await cli.post("/v1/runs", json=payload, headers=headers)
            run_id = (await response.json())["run_id"]
            task = adapter._active_run_tasks.get(run_id)
            if task:
                await task
            status = await (await cli.get(f"/v1/runs/{run_id}")).json()
            assert status["status"] == "interrupted"
            assert "lease lost" in status["error"]
            stream = await (await cli.get(f"/v1/runs/{run_id}/events")).text()
            assert "run.interrupted" in stream
            assert "run.completed" not in stream
            replay = await (await cli.post("/v1/runs", json=payload, headers=headers)).json()
            assert replay["run_id"] == run_id
            assert replay["status"] == "interrupted"
            durable = adapter._run_idempotency_store.status_for_run(adapter._run_idempotency_scope(None), run_id)
            assert durable["status"]["status"] == "interrupted"
    finally:
        successor.release_session_turn_lease("chat", "successor")
        db.close()
        successor.close()


@pytest.mark.asyncio
async def test_final_fenced_flush_cannot_complete_native_run(tmp_path, monkeypatch):
    """Lease takeover at final persist must reach HTTP/events/durable retry."""
    from tests.run_agent.test_cross_process_turn_lease import _live_agent

    db = SessionDB(tmp_path / "state.db")
    successor = SessionDB(tmp_path / "state.db")
    db.create_session("chat", "api_server")
    adapter = _make_adapter()
    adapter._session_db = db
    agent = _live_agent(db)
    monkeypatch.setattr(adapter, "_create_agent", lambda **kwargs: agent)

    def conversation_loop(agent, message, system, history, *args, **kwargs):
        if message == "followup":
            agent._persist_session(list(history) + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": "saved answer"},
            ], history)
            return {"completed": True, "final_response": "saved answer"}
        messages = [{"role": "user", "content": message}]
        agent._persist_session(messages, history)
        db.release_session_turn_lease("chat", agent._active_session_turn_lease_holder)
        assert successor.try_acquire_session_turn_lease("chat", "successor", ttl_seconds=30)
        messages.append({"role": "assistant", "content": "unsaved answer"})
        agent._persist_session(messages, history)
        return {"completed": True, "final_response": "unsaved answer", "messages": messages}

    monkeypatch.setattr("agent.conversation_loop.run_conversation", conversation_loop)
    try:
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            payload = {"input": "continue", "session_id": "chat"}
            headers = {"Idempotency-Key": "final-fence"}
            response = await cli.post("/v1/runs", json=payload, headers=headers)
            run_id = (await response.json())["run_id"]
            task = adapter._active_run_tasks.get(run_id)
            if task:
                await task
            assert [m["content"] for m in db.get_messages("chat")] == ["continue"]
            status = await (await cli.get(f"/v1/runs/{run_id}")).json()
            assert status["status"] == "failed"
            assert "session_turn_lease_lost" in status["error"]
            stream = await (await cli.get(f"/v1/runs/{run_id}/events")).text()
            assert "run.failed" in stream
            assert "run.completed" not in stream
            replay = await (await cli.post("/v1/runs", json=payload, headers=headers)).json()
            assert replay["run_id"] == run_id
            assert replay["status"] == "failed"
            durable = adapter._run_idempotency_store.status_for_run(adapter._run_idempotency_scope(None), run_id)
            assert durable["status"]["status"] == "failed"
            successor.release_session_turn_lease("chat", "successor")
            followup = await cli.post("/v1/runs", json={"input": "followup", "session_id": "chat"})
            followup_id = (await followup.json())["run_id"]
            await settle(adapter, followup_id)
            assert [m["content"] for m in db.get_messages("chat")] == [
                "continue", "followup", "saved answer",
            ]
    finally:
        successor.release_session_turn_lease("chat", "successor")
        db.close()
        successor.close()


def test_owner_finishing_while_status_is_checked_keeps_completed_output(tmp_path, monkeypatch):
    from tests.gateway.test_api_server_runs import _make_adapter
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
    adapter = _make_adapter()
    adapter._run_idempotency_store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(str(tmp_path / 'runs.db'))
    writer = RunIdempotencyStore(str(tmp_path / 'runs.db'))
    scope = adapter._run_idempotency_scope(None)
    writer.reserve(scope, 'key', 'fingerprint', 'run_old', {'run_id': 'run_old', 'status': 'running'}, owner_pid=123456, owner_started=0)
    def owner_exits_after_snapshot(pid):
        # Owner commits its successful terminal result and then exits between
        # status_for_run's read and the observer's process-aliveness check.
        writer.update_status('run_old', {'run_id': 'run_old', 'status': 'completed', 'output': 'saved result'})
        return False
    monkeypatch.setattr('gateway.status._pid_exists', owner_exits_after_snapshot)
    try:
        status = adapter._durable_run_status(None, 'run_old')
        durable = writer.status_for_run(scope, 'run_old')['status']
        assert status['status'] == 'completed'
        assert durable['output'] == 'saved result'
    finally:
        adapter._run_idempotency_store.close()
        writer.close()

@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"input": "hello"}, "Platform rules"),
        ({"input": "hello", "instructions": "Be a pirate"}, "Be a pirate"),
        ({"input": "hello", "instructions": ""}, ""),
    ],
)
async def test_runs_default_to_configured_system_prompt(body, expected):
    from types import SimpleNamespace
    adapter = _make_adapter()
    runner = SimpleNamespace(_ephemeral_system_prompt="Platform rules")
    with patch("gateway.run._gateway_runner_ref", lambda: runner), \
            patch.object(adapter, "_create_agent", return_value=RecordingAgent()) as create_agent:
        async with TestClient(TestServer(_create_runs_app(adapter))) as cli:
            response = await cli.post("/v1/runs", json=body)
            assert response.status == 202
            await settle(adapter, (await response.json())["run_id"])
    assert create_agent.call_args.kwargs["ephemeral_system_prompt"] == expected
