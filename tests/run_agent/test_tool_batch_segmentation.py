"""Segment-aware mixed tool-batch dispatch.

A model response containing several parallel-safe reads plus one unsafe
tool used to lose ALL concurrency: `_should_parallelize_tool_batch` was
all-or-nothing, so one barrier call forced the entire batch onto the
sequential path.  `_plan_tool_batch_segments` now splits the batch into
ordered segments — maximal contiguous runs of parallel-safe calls execute
concurrently, barrier calls sequentially — while preserving:

  * model tool-result ordering (one result per call, in emission order),
  * side-effect boundaries (no call starts before an earlier barrier ends).
"""

import json
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from run_agent import AIAgent
from agent.tool_dispatch_helpers import (
    _plan_tool_batch_segments,
    _should_parallelize_tool_batch,
)
from agent.prompt_builder import STEER_MARKER_OPEN
from tools.budget_config import BudgetConfig


def _tc(name="web_search", arguments="{}", call_id=None):
    return SimpleNamespace(
        id=call_id or f"call_{uuid.uuid4().hex[:8]}",
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _kinds(segments):
    return [kind for kind, _ in segments]


def _flatten_ids(segments):
    return [tc.id for _, calls in segments for tc in calls]


# ---------------------------------------------------------------------------
# Planner unit tests
# ---------------------------------------------------------------------------


class TestPlanToolBatchSegments:
    def test_all_safe_batch_is_single_parallel_segment(self):
        calls = [_tc("web_search"), _tc("read_file", '{"path":"a.py"}'), _tc("web_extract")]
        segments = _plan_tool_batch_segments(calls)
        assert _kinds(segments) == ["parallel"]
        assert _flatten_ids(segments) == [c.id for c in calls]

    def test_registry_opted_in_plugin_tools_run_in_parallel(self):
        from tools.registry import registry

        tool_name = f"plugin_parallel_{uuid.uuid4().hex}"
        registry.register(
            name=tool_name,
            toolset="plugin-test",
            schema={
                "name": tool_name,
                "description": "Test parallel-safe plugin tool",
                "parameters": {"type": "object", "properties": {}},
            },
            handler=lambda args, **kwargs: "ok",
            parallel_safe=True,
        )
        try:
            calls = [_tc(tool_name, call_id="p1"), _tc(tool_name, call_id="p2")]
            segments = _plan_tool_batch_segments(calls)
            assert _kinds(segments) == ["parallel"]
            assert _flatten_ids(segments) == ["p1", "p2"]
        finally:
            registry.deregister(tool_name)

    def test_three_safe_reads_plus_trailing_unsafe_keeps_reads_parallel(self):
        """The headline case: 3 safe reads + 1 unsafe tool must NOT go fully sequential."""
        calls = [
            _tc("web_search", call_id="r1"),
            _tc("web_search", call_id="r2"),
            _tc("read_file", '{"path":"a.py"}', call_id="r3"),
            _tc("terminal", '{"command":"echo hi"}', call_id="b1"),
        ]
        segments = _plan_tool_batch_segments(calls)
        assert _kinds(segments) == ["parallel", "sequential"]
        assert [tc.id for tc in segments[0][1]] == ["r1", "r2", "r3"]
        assert [tc.id for tc in segments[1][1]] == ["b1"]

    def test_barrier_in_middle_splits_runs_and_preserves_order(self):
        calls = [
            _tc("web_search", call_id="r1"),
            _tc("web_search", call_id="r2"),
            _tc("terminal", '{"command":"make"}', call_id="b1"),
            _tc("web_search", call_id="r3"),
            _tc("web_search", call_id="r4"),
        ]
        segments = _plan_tool_batch_segments(calls)
        assert _kinds(segments) == ["parallel", "sequential", "parallel"]
        assert _flatten_ids(segments) == ["r1", "r2", "b1", "r3", "r4"]

    def test_single_safe_call_after_barrier_is_demoted_and_merged(self):
        # parallel run of 1 gains nothing — demote to sequential and merge
        # with the adjacent barrier segment.
        calls = [
            _tc("web_search", call_id="r1"),
            _tc("web_search", call_id="r2"),
            _tc("terminal", '{"command":"make"}', call_id="b1"),
            _tc("web_search", call_id="r3"),
        ]
        segments = _plan_tool_batch_segments(calls)
        assert _kinds(segments) == ["parallel", "sequential"]
        assert [tc.id for tc in segments[1][1]] == ["b1", "r3"]


    def test_never_parallel_tool_is_a_barrier(self):
        calls = [
            _tc("web_search", call_id="r1"),
            _tc("web_search", call_id="r2"),
            _tc("clarify", '{"question":"?"}', call_id="c1"),
        ]
        segments = _plan_tool_batch_segments(calls)
        assert _kinds(segments) == ["parallel", "sequential"]
        assert [tc.id for tc in segments[1][1]] == ["c1"]



    def test_overlapping_paths_split_across_segments(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("read_file", '{"path":"a.py"}', call_id="w1"),
            _tc("web_search", call_id="r1"),
            _tc("write_file", '{"path":"a.py","content":"x"}', call_id="w2"),
            _tc("web_search", call_id="r2"),
        ]
        segments = _plan_tool_batch_segments(calls)
        # w2 conflicts with w1 → closes the first run; w2+r2 form the second.
        assert _kinds(segments) == ["parallel", "parallel"]
        assert [tc.id for tc in segments[0][1]] == ["w1", "r1"]
        assert [tc.id for tc in segments[1][1]] == ["w2", "r2"]
        # Order and completeness preserved.
        assert _flatten_ids(segments) == ["w1", "r1", "w2", "r2"]

    def test_v4a_decoy_path_does_not_parallelize_with_real_target(self, tmp_path):
        """mode=patch scopes via V4A headers, not a decoy path= argument.

        A patch that claims path=dummy.txt but updates real.py must not share
        a parallel segment with write_file/read_file on real.py.
        """
        patch_body = (
            "*** Begin Patch\n"
            "*** Update File: real.py\n"
            "@@\n"
            "-old\n"
            "+new\n"
            "*** End Patch\n"
        )
        patch_args = json.dumps({
            "mode": "patch",
            "path": "dummy.txt",
            "patch": patch_body,
        })
        calls = [
            _tc("patch", patch_args, call_id="p1"),
            _tc("write_file", '{"path":"real.py","content":"x"}', call_id="w1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        assert _flatten_ids(segments) == ["p1", "w1"]
        # Overlap on real.py must prevent a single parallel segment.
        assert not (
            len(segments) == 1
            and segments[0][0] == "parallel"
            and [tc.id for tc in segments[0][1]] == ["p1", "w1"]
        )
        # Solo runs demote to sequential and may merge; either shape is safe.
        if len(segments) == 1:
            assert segments[0][0] == "sequential"
        else:
            assert [tc.id for tc in segments[0][1]] == ["p1"]
            assert [tc.id for tc in segments[1][1]] == ["w1"]

    def test_v4a_multi_file_reserves_all_header_targets(self, tmp_path):
        """Multi-file V4A must reserve every Update/Add/Delete/Move target."""
        patch_body = (
            "*** Begin Patch\n"
            "*** Update File: a.py\n"
            "@@\n-a\n+b\n"
            "*** Add File: b.py\n"
            "+fresh\n"
            "*** End Patch\n"
        )
        # Honest path= only names a.py — b.py still must be reserved.
        patch_args = json.dumps({
            "mode": "patch",
            "path": "a.py",
            "patch": patch_body,
        })
        calls = [
            _tc("patch", patch_args, call_id="p1"),
            _tc("read_file", '{"path":"b.py"}', call_id="r1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        assert _flatten_ids(segments) == ["p1", "r1"]
        assert not (
            len(segments) == 1
            and segments[0][0] == "parallel"
            and [tc.id for tc in segments[0][1]] == ["p1", "r1"]
        )
        if len(segments) == 1:
            assert segments[0][0] == "sequential"
        else:
            assert [tc.id for tc in segments[0][1]] == ["p1"]
            assert [tc.id for tc in segments[1][1]] == ["r1"]

    def test_v4a_without_path_arg_still_scopes_from_headers(self, tmp_path):
        """mode=patch with no path= must still parallel-scope from V4A headers."""
        patch_body = (
            "*** Begin Patch\n"
            "*** Update File: real.py\n"
            "@@\n-old\n+new\n"
            "*** End Patch\n"
        )
        patch_args = json.dumps({"mode": "patch", "patch": patch_body})
        calls = [
            _tc("patch", patch_args, call_id="p1"),
            _tc("write_file", '{"path":"other.py","content":"x"}', call_id="w1"),
            _tc("read_file", '{"path":"real.py"}', call_id="r1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        # p1+w1 are disjoint → can share a parallel run; r1 overlaps real.py → new run.
        assert _flatten_ids(segments) == ["p1", "w1", "r1"]
        assert [tc.id for tc in segments[0][1]] == ["p1", "w1"]
        assert segments[0][0] == "parallel"
        assert [tc.id for tc in segments[1][1]] == ["r1"]

    def test_path_scoped_tool_without_path_is_a_barrier(self):
        calls = [
            _tc("read_file", "{}", call_id="nopath"),
            _tc("web_search", call_id="r1"),
            _tc("web_search", call_id="r2"),
        ]
        segments = _plan_tool_batch_segments(calls)
        assert _kinds(segments) == ["sequential", "parallel"]

    def test_flattened_segments_always_preserve_emission_order(self):
        calls = [
            _tc("terminal", '{"command":"x"}', call_id="b1"),
            _tc("web_search", call_id="r1"),
            _tc("clarify", '{"question":"?"}', call_id="c1"),
            _tc("read_file", '{"path":"a.py"}', call_id="r2"),
            _tc("read_file", '{"path":"b.py"}', call_id="r3"),
        ]
        segments = _plan_tool_batch_segments(calls)
        assert _flatten_ids(segments) == ["b1", "r1", "c1", "r2", "r3"]


class TestReaderWriterPathRoles:
    """Reader/writer reservation semantics on path-scoped tools.

    The originating bug: ``search_files`` was in ``_PARALLEL_SAFE_TOOLS``
    with no path reservation, so ``patch(path=X)`` + ``search_files(path=dir(X))``
    landed in ONE parallel segment and the search could observe pre-patch
    file content (stale-read race).  Fix: ``search_files`` reserves its
    search root as a READER; overlap conflicts only when a WRITER is on
    either side.
    """

    def test_search_files_after_patch_same_subtree_splits(self, tmp_path, monkeypatch):
        """The exact smoke-test race: patch a file, search its directory."""
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("patch", '{"path":"scratch/sample.txt","old_string":"a","new_string":"patched"}', call_id="w1"),
            _tc("search_files", '{"pattern":"patched","path":"scratch"}', call_id="s1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        # Both calls survive, but never in the same PARALLEL segment.
        # (A shared *sequential* segment is fine — sequential is ordered.)
        assert _flatten_ids(segments) == ["w1", "s1"]
        for kind, seg_calls in segments:
            ids = [tc.id for tc in seg_calls]
            assert not (kind == "parallel" and {"w1", "s1"} <= set(ids)), (
                "write and dependent search must not share a parallel segment"
            )

    def test_search_files_default_root_conflicts_with_write_into_cwd(self, tmp_path, monkeypatch):
        """search_files with NO path arg reserves the cwd — a write anywhere
        under the cwd must not share its segment."""
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("write_file", '{"path":"out/notes.txt","content":"x"}', call_id="w1"),
            _tc("search_files", '{"pattern":"notes"}', call_id="s1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        for kind, seg_calls in segments:
            ids = [tc.id for tc in seg_calls]
            assert not (kind == "parallel" and {"w1", "s1"} <= set(ids))

    def test_reader_reader_same_file_stays_parallel(self, tmp_path, monkeypatch):
        """Two reads of the same file commute — the old planner needlessly
        split them; they must now share one parallel segment."""
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("read_file", '{"path":"a.py"}', call_id="r1"),
            _tc("read_file", '{"path":"a.py"}', call_id="r2"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        assert _kinds(segments) == ["parallel"]
        assert [tc.id for tc in segments[0][1]] == ["r1", "r2"]

    def test_read_file_and_search_files_overlapping_stay_parallel(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("read_file", '{"path":"src/a.py"}', call_id="r1"),
            _tc("search_files", '{"pattern":"foo","path":"src"}', call_id="s1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        assert _kinds(segments) == ["parallel"]

    def test_search_files_disjoint_from_write_stays_parallel(self, tmp_path, monkeypatch):
        """A search rooted outside the written subtree has no conflict."""
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("write_file", '{"path":"src/a.py","content":"x"}', call_id="w1"),
            _tc("search_files", '{"pattern":"foo","path":"docs"}', call_id="s1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        assert _kinds(segments) == ["parallel"]
        assert [tc.id for tc in segments[0][1]] == ["w1", "s1"]

    def test_writer_writer_same_path_still_splits(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("write_file", '{"path":"a.py","content":"1"}', call_id="w1"),
            _tc("write_file", '{"path":"a.py","content":"2"}', call_id="w2"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        for kind, seg_calls in segments:
            ids = [tc.id for tc in seg_calls]
            assert not (kind == "parallel" and {"w1", "w2"} <= set(ids))

    def test_read_then_write_same_file_still_splits(self, tmp_path, monkeypatch):
        """Reader followed by writer on the same path keeps the pre-existing
        split (write must not clobber a file mid-read)."""
        monkeypatch.chdir(tmp_path)
        calls = [
            _tc("read_file", '{"path":"a.py"}', call_id="r1"),
            _tc("write_file", '{"path":"a.py","content":"x"}', call_id="w1"),
        ]
        segments = _plan_tool_batch_segments(calls, execution_cwd=tmp_path)
        for kind, seg_calls in segments:
            ids = [tc.id for tc in seg_calls]
            assert not (kind == "parallel" and {"r1", "w1"} <= set(ids))


class TestShouldParallelizeBackwardCompat:
    """The boolean gate is now a view over the planner — same answers as before."""

    def test_single_call_is_sequential(self):
        assert not _should_parallelize_tool_batch([_tc("web_search")])





# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------


def _make_tool_defs(*names: str) -> list:
    return [
        {
            "type": "function",
            "function": {
                "name": n,
                "description": f"{n} tool",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        for n in names
    ]


@pytest.fixture()
def agent():
    with (
        patch(
            "run_agent.get_tool_definitions",
            return_value=_make_tool_defs("web_search", "terminal"),
        ),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        a = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://openrouter.ai/api/v1",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
        )
        a.client = MagicMock()
        return a


@pytest.fixture()
def clarify_relay(agent):
    pytest.importorskip("nemo_relay")
    from agent import relay_runtime

    relay_runtime._reset_for_tests()
    agent.session_id = "clarify-session"
    lease = relay_runtime.SESSION_COORDINATOR.acquire_conversation(
        profile_key=relay_runtime.current_profile_key(),
        session_id=agent.session_id,
        platform="cli",
    )
    turn = relay_runtime.SESSION_COORDINATOR.begin_turn(lease, turn_id="turn-1", task_id="task-1")
    lease.host.retain_managed_execution("test.clarify")
    try:
        yield lease.host.relay
    finally:
        lease.host.release_managed_execution("test.clarify")
        relay_runtime.SESSION_COORDINATOR.end_turn(turn, outcome="success")
        relay_runtime.SESSION_COORDINATOR.release_conversation(lease)
        relay_runtime._reset_for_tests()


class TestSegmentedDispatchIntegration:
    def test_clarify_policy_waits_for_intervening_file_write(self, agent, monkeypatch, tmp_path):
        from hermes_cli import plugins
        from tools import file_tools, terminal_tool
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations

        marker = tmp_path / "policy-ready.txt"
        env = LocalEnvironment(cwd=str(tmp_path), timeout=5)
        file_ops = ShellFileOperations(env)
        monkeypatch.setitem(terminal_tool._active_environments, "default", env)
        monkeypatch.setitem(terminal_tool._active_environments, "clarify-barrier", env)
        monkeypatch.setattr(file_tools, "_get_file_ops", lambda task_id="default": file_ops)
        agent.valid_tool_names = set(agent.valid_tool_names) | {"write_file"}
        manager = plugins.PluginManager()
        monkeypatch.setattr(plugins, "_plugin_manager", manager)
        policy_inputs, prompts, events, messages = [], [], [], []

        def policy(tool_call_id, **kwargs):
            ready = marker.exists() and marker.read_text() == "ready"
            policy_inputs.append((tool_call_id, ready))
            if tool_call_id == "second" and not ready:
                return {"action": "block", "message": "The intervening write has not completed"}

        manager._hooks["pre_tool_call"] = [policy]
        agent.clarify_callback = lambda question, choices: prompts.append((question, choices)) or "Answer"
        agent.tool_start_callback = lambda call_id, *args: events.append(("start", call_id))
        agent.tool_complete_callback = lambda call_id, *args: events.append(("complete", call_id))
        try:
            agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=[
                _tc("clarify", '{"question":"Which topic?","choices":["General","Specific"]}', call_id="first"),
                _tc("write_file", json.dumps({"path": str(marker), "content": "ready"}), call_id="write"),
                _tc("clarify", '{"question":"Which post-write detail?","choices":["Summary","Full"]}', call_id="second"),
            ]), messages, "clarify-barrier")
        finally:
            env.cleanup()

        assert marker.read_text() == "ready"
        assert policy_inputs == [("first", False), ("write", False), ("second", True)]
        assert prompts == [("Which topic?", ["General", "Specific"]), ("Which post-write detail?", ["Summary", "Full"])]
        assert [message["tool_call_id"] for message in messages] == ["first", "write", "second"]
        assert json.loads(messages[2]["content"])["user_response"] == "Answer"
        assert events == [("start", "first"), ("complete", "first"), ("start", "write"), ("complete", "write"), ("start", "second"), ("complete", "second")]

    @pytest.mark.parametrize("managed", [False, True])
    def test_stop_cancels_clarify_batch_waiting_for_second_call_approval(self, agent, monkeypatch, request, managed):
        from hermes_cli import plugins
        from tools import approval
        from tools.interrupt import set_interrupt
        from tools.thread_context import propagate_context_to_thread

        relay = request.getfixturevalue("clarify_relay") if managed else None
        if relay is not None:
            async def wrap(name, args, next_call):
                return relay.ToolExecutionInterceptOutcome(await next_call(args))
            relay.intercepts.register_tool_execution("test.clarify.approval", 1, wrap)

        manager = plugins.PluginManager()
        monkeypatch.setattr(plugins, "_plugin_manager", manager)
        manager._hooks["pre_tool_call"] = [
            lambda tool_call_id, **kwargs: {"action": "approve", "message": "Approve the second question"} if tool_call_id == "second" else None
        ]
        monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
        monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
        monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
        monkeypatch.setattr(approval, "_get_approval_config", lambda: {"mode": "manual", "timeout": 300})
        session_key = "clarify-stop-approval"
        session_token = approval.set_current_session_key(session_key)
        notified, finished = threading.Event(), threading.Event()
        prompts, messages, errors, approval_tids = [], [], [], []
        agent.clarify_callback = lambda question, choices: prompts.append(question) or "Answer"

        def notify(data):
            approval_tids.append(threading.get_ident())
            notified.set()

        def execute():
            agent._execution_thread_id = threading.get_ident()
            try:
                agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=[
                    _tc("clarify", '{"question":"Which topic?"}', call_id="first"),
                    _tc("clarify", '{"question":"Which protected detail?"}', call_id="second"),
                ]), messages, "task-1")
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        approval.register_gateway_notify(session_key, notify)
        thread = threading.Thread(target=propagate_context_to_thread(execute), daemon=True)
        try:
            thread.start()
            assert notified.wait(5), "The second question never reached the real approval queue"
            agent.interrupt("stop")
            assert finished.wait(3), "Stop did not release the queued clarification approval"
            assert errors == []
            assert prompts == []
            assert [message["tool_call_id"] for message in messages] == ["first", "second"]
            assert "cancel" in messages[0]["content"].lower()
            assert "skipped" in messages[1]["content"].lower()
            assert not approval.has_blocking_approval(session_key)
            assert not agent._tool_worker_threads
        finally:
            # Release the real approval queue even when the regression fails;
            # this cleanup must not supply the interrupt the assertion tests.
            approval.unregister_gateway_notify(session_key)
            thread.join(5)
            approval.reset_current_session_key(session_token)
            approval.clear_session(session_key)
            for thread_id in [thread.ident, *approval_tids]:
                set_interrupt(False, thread_id)
            if relay is not None:
                relay.intercepts.deregister_tool_execution("test.clarify.approval")

    @pytest.mark.parametrize("count", [8, 9])
    def test_clarify_batch_respects_worker_bound_without_partial_publication(self, agent, count):
        prompts, messages = [], []
        calls = [_tc("clarify", json.dumps({"question": f"Question {index}?"}), call_id=f"q{index}") for index in range(count)]
        agent.clarify_callback = lambda question, choices: prompts.append(question) or "All answered"

        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=calls), messages, "task-1")

        assert [message["tool_call_id"] for message in messages] == [f"q{index}" for index in range(count)]
        if count == 8:
            assert len(prompts) == 1
            assert "1. Question 0?" in prompts[0] and "8. Question 7?" in prompts[0]
            assert all(json.loads(message["content"])["user_response"] == "All answered" for message in messages)
        else:
            assert prompts == []
            assert all("8" in json.JSONDecoder().raw_decode(message["content"])[0]["error"] for message in messages)

    @pytest.mark.parametrize("blocked_ids", [("second",), ("first",), ("first", "second")])
    @pytest.mark.parametrize("block_stage", ["pre_tool_call", "tool_execution"])
    def test_clarify_batch_publishes_only_individually_authorized_questions(self, agent, monkeypatch, blocked_ids, block_stage):
        from hermes_cli import plugins

        manager = plugins.PluginManager()
        monkeypatch.setattr(plugins, "_plugin_manager", manager)
        questions = {
            "first": {"question": "Which topic?", "choices": ["General", "Specific"]},
            "second": {"question": "Which restricted detail?", "choices": ["Private", "Internal"]},
        }
        execution_inputs, policy_inputs, post_inputs, prompts, completed = [], [], [], [], []

        def policy(tool_call_id, args, **kwargs):
            policy_inputs.append((tool_call_id, args))
            if block_stage == "pre_tool_call" and tool_call_id in blocked_ids:
                return {"action": "block", "message": f"Denied {tool_call_id}"}

        def execution(tool_call_id, args, next_call, **kwargs):
            execution_inputs.append((tool_call_id, args))
            if block_stage == "tool_execution" and tool_call_id in blocked_ids:
                return json.dumps({"error": f"Denied {tool_call_id}"})
            return next_call(args)

        manager._hooks["pre_tool_call"] = [policy]
        manager._hooks["post_tool_call"] = [lambda tool_call_id, args, **kwargs: post_inputs.append((tool_call_id, args))]
        manager._middleware["tool_execution"] = [execution]
        agent.clarify_callback = lambda question, choices, multi_select=False: prompts.append((question, choices, multi_select)) or "General"
        agent.tool_complete_callback = lambda call_id, *args: completed.append(call_id)
        calls = [_tc("clarify", json.dumps(args), call_id=call_id) for call_id, args in questions.items()]
        messages = []

        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=calls), messages, "task-1")

        allowed = [call_id for call_id in questions if call_id not in blocked_ids]
        assert prompts == [(questions[call_id]["question"], questions[call_id]["choices"], False) for call_id in allowed]
        assert execution_inputs == list(questions.items())
        assert policy_inputs == [(call_id, args) for call_id, args in questions.items() if block_stage == "pre_tool_call" or call_id in allowed]
        assert post_inputs == list(questions.items())
        assert [message["tool_call_id"] for message in messages] == ["first", "second"]
        for message in messages:
            response = json.loads(message["content"])
            if message["tool_call_id"] in blocked_ids:
                assert response == {"error": f"Denied {message['tool_call_id']}"}
            else:
                assert response["user_response"] == "General"
        assert completed == (allowed if block_stage == "pre_tool_call" else list(questions))

    @pytest.mark.parametrize("rewrite_stage", ["tool_request", "tool_execution"])
    def test_clarify_batch_uses_sanitized_args_and_preserves_per_call_wrappers(self, agent, monkeypatch, rewrite_stage):
        from hermes_cli import plugins
        from tools.env_passthrough import get_all_passthrough, scoped_env_passthrough

        manager = plugins.PluginManager()
        monkeypatch.setattr(plugins, "_plugin_manager", manager)
        original = {
            "first": {"question": "Which topic?", "choices": ["General", "Specific"]},
            "second": {"question": "Raw private question?", "choices": ["Raw private option"]},
        }
        sanitized = {"question": "Which public region?", "choices": ["Europe", "Asia"]}
        requests, policy_inputs, wrapper_scopes, prompts, completed, events = [], [], [], [], [], []
        grants = {"first": "CLARIFY_FIRST_TOKEN", "second": "CLARIFY_SECOND_TOKEN"}
        baseline_grants = get_all_passthrough()

        def request(tool_call_id, args, **kwargs):
            requests.append((tool_call_id, args))
            if rewrite_stage == "tool_request" and tool_call_id == "second":
                return {"args": sanitized, "source": "test-sanitizer"}

        def execution(tool_call_id, args, next_call, **kwargs):
            wrapper_scopes.append(("before", tool_call_id, get_all_passthrough()))
            if rewrite_stage == "tool_execution" and tool_call_id == "second":
                args = sanitized
            with scoped_env_passthrough([grants[tool_call_id]]):
                result = json.loads(next_call(args))
                wrapper_scopes.append(("after", tool_call_id, get_all_passthrough()))
                result["wrapped_call_id"] = tool_call_id
                return json.dumps(result)

        manager._middleware["tool_request"] = [request]
        manager._middleware["tool_execution"] = [execution]
        manager._hooks["pre_tool_call"] = [lambda tool_call_id, args, **kwargs: policy_inputs.append((tool_call_id, args))]
        agent.clarify_callback = lambda question, choices, multi_select=False: prompts.append((question, choices, multi_select)) or "General, Europe"
        agent.tool_start_callback = lambda call_id, *args: events.append(("start", call_id))

        def complete(call_id, name, args, result):
            completed.append((call_id, args))
            events.append(("complete", call_id))

        agent.tool_complete_callback = complete
        calls = [_tc("clarify", json.dumps(args), call_id=call_id) for call_id, args in original.items()]
        original_arguments = [call.function.arguments for call in calls]
        messages = []

        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=calls), messages, "task-1")

        assert len(prompts) == 1
        assert "1. Which topic?" in prompts[0][0]
        assert "2. Which public region?" in prompts[0][0]
        assert "Europe" in prompts[0][0] and "Asia" in prompts[0][0]
        assert "Raw private" not in prompts[0][0]
        assert prompts[0][1:] == (None, False)
        assert requests == list(original.items())
        assert policy_inputs == [("first", original["first"]), ("second", sanitized)]
        assert [message["tool_call_id"] for message in messages] == ["first", "second"]
        for message in messages:
            response = json.loads(message["content"])
            assert response["user_response"] == "General, Europe"
            assert response["wrapped_call_id"] == message["tool_call_id"]
        assert completed == policy_inputs
        assert events == [("start", "first"), ("complete", "first"), ("start", "second"), ("complete", "second")]
        assert [call.function.arguments for call in calls] == original_arguments
        assert [scope for stage, _, scope in wrapper_scopes if stage == "before"] == [baseline_grants, baseline_grants]
        for stage, call_id, scope in wrapper_scopes:
            if stage == "after":
                assert scope == baseline_grants | {grants[call_id]}
        assert get_all_passthrough() == baseline_grants

    @pytest.mark.parametrize("batched", [False, True])
    def test_clarify_batch_keeps_managed_relay_intercepts(self, agent, clarify_relay, batched):
        relay = clarify_relay

        def rewrite(name, args):
            if name == "clarify" and args["question"] == "Raw private question?":
                return {"question": "Which public region?"}
            return args

        async def wrap(name, args, next_call):
            result = await next_call(args)
            return relay.ToolExecutionInterceptOutcome(json.dumps({**json.loads(result), "relay_wrapped": True}))

        relay.intercepts.register_tool_request("test.clarify.request", 1, False, rewrite)
        relay.intercepts.register_tool_execution("test.clarify.execution", 1, wrap)
        prompts, messages = [], []
        agent.clarify_callback = lambda question, choices: prompts.append(question) or "General, Europe"
        calls = [
            _tc("clarify", '{"question":"Which topic?"}', call_id="first"),
            _tc("clarify", '{"question":"Raw private question?"}', call_id="second"),
        ]
        try:
            for group in ([calls] if batched else [[call] for call in calls]):
                agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=group), messages, "task-1")
        finally:
            relay.intercepts.deregister_tool_execution("test.clarify.execution")
            relay.intercepts.deregister_tool_request("test.clarify.request")

        assert len(prompts) == (1 if batched else 2)
        assert "Which public region?" in prompts[-1]
        assert all("Raw private" not in prompt for prompt in prompts)
        assert [message["tool_call_id"] for message in messages] == ["first", "second"]
        assert all(json.loads(message["content"])["relay_wrapped"] for message in messages)

    @pytest.mark.parametrize("count", [2, 3])
    def test_prequeued_clarifies_share_one_complete_native_answer(self, agent, count):
        """An answer that supplies every order field must not meet a stale second prompt."""
        calls = [
            _tc("clarify", json.dumps({"question": "Which venue?", "choices": ["Hyperliquid", "Lighter"]}), call_id="venue"),
            _tc("clarify", json.dumps({"question": "What amount and leverage?", "choices": ["100 USDC, 5x cross", "Other"]}), call_id="sizing"),
        ]
        if count == 3:
            calls.append(_tc("clarify", json.dumps({"question": "What order type?", "choices": ["Market", "Limit"]}), call_id="order-type"))
        msg = SimpleNamespace(content="", tool_calls=calls)
        original_arguments = [call.function.arguments for call in calls]
        prompts, completed = [], []
        answer = "Hyperliquid, 10 USDC margin, 3x isolated, market, no TP/SL"

        def callback(question, choices, multi_select=False):
            prompts.append((question, choices, multi_select))
            return answer

        agent.clarify_callback = callback
        agent.tool_complete_callback = lambda call_id, name, args, result: completed.append((call_id, name, result))
        messages = []
        agent._execute_tool_calls(msg, messages, "task-1")

        assert len(prompts) == 1
        assert "1. Which venue?" in prompts[0][0]
        assert "2. What amount and leverage?" in prompts[0][0]
        assert "Hyperliquid" in prompts[0][0] and "100 USDC, 5x cross" in prompts[0][0]
        if count == 3:
            assert "3. What order type?" in prompts[0][0] and "Market" in prompts[0][0]
        assert prompts[0][1:] == (None, False)
        assert [message["tool_call_id"] for message in messages] == [call.id for call in calls]
        responses = [json.loads(message["content"]) for message in messages]
        assert all(response["user_response"] == answer for response in responses)
        assert all(response["question"] == prompts[0][0] for response in responses)
        assert [call.function.arguments for call in calls] == original_arguments
        assert [call_id for call_id, _, _ in completed] == [call.id for call in calls]

    def test_prequeued_clarify_failure_does_not_prompt_again(self, agent):
        prompts = []

        def cancelled(question, choices):
            prompts.append(question)
            raise TimeoutError("Clarification timed out")

        agent.clarify_callback = cancelled
        messages = []
        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=[
            _tc("clarify", '{"question":"Venue?"}', call_id="venue"),
            _tc("clarify", '{"question":"Amount?"}', call_id="sizing"),
        ]), messages, "task-1")
        assert len(prompts) == 1
        assert [message["tool_call_id"] for message in messages] == ["venue", "sizing"]
        assert all("timed out" in message["content"] for message in messages)

    def test_single_clarify_retains_native_select_choices(self, agent):
        prompts = []
        agent.clarify_callback = lambda question, choices, multi_select=False: prompts.append((question, choices, multi_select)) or '["Hyperliquid"]'
        messages = []
        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=[
            _tc("clarify", '{"question":"Venue?","choices":["Hyperliquid","Lighter"],"multi_select":true}', call_id="venue"),
        ]), messages, "task-1")
        assert prompts == [("Venue?", ["Hyperliquid", "Lighter"], True)]
        assert json.loads(messages[0]["content"])["user_response"] == ["Hyperliquid"]

    def test_oversized_clarify_batch_is_rejected_without_losing_a_question(self, agent):
        agent.clarify_callback = lambda *args, **kwargs: pytest.fail("An oversized batch must not publish a truncated prompt")
        messages = []
        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=[
            _tc("clarify", json.dumps({"question": "a" * 3000}), call_id="first"),
            _tc("clarify", json.dumps({"question": "b" * 3000}), call_id="second"),
        ]), messages, "task-1")
        assert [message["tool_call_id"] for message in messages] == ["first", "second"]
        assert all("4096" in message["content"] and "error" in message["content"] for message in messages)

    def test_interrupt_during_combined_clarify_cancels_remaining_calls(self, agent):
        prompts = []

        def interrupted(question, choices):
            prompts.append(question)
            agent._interrupt_requested = True
            return ""

        agent.clarify_callback = interrupted
        messages = []
        agent._execute_tool_calls(SimpleNamespace(content="", tool_calls=[
            _tc("clarify", '{"question":"Venue?"}', call_id="venue"),
            _tc("clarify", '{"question":"Amount?"}', call_id="sizing"),
        ]), messages, "task-1")
        assert len(prompts) == 1
        assert [message["tool_call_id"] for message in messages] == ["venue", "sizing"]
        assert "skipped" in messages[1]["content"].lower()

    def test_mixed_batch_runs_safe_prefix_concurrently_and_barrier_after(self, agent):
        """Two web_search calls must overlap in time; terminal must start only
        after both finish; results land in the model's emission order."""
        calls = [
            _tc("web_search", '{"query":"a"}', call_id="s1"),
            _tc("web_search", '{"query":"b"}', call_id="s2"),
            _tc("terminal", '{"command":"echo done"}', call_id="t1"),
        ]
        msg = SimpleNamespace(content="", tool_calls=calls)
        messages = []

        rendezvous = threading.Barrier(2, timeout=10)
        events = []
        events_lock = threading.Lock()

        def fake_handle(name, args, task_id, **kwargs):
            with events_lock:
                events.append(("start", name, kwargs["tool_call_id"]))
            if name == "web_search":
                # Both searches must be in flight at once to pass this
                # barrier — proves genuine concurrency for the safe prefix.
                rendezvous.wait()
            with events_lock:
                events.append(("end", name, kwargs["tool_call_id"]))
            return json.dumps({"ok": name})

        with patch("run_agent.handle_function_call", side_effect=fake_handle):
            agent._execute_tool_calls(msg, messages, "task-1")

        # One result per call, in emission order.
        assert [m["tool_call_id"] for m in messages] == ["s1", "s2", "t1"]
        assert all(m["role"] == "tool" for m in messages)

        # The barrier (terminal) started only after BOTH searches ended.
        terminal_start = events.index(("start", "terminal", "t1"))
        search_ends = [
            i for i, e in enumerate(events) if e[0] == "end" and e[1] == "web_search"
        ]
        assert len(search_ends) == 2
        assert all(i < terminal_start for i in search_ends)

    def test_mixed_batch_preserves_order_with_barrier_in_middle(self, agent):
        calls = [
            _tc("web_search", '{"query":"a"}', call_id="s1"),
            _tc("web_search", '{"query":"b"}', call_id="s2"),
            _tc("terminal", '{"command":"touch x"}', call_id="t1"),
            _tc("web_search", '{"query":"c"}', call_id="s3"),
            _tc("web_search", '{"query":"d"}', call_id="s4"),
        ]
        msg = SimpleNamespace(content="", tool_calls=calls)
        messages = []
        executed = []
        lock = threading.Lock()

        def fake_handle(name, args, task_id, **kwargs):
            with lock:
                executed.append(kwargs["tool_call_id"])
            return json.dumps({"ok": True})

        with patch("run_agent.handle_function_call", side_effect=fake_handle):
            agent._execute_tool_calls(msg, messages, "task-1")

        assert [m["tool_call_id"] for m in messages] == ["s1", "s2", "t1", "s3", "s4"]
        # Barrier ordering: t1 executed after {s1,s2} and before {s3,s4}.
        t1_pos = executed.index("t1")
        assert {"s1", "s2"} == set(executed[:t1_pos])
        assert {"s3", "s4"} == set(executed[t1_pos + 1:])

    def test_homogeneous_safe_batch_still_uses_plain_concurrent_path(self, agent):
        calls = [_tc("web_search", '{"query":"a"}'), _tc("web_search", '{"query":"b"}')]
        msg = SimpleNamespace(content="", tool_calls=calls)

        with (
            patch.object(agent, "_execute_tool_calls_concurrent") as conc,
            patch.object(agent, "_execute_tool_calls_sequential") as seq,
        ):
            agent._execute_tool_calls(msg, [], "task-1")

        conc.assert_called_once()
        seq.assert_not_called()



    def test_interrupt_during_barrier_drains_later_segments(self, agent):
        """Interrupt raised while the barrier tool runs: the trailing parallel
        segment must be drained with cancelled results — one per call —
        without executing."""
        calls = [
            _tc("web_search", '{"query":"a"}', call_id="s1"),
            _tc("web_search", '{"query":"b"}', call_id="s2"),
            _tc("terminal", '{"command":"long"}', call_id="t1"),
            _tc("web_search", '{"query":"c"}', call_id="s3"),
            _tc("web_search", '{"query":"d"}', call_id="s4"),
        ]
        msg = SimpleNamespace(content="", tool_calls=calls)
        messages = []
        executed = []
        lock = threading.Lock()

        def fake_handle(name, args, task_id, **kwargs):
            with lock:
                executed.append(kwargs["tool_call_id"])
            if kwargs["tool_call_id"] == "t1":
                agent._interrupt_requested = True
            return json.dumps({"ok": True})

        with patch("run_agent.handle_function_call", side_effect=fake_handle):
            agent._execute_tool_calls(msg, messages, "task-1")

        # Every call still gets exactly one result, in order.
        assert [m["tool_call_id"] for m in messages] == ["s1", "s2", "t1", "s3", "s4"]
        # s3/s4 were never executed.
        assert "s3" not in executed and "s4" not in executed
        for m in messages[-2:]:
            assert "cancelled" in m["content"] or "skipped" in m["content"]

    def test_steer_lands_exactly_once_in_mixed_batch(self, agent):
        """The whole-batch finalizer drains steer once, so the marker cannot
        be duplicated by segment boundaries."""
        calls = [
            _tc("web_search", '{"query":"a"}', call_id="s1"),
            _tc("web_search", '{"query":"b"}', call_id="s2"),
            _tc("terminal", '{"command":"echo hi"}', call_id="t1"),
        ]
        msg = SimpleNamespace(content="", tool_calls=calls)
        messages = []

        def fake_handle(name, args, task_id, **kwargs):
            return json.dumps({"ok": True})

        agent.steer("focus on the tests")
        with patch("run_agent.handle_function_call", side_effect=fake_handle):
            agent._execute_tool_calls(msg, messages, "task-1")

        contents = [m["content"] for m in messages]
        hits = [c for c in contents if "focus on the tests" in c]
        assert len(hits) == 1

    @pytest.mark.parametrize(
        ("calls", "expected_segment_kinds"),
        [
            (
                [
                    _tc("web_search", '{"query":"large"}', call_id="parallel-large"),
                    _tc("web_search", '{"query":"small"}', call_id="parallel-small"),
                ],
                ["parallel"],
            ),
            (
                [
                    _tc("terminal", '{"command":"large"}', call_id="sequential-large"),
                    _tc("terminal", '{"command":"small"}', call_id="sequential-small"),
                ],
                ["sequential"],
            ),
            (
                [
                    _tc("web_search", '{"query":"large"}', call_id="mixed-large"),
                    _tc("web_search", '{"query":"small"}', call_id="mixed-search-small"),
                    _tc("terminal", '{"command":"small"}', call_id="mixed-terminal-small"),
                ],
                ["parallel", "sequential"],
            ),
            (
                [
                    _tc("web_search", '{"query":"small"}', call_id="mixed-search-first-small"),
                    _tc("web_search", '{"query":"small"}', call_id="mixed-search-second-small"),
                    _tc("terminal", '{"command":"large"}', call_id="mixed-terminal-large"),
                ],
                ["parallel", "sequential"],
            ),
        ],
        ids=["parallel", "sequential", "mixed-parallel-large", "mixed-sequential-large"],
    )
    def test_steer_survives_turn_budget_in_every_dispatch_path(
        self, agent, calls, expected_segment_kinds
    ):
        """A steer must be appended after aggregate budgeting in direct
        concurrent, direct sequential, and segmented mixed batches.

        The large result forces ``enforce_turn_budget()`` to replace it.
        Before the fix, the per-tool drain consumed the steer first, so that
        replacement silently discarded the canonical marker.
        """
        messages = []
        msg = SimpleNamespace(content="", tool_calls=calls)
        budget = BudgetConfig(
            default_result_size=10_000,
            turn_budget=48,
            preview_size=16,
        )

        assert _kinds(_plan_tool_batch_segments(calls)) == expected_segment_kinds

        def fake_handle(name, args, task_id, **kwargs):
            if kwargs["tool_call_id"].endswith("large"):
                assert agent.steer("preserve this steer after budget enforcement")
                return "L" * 1_000
            return "small"

        with (
            patch("run_agent.handle_function_call", side_effect=fake_handle),
            patch("agent.tool_executor._budget_for_agent", return_value=budget),
        ):
            agent._execute_tool_calls(msg, messages, "task-1")

        large_result_index = next(i for i, call in enumerate(calls) if call.id.endswith("large"))
        assert "Truncated:" in messages[large_result_index]["content"]
        steer_messages = [m for m in messages if STEER_MARKER_OPEN in m["content"]]
        assert steer_messages == [messages[-1]]
        assert "preserve this steer after budget enforcement" in steer_messages[0]["content"]

    def test_steer_survives_turn_budget_after_malformed_arguments(self, agent):
        """Malformed arguments still reach the shared post-budget finalizer.

        The parser error itself can exceed a constrained turn budget.  A steer
        queued before that malformed sequential call must therefore remain
        pending until after the error result is replaced by the budget preview.
        """
        calls = [_tc("terminal", "{not json", call_id="malformed")]
        messages = []
        msg = SimpleNamespace(content="", tool_calls=calls)
        budget = BudgetConfig(
            default_result_size=10_000,
            turn_budget=48,
            preview_size=16,
        )

        assert _kinds(_plan_tool_batch_segments(calls)) == ["sequential"]
        assert agent.steer("preserve malformed-call steer after budget enforcement")

        with patch("agent.tool_executor._budget_for_agent", return_value=budget):
            agent._execute_tool_calls(msg, messages, "task-1")

        assert len(messages) == 1
        assert "Truncated:" in messages[0]["content"]
        assert messages[0]["content"].count(STEER_MARKER_OPEN) == 1
        assert "preserve malformed-call steer after budget enforcement" in messages[0]["content"]


class TestPathCanonicalization:
    """Regression tests for _canonical_path / _extract_parallel_scope_path fixes.

    Verifies that symlink aliases, relative/absolute cwd mismatches, and
    (on Windows) case-insensitive aliases are never placed in the same
    parallel segment.
    """

    def test_relative_and_absolute_same_target_use_separate_segments(self, tmp_path):
        """A relative path resolved against execution_cwd and an absolute path
        pointing to the same file must be detected as overlapping."""
        from agent.tool_dispatch_helpers import (
            _canonical_path,
            _paths_overlap,
        )

        target = tmp_path / "config.json"
        target.touch()

        abs_path = _canonical_path(str(target))
        rel_path = _canonical_path("config.json", execution_cwd=tmp_path)

        assert _paths_overlap(abs_path, rel_path), (
            "Absolute and relative paths pointing to the same file must overlap"
        )

    def test_symlink_aliases_are_not_parallelized(self, tmp_path):
        """A symlink alias and the real path must be detected as overlapping
        so they are never placed in the same parallel segment."""
        import os
        from agent.tool_dispatch_helpers import (
            _canonical_path,
            _paths_overlap,
        )

        real_dir = tmp_path / "real"
        real_dir.mkdir()
        target = real_dir / "config.json"
        target.touch()

        alias_dir = tmp_path / "alias"
        alias_dir.symlink_to(real_dir)

        real_path = _canonical_path(str(target))
        alias_path = _canonical_path(str(alias_dir / "config.json"))

        assert _paths_overlap(real_path, alias_path), (
            "Symlink alias and real path must overlap — "
            "they must not be parallelized"
        )

    def test_execution_cwd_used_over_process_cwd(self, tmp_path, monkeypatch):
        """_extract_parallel_scope_path must use execution_cwd, not
        process cwd, when resolving relative paths."""
        from agent.tool_dispatch_helpers import (
            _extract_parallel_scope_path,
            _paths_overlap,
        )

        exec_cwd = tmp_path / "sub"
        exec_cwd.mkdir()
        (exec_cwd / "x.txt").touch()

        # Point process cwd somewhere else entirely.
        monkeypatch.chdir(tmp_path)

        # With execution_cwd supplied the relative path resolves under exec_cwd.
        path_with_cwd = _extract_parallel_scope_path(
            "write_file", {"path": "x.txt"}, execution_cwd=exec_cwd
        )
        # The absolute path under exec_cwd must match.
        path_absolute = _extract_parallel_scope_path(
            "write_file", {"path": str(exec_cwd / "x.txt")}
        )

        assert path_with_cwd is not None
        assert path_absolute is not None
        assert _paths_overlap(path_with_cwd, path_absolute), (
            "execution_cwd-relative path and absolute path must overlap; "
            "process cwd must not be used when execution_cwd is provided"
        )


    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="normcase() case-folding only matters on Windows",
    )
    def test_case_insensitive_paths_overlap_windows(self, tmp_path):
        """On Windows, FILE.txt and file.txt are the same file — they must
        be detected as overlapping after normcase() canonicalisation."""
        from agent.tool_dispatch_helpers import _canonical_path, _paths_overlap

        upper = _canonical_path(str(tmp_path / "FILE.txt"), execution_cwd=tmp_path)
        lower = _canonical_path(str(tmp_path / "file.txt"), execution_cwd=tmp_path)

        assert _paths_overlap(upper, lower), (
            "Case-insensitive aliases must overlap on Windows"
        )
