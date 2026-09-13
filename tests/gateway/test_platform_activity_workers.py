"""Residency belongs to executor work, including abandoned coroutine waits."""
import asyncio
import os
import shlex
import signal
import sys
import threading
from contextvars import copy_context
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.platform_activity import (
    PlatformActivityError,
    PlatformActivityClient,
    PlatformActivityLease,
    platform_activity_scope,
    platform_run_in_executor,
)


@pytest.mark.asyncio
@pytest.mark.parametrize('cancel_count', [1, 2])
@pytest.mark.parametrize('worker_fails', [False, True])
async def test_gateway_cancellation_retains_actual_worker(monkeypatch, cancel_count, worker_fails):
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source
    from tests.gateway.test_run_cleanup_progress import _make_runner, _install_fakes

    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()

    class BlockingAgent:
        def __init__(self, **kwargs):
            self.tools = []

        def run_conversation(self, *args, **kwargs):
            loop.call_soon_threadsafe(entered.set)
            try:
                release.wait(10)
                if worker_fails:
                    raise RuntimeError('worker failed after cancellation')
                return {'final_response': 'done', 'messages': [], 'api_calls': 1}
            finally:
                exited.set()

    _install_fakes(monkeypatch, BlockingAgent, cleanup_on=False)
    monkeypatch.setenv('HERMES_AGENT_TIMEOUT', '0')
    runner, adapter = make_restart_runner()
    baseline = _make_runner(adapter)
    for key, value in vars(baseline).items():
        if key not in ('config', 'hooks'):
            setattr(runner, key, value)
    runner._external_drain_active = False
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'turn')
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', AsyncMock(return_value=lease))

    async def run_real_agent(event, source, key, generation):
        return await runner._run_agent(message=event.text, context_prompt='', history=[],
                                       source=source, session_id='lease-review',
                                       session_key=key, run_generation=generation)

    monkeypatch.setattr(runner, '_handle_message_with_agent', run_real_agent)
    event = MessageEvent(text='hello', message_type=MessageType.TEXT,
                         source=make_restart_source(), message_id='review-1')
    task = asyncio.create_task(runner._handle_message(event))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        for _ in range(cancel_count):
            task.cancel()
            await asyncio.sleep(0)
        assert not exited.is_set()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)
    with pytest.raises(asyncio.CancelledError):
        await task
    client.finish.assert_awaited_once_with('turn')


@pytest.mark.asyncio
async def test_gateway_cancellation_retains_message_preparation_worker(monkeypatch):
    """Cancellation cannot release residency while pre-agent thread work continues."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()
    runner, _ = make_restart_runner()
    runner._external_drain_active = False

    def recover_topic(source):
        loop.call_soon_threadsafe(entered.set)
        try:
            release.wait(10)
        finally:
            exited.set()

    monkeypatch.setattr(runner, '_recover_telegram_topic_thread_id', recover_topic)
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'turn')
    monkeypatch.setattr(
        'gateway.platform_activity.begin_platform_activity',
        AsyncMock(return_value=lease),
    )
    event = MessageEvent(
        text='hello',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='preparation-review',
    )
    task = asyncio.create_task(runner._handle_message(event))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not exited.is_set()
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)

    with pytest.raises(asyncio.CancelledError):
        await task
    client.finish.assert_awaited_once_with('turn')


@pytest.mark.asyncio
@pytest.mark.parametrize('fallback', [False, True])
async def test_gateway_cancellation_retains_voice_transcription_worker(monkeypatch, fallback):
    """Voice preparation must keep residency until its real STT worker exits."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source
    from tools import transcription_tools

    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    runner.config.stt_enabled = True

    def blocking_transcription(path):
        loop.call_soon_threadsafe(entered.set)
        try:
            release.wait(10)
            return {'success': True, 'transcription': 'hello'}
        finally:
            exited.set()

    if fallback:
        monkeypatch.setattr(
            transcription_tools,
            'transcribe_audio',
            lambda path: {'success': False, 'error': 'primary unavailable'},
        )
        monkeypatch.setattr(
            transcription_tools,
            'transcribe_audio_local_fallback',
            blocking_transcription,
        )
    else:
        monkeypatch.setattr(
            transcription_tools,
            'transcribe_audio',
            blocking_transcription,
        )

    async def prepare_voice(event, source, key, generation):
        return await runner._enrich_message_with_transcription(
            event.text,
            ['/tmp/hosted-activity-voice.ogg'],
        )

    monkeypatch.setattr(runner, '_handle_message_with_agent', prepare_voice)
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'voice')
    monkeypatch.setattr(
        'gateway.platform_activity.begin_platform_activity',
        AsyncMock(return_value=lease),
    )
    event = MessageEvent(
        text='voice',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='voice-worker',
    )
    task = asyncio.create_task(runner._handle_message(event))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not exited.is_set()
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)
        await asyncio.gather(task, return_exceptions=True)

    client.finish.assert_awaited_once_with('voice')


@pytest.mark.asyncio
async def test_gateway_cancellation_retains_session_store_worker(monkeypatch):
    """The real async persistence facade must not outlive residency."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()
    runner, _ = make_restart_runner()
    runner._external_drain_active = False

    def get_or_create_session(source):
        loop.call_soon_threadsafe(entered.set)
        try:
            release.wait(10)
        finally:
            exited.set()

    monkeypatch.setattr(runner, '_recover_telegram_topic_thread_id', lambda source: None)
    monkeypatch.setattr(runner.session_store, 'get_or_create_session', get_or_create_session)
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'turn')
    monkeypatch.setattr(
        'gateway.platform_activity.begin_platform_activity',
        AsyncMock(return_value=lease),
    )
    event = MessageEvent(
        text='hello',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='persistence-review',
    )
    task = asyncio.create_task(runner._handle_message(event))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not exited.is_set()
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)

    with pytest.raises(asyncio.CancelledError):
        await task
    client.finish.assert_awaited_once_with('turn')


@pytest.mark.asyncio
async def test_cancelled_session_database_wait_retains_worker():
    """The lower-level async database facade shares the same ownership rule."""
    from hermes_state import AsyncSessionDB

    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()

    class BlockingDatabase:
        def write(self):
            loop.call_soon_threadsafe(entered.set)
            try:
                release.wait(10)
            finally:
                exited.set()

    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'database')
    database = AsyncSessionDB(BlockingDatabase())
    with platform_activity_scope(lease):
        worker_wait = asyncio.create_task(database.write())
        await asyncio.wait_for(entered.wait(), 3)
        worker_wait.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker_wait
        finish = asyncio.create_task(lease.finish())
        for _ in range(20):
            await asyncio.sleep(0)
        try:
            assert not exited.is_set()
            assert not finish.done()
            client.finish.assert_not_awaited()
        finally:
            release.set()
            await asyncio.to_thread(exited.wait, 3)

        await finish
    client.finish.assert_awaited_once_with('database')


@pytest.mark.asyncio
async def test_manual_compress_runs_under_residency(monkeypatch):
    """The real command dispatcher retains a cancelled compression worker."""
    from tests.gateway.restart_test_helpers import make_restart_runner
    from tests.gateway.test_compress_command import _make_event, _make_history, _make_runner

    runner, _ = make_restart_runner()
    baseline = _make_runner(_make_history())
    runner.session_store = baseline.session_store
    runner._session_db = None
    runner._external_drain_active = False
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'compress')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    monkeypatch.setattr(
        'gateway.run._resolve_runtime_agent_kwargs',
        lambda *args, **kwargs: {'api_key': 'test-key'},
    )
    monkeypatch.setattr(
        'gateway.run._resolve_gateway_model',
        lambda *args, **kwargs: 'test-model',
    )
    monkeypatch.setattr(
        'agent.model_metadata.estimate_request_tokens_rough',
        lambda *args, **kwargs: 100,
    )
    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()
    agent = MagicMock()
    agent._cached_system_prompt = ''
    agent.tools = None
    agent.context_compressor.has_content_to_compress.return_value = True

    def compress(*args, **kwargs):
        loop.call_soon_threadsafe(entered.set)
        try:
            release.wait(10)
        finally:
            exited.set()

    agent._compress_context.side_effect = compress
    monkeypatch.setattr('run_agent.AIAgent', lambda **kwargs: agent)

    task = asyncio.create_task(runner._handle_message(_make_event()))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not exited.is_set()
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)

    with pytest.raises(asyncio.CancelledError):
        await task
    admission.assert_awaited_once()
    client.finish.assert_awaited_once_with('compress')


@pytest.mark.asyncio
async def test_manual_compress_retains_topic_binding_worker(monkeypatch):
    """A cancelled rotation keeps residency through its final routing write."""
    from tests.gateway.restart_test_helpers import make_restart_runner
    from tests.gateway.test_compress_command import _make_event, _make_history, _make_runner

    runner, _ = make_restart_runner()
    baseline = _make_runner(_make_history())
    runner.session_store = baseline.session_store
    runner._session_db = None
    runner._external_drain_active = False
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'compress-binding')
    monkeypatch.setattr(
        'gateway.platform_activity.begin_platform_activity',
        AsyncMock(return_value=lease),
    )
    monkeypatch.setattr(
        'gateway.run._resolve_runtime_agent_kwargs',
        lambda *args, **kwargs: {'api_key': 'test-key'},
    )
    monkeypatch.setattr(
        'gateway.run._resolve_gateway_model',
        lambda *args, **kwargs: 'test-model',
    )
    monkeypatch.setattr(
        'agent.model_metadata.estimate_request_tokens_rough',
        lambda *args, **kwargs: 100,
    )
    agent = MagicMock()
    agent._cached_system_prompt = ''
    agent.tools = None
    agent.session_id = 'rotated-session'
    agent._compression_skipped_due_to_lock = False
    agent.context_compressor.has_content_to_compress.return_value = True
    agent._compress_context.return_value = (_make_history(), '')
    monkeypatch.setattr('run_agent.AIAgent', lambda **kwargs: agent)

    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()

    def sync_topic_binding(*args, **kwargs):
        loop.call_soon_threadsafe(entered.set)
        try:
            release.wait(10)
        finally:
            exited.set()

    monkeypatch.setattr(runner, '_sync_telegram_topic_binding', sync_topic_binding)
    task = asyncio.create_task(runner._handle_message(_make_event()))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not exited.is_set()
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)
        await asyncio.gather(task, return_exceptions=True)

    client.finish.assert_awaited_once_with('compress-binding')


@pytest.mark.asyncio
async def test_slash_command_cancellation_retains_actual_worker(monkeypatch):
    """The shared command dispatcher owns blocking work until its thread exits."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    client = type("Client", (), {"finish": AsyncMock()})()
    lease = PlatformActivityLease(client, "slash-worker")
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr("gateway.platform_activity.begin_platform_activity", admission)
    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    loop = asyncio.get_running_loop()

    def run_slash(_text):
        loop.call_soon_threadsafe(entered.set)
        try:
            release.wait(10)
            return "Created t_abcdef"
        finally:
            exited.set()

    monkeypatch.setattr("hermes_cli.kanban.run_slash", run_slash)
    task = asyncio.create_task(
        runner._handle_message(
            MessageEvent(
                text="/kanban create review-task",
                message_type=MessageType.TEXT,
                source=make_restart_source(),
                message_id="slash-worker",
            )
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not exited.is_set()
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        release.set()
        await asyncio.to_thread(exited.wait, 3)

    with pytest.raises(asyncio.CancelledError):
        await task
    admission.assert_awaited_once()
    client.finish.assert_awaited_once_with("slash-worker")


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group behavior")
@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_count", [1, 2])
async def test_quick_exec_cancellation_stops_descendants_before_finish(
    monkeypatch, tmp_path, cancel_count
):
    """A cancelled quick command retains residency through its entire process group."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import (
        make_restart_runner,
        make_restart_source,
    )

    pid_path = tmp_path / "quick-child.pid"
    child_code = (
        "import os, pathlib, signal; "
        f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
        "signal.signal(signal.SIGTERM, lambda *_: os._exit(0)); "
        "signal.pause()"
    )
    # Avoid syntax that replaces the shell: the regression requires a real
    # descendant whose stdio does not keep Process.communicate() open.
    command = (
        f"{shlex.quote(sys.executable)} -c {shlex.quote(child_code)} >/dev/null 2>&1"
    )
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    runner.config.quick_commands = {'reviewexec': {'type': 'exec', 'command': command}}
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'quick-exec')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)

    event = MessageEvent(
        text='/reviewexec',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='quick-exec',
    )
    task = asyncio.create_task(runner._handle_message(event))
    try:
        for _ in range(300):
            if pid_path.exists():
                break
            await asyncio.sleep(0.01)
        assert pid_path.exists()
        child_pid = int(pid_path.read_text())
        admission.assert_awaited_once()
        for _ in range(cancel_count):
            task.cancel()
            await asyncio.sleep(0)
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)

        import psutil

        assert not psutil.pid_exists(child_pid) or (
            psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE
        )
        client.finish.assert_awaited_once_with("quick-exec")
    finally:
        if "child_pid" in locals():
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_quick_exec_is_refused_by_real_hosted_drain(monkeypatch, tmp_path):
    """A supervisor drain marker prevents a quick-command process from starting."""
    from gateway import platform_activity
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    drain_path = tmp_path / 'drain-request.json'
    drain_path.write_text('{}', encoding='utf-8')
    monkeypatch.setenv('TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED', 'true')
    monkeypatch.setenv('TENANT_RUNTIME_ACTIVITY_SOCKET', str(tmp_path / 'activity.sock'))
    monkeypatch.setenv('HERMES_DRAIN_REQUEST_PATH', str(drain_path))
    monkeypatch.setattr(platform_activity, '_client', PlatformActivityClient())
    process = MagicMock()
    process.communicate = AsyncMock(return_value=(b'unexpected', b''))
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, 'create_subprocess_shell', spawn)
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    runner.config.quick_commands = {
        'reviewexec': {'type': 'exec', 'command': 'printf unexpected'}
    }

    result = await runner._handle_message(
        MessageEvent(
            text='/reviewexec',
            message_type=MessageType.TEXT,
            source=make_restart_source(),
            message_id='quick-exec-drain',
        )
    )

    assert result is not None
    assert 'cannot accept new work' in result
    spawn.assert_not_awaited()


@pytest.mark.asyncio
async def test_plugin_command_runs_under_residency(monkeypatch):
    """A plugin command cannot bypass hosted activity admission."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    entered = asyncio.Event()
    release = asyncio.Event()

    async def plugin_handler(_args):
        entered.set()
        await release.wait()
        return 'plugin finished'

    monkeypatch.setattr(
        'hermes_cli.plugins.get_plugin_command_handler',
        lambda command: plugin_handler if command == 'review-plugin' else None,
    )
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'plugin-command')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    task = asyncio.create_task(
        runner._handle_message(
            MessageEvent(
                text='/review-plugin',
                message_type=MessageType.TEXT,
                source=make_restart_source(),
                message_id='plugin-command',
            )
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), 3)
        admission.assert_awaited_once()
        client.finish.assert_not_awaited()
    finally:
        release.set()

    assert await task == 'plugin finished'
    client.finish.assert_awaited_once_with('plugin-command')


@pytest.mark.asyncio
async def test_registered_work_is_refused_but_control_remains_available_during_drain(
    monkeypatch, tmp_path
):
    """The command classifier fails closed without hiding drain controls."""
    from gateway import platform_activity
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    drain_path = tmp_path / 'drain-request.json'
    drain_path.write_text('{}', encoding='utf-8')
    monkeypatch.setenv('TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED', 'true')
    monkeypatch.setenv('TENANT_RUNTIME_ACTIVITY_SOCKET', str(tmp_path / 'activity.sock'))
    monkeypatch.setenv('HERMES_DRAIN_REQUEST_PATH', str(drain_path))
    monkeypatch.setattr(platform_activity, '_client', PlatformActivityClient())
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    insights = AsyncMock(return_value='unexpected insights')
    status = AsyncMock(return_value='runtime status')
    monkeypatch.setattr(runner, '_handle_insights_command', insights)
    monkeypatch.setattr(runner, '_handle_status_command', status)

    def event(text):
        return MessageEvent(
            text=text,
            message_type=MessageType.TEXT,
            source=make_restart_source(),
            message_id=text,
        )

    refused = await runner._handle_message(event('/insights'))
    available = await runner._handle_message(event('/status'))

    assert refused is not None
    assert 'cannot accept new work' in refused
    insights.assert_not_awaited()
    assert available == 'runtime status'
    status.assert_awaited_once()


@pytest.mark.asyncio
async def test_background_agent_owns_an_independent_activity_lease(monkeypatch):
    """A fire-and-forget background agent retains residency after dispatch returns."""
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    runner, _ = make_restart_runner()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def background(*_args):
        entered.set()
        await release.wait()

    monkeypatch.setattr(runner, '_run_background_task_inner', background)
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'background-agent')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    task = asyncio.create_task(
        runner._run_background_task('work', make_restart_source(), 'background-task')
    )
    try:
        await asyncio.wait_for(entered.wait(), 3)
        admission.assert_awaited_once()
        client.finish.assert_not_awaited()
    finally:
        release.set()

    await task
    client.finish.assert_awaited_once_with('background-agent')


@pytest.mark.skipif(os.name == 'nt', reason='POSIX background-process behavior')
@pytest.mark.asyncio
async def test_tracked_background_process_retains_turn_residency_until_exit(tmp_path):
    """A successful turn cannot release residency while its process survives."""
    from tools.process_registry import ProcessRegistry

    registry = ProcessRegistry()
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'background-process')
    command = f'{shlex.quote(sys.executable)} -c "import time; time.sleep(30)"'

    with platform_activity_scope(lease):
        context = copy_context()
        session = await platform_run_in_executor(
            None, context.run, registry.spawn_local, command, str(tmp_path),
            'activity-test', 'telegram:activity-test',
        )

    finish = asyncio.create_task(lease.finish())
    await asyncio.sleep(0)
    try:
        assert session.exited is False
        assert finish.done() is False
        client.finish.assert_not_awaited()
    finally:
        registry.kill_process(session.id)

    await asyncio.wait_for(finish, 3)
    client.finish.assert_awaited_once_with('background-process')


@pytest.mark.asyncio
async def test_recovered_background_process_reacquires_residency():
    """A gateway respawn cannot orphan a still-running tracked process."""
    from tools.process_registry import ProcessRegistry, ProcessSession

    registry = ProcessRegistry()
    session = ProcessSession(id='proc_recovered', command='server', started_at=1)
    registry._running[session.id] = session
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'recovered-process')

    assert registry.retain_running_with_platform_activity(lease) == 1
    finish = asyncio.create_task(lease.finish())
    await asyncio.sleep(0)
    assert finish.done() is False
    client.finish.assert_not_awaited()

    registry._move_to_finished(session)
    await asyncio.wait_for(finish, 3)
    client.finish.assert_awaited_once_with('recovered-process')


@pytest.mark.asyncio
@pytest.mark.parametrize('batch', [False, True])
async def test_detached_subagent_retains_turn_residency_until_completion(batch):
    """An async delegation inherits residency after its parent turn returns."""
    from tools import async_delegation

    async_delegation._reset_for_tests()
    release = threading.Event()
    entered = threading.Event()
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'background-subagent')

    def run_child():
        entered.set()
        release.wait(10)
        return {
            'status': 'completed', 'summary': 'done', 'api_calls': 1,
            'duration_seconds': 0.1,
        }

    try:
        with platform_activity_scope(lease):
            common = {
                'context': None, 'toolsets': None, 'role': 'worker',
                'model': 'test', 'session_key': 'telegram:activity-test',
                'runner': run_child,
            }
            if batch:
                result = async_delegation.dispatch_async_delegation_batch(
                    goals=['inspect'], **common,
                )
            else:
                result = async_delegation.dispatch_async_delegation(
                    goal='inspect', **common,
                )
        assert result['status'] == 'dispatched'
        assert await asyncio.to_thread(entered.wait, 3)
        finish = asyncio.create_task(lease.finish())
        await asyncio.sleep(0)
        assert finish.done() is False
        client.finish.assert_not_awaited()
    finally:
        release.set()

    await asyncio.wait_for(finish, 3)
    client.finish.assert_awaited_once_with('background-subagent')
    async_delegation._reset_for_tests()


@pytest.mark.asyncio
async def test_message_envelope_retains_activity_through_delivery_pipeline(monkeypatch):
    """The adapter releases residency only after processing and delivery settle."""
    from gateway.platform_activity import current_platform_activity_lease
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import (
        RestartTestAdapter,
        make_restart_source,
    )

    adapter = RestartTestAdapter()
    client = type("Client", (), {"finish": AsyncMock()})()
    lease = PlatformActivityLease(client, "message-delivery")
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr("gateway.platform_activity.begin_platform_activity", admission)
    entered_delivery = asyncio.Event()
    release_delivery = asyncio.Event()

    async def processing_and_delivery(_event, _session_key):
        assert current_platform_activity_lease() is lease
        entered_delivery.set()
        await release_delivery.wait()

    monkeypatch.setattr(
        adapter, "_process_message_background_impl", processing_and_delivery
    )
    event = MessageEvent(
        text="hello",
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id="message-delivery",
    )
    task = asyncio.create_task(
        adapter._process_message_background(event, "telegram:123456")
    )
    try:
        await asyncio.wait_for(entered_delivery.wait(), 3)
        admission.assert_awaited_once()
        client.finish.assert_not_awaited()
    finally:
        release_delivery.set()

    await task
    client.finish.assert_awaited_once_with("message-delivery")


@pytest.mark.asyncio
@pytest.mark.parametrize('worker_fails', [False, True])
async def test_abandoned_wait_and_cancelled_finish_keep_worker(worker_fails):
    entered = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'turn')

    def work():
        loop.call_soon_threadsafe(entered.set)
        release.wait(5)
        if worker_fails:
            raise RuntimeError('worker failed')

    with platform_activity_scope(lease):
        wrapper = platform_run_in_executor(None, work)
        await entered.wait()
        # The timeout/cancellation owns only this wait, not the thread.
        wrapper.cancel()
        finish = asyncio.create_task(lease.finish())
        await asyncio.sleep(0)
        finish.cancel()
        await asyncio.sleep(0)
        finish.cancel()
        await asyncio.sleep(0)
        try:
            assert lease.active
            assert not finish.done()
            client.finish.assert_not_awaited()
            with pytest.raises(PlatformActivityError, match='already finishing'):
                platform_run_in_executor(None, lambda: None)
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await finish
    assert not lease.active
    await lease.finish()
    client.finish.assert_awaited_once_with('turn')


@pytest.mark.asyncio
async def test_inert_lease_keeps_ordinary_executor_cancellation():
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, None)
    with platform_activity_scope(lease):
        future = platform_run_in_executor(None, lambda: 'ordinary')
        assert await future == 'ordinary'
    await lease.finish()
    assert not lease._workers
    client.finish.assert_not_awaited()


@pytest.mark.asyncio
async def test_completed_hosted_scope_refuses_new_worker_before_submission():
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'completed-turn')
    await lease.finish()
    submitted = False

    def work():
        nonlocal submitted
        submitted = True

    with platform_activity_scope(lease):
        with pytest.raises(PlatformActivityError, match='finished'):
            await platform_run_in_executor(None, work)

    assert submitted is False


@pytest.mark.asyncio
async def test_finishing_scope_refuses_detached_activity_reservation():
    from gateway.platform_activity import reserve_platform_activity

    release_finish = asyncio.Event()

    async def finish_remote(_handle):
        await release_finish.wait()

    client = type('Client', (), {'finish': AsyncMock(side_effect=finish_remote)})()
    lease = PlatformActivityLease(client, 'finishing-turn')
    finish = asyncio.create_task(lease.finish())
    await asyncio.sleep(0)

    try:
        with platform_activity_scope(lease):
            with pytest.raises(PlatformActivityError, match='already finishing'):
                reserve_platform_activity()
    finally:
        release_finish.set()

    await finish
    client.finish.assert_awaited_once_with('finishing-turn')


@pytest.mark.asyncio
async def test_drain_control_clears_inherited_completed_message_lease(monkeypatch):
    """A queued control remains usable without borrowing its parent's lease."""
    from gateway.platform_activity import (
        current_platform_activity_lease,
        platform_to_thread,
    )
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import RestartTestAdapter, make_restart_source

    adapter = RestartTestAdapter()
    client = type('Client', (), {'finish': AsyncMock()})()
    old_lease = PlatformActivityLease(client, 'previous-message')
    await old_lease.finish()
    worker_states = []

    async def dispatch(_event):
        return await platform_to_thread(
            lambda: worker_states.append(current_platform_activity_lease())
            or 'runtime status'
        )

    adapter._message_handler = dispatch
    event = MessageEvent(
        text='/status',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='queued-control',
    )

    with platform_activity_scope(old_lease):
        await adapter._process_message_background(event, 'telegram:queued-control')

    assert worker_states == [None]
    assert adapter.sent == ['runtime status']


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['refused', 'cancelled'])
async def test_gateway_releases_session_when_admission_does_not_complete(monkeypatch, failure):
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    source = make_restart_source()
    key = runner._session_key_for_source(source)

    async def admission():
        # The local sentinel must precede the newly introduced protocol await.
        assert runner._is_session_running(key)
        if failure == 'cancelled':
            raise asyncio.CancelledError
        raise PlatformActivityError('draining')

    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    work = AsyncMock()
    monkeypatch.setattr(runner, '_handle_message_with_agent', work)
    event = MessageEvent(text='hello', message_type=MessageType.TEXT,
                         source=source, message_id='rejected')
    if failure == 'cancelled':
        with pytest.raises(asyncio.CancelledError):
            await runner._handle_message(event)
    else:
        result = await runner._handle_message(event)
        assert 'cannot accept a new turn' in result
    assert not runner._is_session_running(key)
    work.assert_not_awaited()


@pytest.mark.asyncio
async def test_debug_upload_is_refused_during_hosted_drain(monkeypatch, tmp_path):
    """A command that uploads data is new work, not a drain control."""
    from gateway import platform_activity
    from gateway.platforms.base import MessageEvent, MessageType
    from hermes_cli import debug
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    drain_path = tmp_path / 'drain-request.json'
    drain_path.write_text('{}', encoding='utf-8')
    monkeypatch.setenv('TENANT_RUNTIME_RUN_LEASE_REPORTING_ENABLED', 'true')
    monkeypatch.setenv('TENANT_RUNTIME_ACTIVITY_SOCKET', str(tmp_path / 'activity.sock'))
    monkeypatch.setenv('HERMES_DRAIN_REQUEST_PATH', str(drain_path))
    monkeypatch.setattr(platform_activity, '_client', PlatformActivityClient())
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    uploaded = []
    monkeypatch.setattr(debug, '_best_effort_sweep_expired_pastes', lambda: None)
    monkeypatch.setattr(debug, '_capture_dump', lambda: '')
    monkeypatch.setattr(debug, 'collect_debug_report', lambda **_kwargs: 'report')
    monkeypatch.setattr(
        debug,
        'upload_to_pastebin',
        lambda report: uploaded.append(report) or 'test-url',
    )
    monkeypatch.setattr(debug, '_schedule_auto_delete', lambda _urls: None)
    event = MessageEvent(
        text='/debug',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='debug-during-drain',
    )

    result = await runner._handle_message(event)

    assert 'cannot accept new work' in result
    assert uploaded == []


@pytest.mark.asyncio
@pytest.mark.parametrize('first_admitted', [False, True])
async def test_message_admission_is_owned_once_through_delivery(monkeypatch, first_admitted):
    """The adapter owns one admission decision through work and delivery."""
    from gateway.platforms.base import MessageEvent, MessageType, SendResult
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    runner, adapter = make_restart_runner()
    runner._external_drain_active = False
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'compress-delivery')
    admission = AsyncMock(side_effect=(
        [lease] if first_admitted else [
            PlatformActivityError('first admission decides the message'), lease,
        ]
    ))
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    compress = AsyncMock(return_value='Compressed successfully.')
    monkeypatch.setattr(runner, '_handle_compress_command_inner', compress)
    adapter._message_handler = runner._handle_message
    delivery_states = []

    async def send(*_args, **kwargs):
        delivery_states.append((
            kwargs.get('content', ''), lease.active, client.finish.await_count,
        ))
        return SendResult(success=True, message_id='sent')

    monkeypatch.setattr(adapter, 'send', send)
    event = MessageEvent(
        text='/compress',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='compress-delivery',
    )

    await adapter._process_message_background(event, 'telegram:compress-delivery')

    assert len(delivery_states) == 1
    if first_admitted:
        assert delivery_states == [('Compressed successfully.', True, 0)]
        compress.assert_awaited_once()
        client.finish.assert_awaited_once_with('compress-delivery')
    else:
        assert 'cannot accept new work' in delivery_states[0][0]
        compress.assert_not_awaited()
        client.finish.assert_not_awaited()
    admission.assert_awaited_once()


@pytest.mark.asyncio
async def test_busy_inline_command_retains_residency_through_delivery(monkeypatch):
    """Busy-session dispatch uses the same outer ownership as normal messages."""
    from gateway.platform_activity import current_platform_activity_lease
    from gateway.platforms.base import MessageEvent, MessageType, SendResult
    from gateway.session import build_session_key
    from tests.gateway.restart_test_helpers import RestartTestAdapter, make_restart_source

    adapter = RestartTestAdapter()
    source = make_restart_source()
    adapter._active_sessions[build_session_key(source)] = asyncio.Event()
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'busy-command-delivery')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    observed = []

    async def dispatch(_event):
        observed.append(('dispatch', current_platform_activity_lease(), lease.active))
        return 'Background task started.'

    async def send(*_args, **_kwargs):
        observed.append(('delivery', current_platform_activity_lease(), lease.active))
        return SendResult(success=True, message_id='sent')

    adapter._message_handler = dispatch
    monkeypatch.setattr(adapter, 'send', send)
    event = MessageEvent(
        text='/background inspect the repository', message_type=MessageType.TEXT,
        source=source, message_id='busy-command-delivery',
    )

    await adapter.handle_message(event)

    assert observed == [('dispatch', lease, True), ('delivery', lease, True)]
    admission.assert_awaited_once()
    client.finish.assert_awaited_once_with('busy-command-delivery')


@pytest.mark.asyncio
async def test_busy_clarify_reply_remains_available_without_new_admission(monkeypatch):
    """A clarify reply settles existing work and must remain usable during drain."""
    from gateway.platforms.base import MessageEvent, MessageType
    from gateway.session import build_session_key
    from tests.gateway.restart_test_helpers import RestartTestAdapter, make_restart_source
    from tools import clarify_gateway

    adapter = RestartTestAdapter()
    source = make_restart_source()
    adapter._active_sessions[build_session_key(source)] = asyncio.Event()
    admission = AsyncMock(side_effect=PlatformActivityError('drain active'))
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    monkeypatch.setattr(
        clarify_gateway, 'get_pending_for_session', MagicMock(return_value=object()),
    )
    dispatch = AsyncMock(return_value='')
    adapter._message_handler = dispatch
    event = MessageEvent(
        text='the second choice', message_type=MessageType.TEXT,
        source=source, message_id='clarify-during-drain',
    )

    await adapter.handle_message(event)

    dispatch.assert_awaited_once_with(event)
    admission.assert_not_awaited()
    assert adapter.sent == []


@pytest.mark.asyncio
async def test_topic_recovery_is_admitted_before_its_worker_starts(monkeypatch):
    """Inbound preparation cannot run before the platform admission boundary."""
    from gateway.platform_activity import current_platform_activity_lease
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import RestartTestAdapter, make_restart_source

    adapter = RestartTestAdapter()
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'topic-recovery')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)
    observed = []

    def recover(_source):
        observed.append((current_platform_activity_lease(), lease.active))

    adapter.set_topic_recovery_fn(recover)
    adapter._message_handler = AsyncMock(return_value='done')
    monkeypatch.setattr(adapter, '_start_session_processing', MagicMock(return_value=True))
    event = MessageEvent(
        text='hello', message_type=MessageType.TEXT,
        source=make_restart_source(), message_id='topic-recovery',
    )

    await adapter.handle_message(event)

    assert observed == [(lease, True)]
    admission.assert_awaited_once()
    client.finish.assert_awaited_once_with('topic-recovery')


@pytest.mark.asyncio
async def test_queued_message_refusal_cannot_reuse_completed_parent_lease(monkeypatch):
    """A child task's copied context must not authorize its next message."""
    from gateway import platform_activity
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    runner, adapter = make_restart_runner()
    runner._external_drain_active = False
    client = type('Client', (), {'finish': AsyncMock()})()
    old_lease = PlatformActivityLease(client, 'previous-message')
    finished = asyncio.Event()
    client.finish.side_effect = lambda _handle: finished.set()
    admission_count = 0

    async def admit():
        nonlocal admission_count
        admission_count += 1
        if admission_count == 1:
            return old_lease
        await finished.wait()
        raise PlatformActivityError('drain active')

    monkeypatch.setattr(platform_activity, 'begin_platform_activity', admit)
    work_states = []

    async def insights(_event):
        return await platform_activity.platform_to_thread(
            lambda: work_states.append(
                (old_lease.active, client.finish.await_count)
            ) or 'Unleased insights ran.'
        )

    monkeypatch.setattr(runner, '_handle_insights_command', insights)

    def make_event(text, message_id):
        return MessageEvent(
            text=text,
            message_type=MessageType.TEXT,
            source=make_restart_source(),
            message_id=message_id,
        )

    async def dispatch(message):
        if message.text == 'hello':
            adapter._pending_messages['telegram:queued-refusal'] = make_event(
                '/insights', 'queued-refusal'
            )
            return ''
        return await runner._handle_message(message)

    adapter._message_handler = dispatch

    await adapter._process_message_background(
        make_event('hello', 'parent-message'), 'telegram:queued-refusal'
    )
    child = adapter._session_tasks['telegram:queued-refusal']
    await child

    assert admission_count == 2
    assert work_states == []
    assert any('cannot accept new work' in message for message in adapter.sent)
