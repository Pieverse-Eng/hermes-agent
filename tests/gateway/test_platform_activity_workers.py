"""Residency belongs to executor work, including abandoned coroutine waits."""
import asyncio
import shlex
import sys
import threading
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
async def test_quick_exec_requires_admission_and_retains_live_subprocess(monkeypatch):
    """A cancelled quick command keeps residency until its process exits."""
    from gateway.platforms.base import MessageEvent, MessageType
    from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source

    child_code = (
        "import sys; print('ready', flush=True); "
        "sys.stdin.buffer.read(1); print('finished', flush=True)"
    )
    command = f'exec {shlex.quote(sys.executable)} -c {shlex.quote(child_code)}'
    runner, _ = make_restart_runner()
    runner._external_drain_active = False
    runner.config.quick_commands = {'reviewexec': {'type': 'exec', 'command': command}}
    client = type('Client', (), {'finish': AsyncMock()})()
    lease = PlatformActivityLease(client, 'quick-exec')
    admission = AsyncMock(return_value=lease)
    monkeypatch.setattr('gateway.platform_activity.begin_platform_activity', admission)

    entered = asyncio.Event()
    processes = []
    original_spawn = asyncio.create_subprocess_shell

    async def observed_spawn(*args, **kwargs):
        process = await original_spawn(*args, stdin=asyncio.subprocess.PIPE, **kwargs)
        # Keep the real child alive after request cancellation so the test can
        # observe whether residency follows process exit rather than its waiter.
        setattr(process, 'terminate', MagicMock())
        processes.append(process)
        assert process.stdout is not None
        assert await process.stdout.readline() == b'ready\n'
        entered.set()
        return process

    monkeypatch.setattr(asyncio, 'create_subprocess_shell', observed_spawn)
    event = MessageEvent(
        text='/reviewexec',
        message_type=MessageType.TEXT,
        source=make_restart_source(),
        message_id='quick-exec',
    )
    task = asyncio.create_task(runner._handle_message(event))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        admission.assert_awaited_once()
        task.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        assert not task.done()
        client.finish.assert_not_awaited()
    finally:
        for process in processes:
            process.stdin.write(b'x')
            await process.stdin.drain()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert processes[0].returncode == 0
    getattr(processes[0], 'terminate').assert_called_once_with()
    client.finish.assert_awaited_once_with('quick-exec')


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
