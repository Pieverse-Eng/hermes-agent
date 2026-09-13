"""Residency belongs to executor work, including abandoned coroutine waits."""
import asyncio
import threading
from unittest.mock import AsyncMock

import pytest

from gateway.platform_activity import (
    PlatformActivityError,
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
