"""Platform skill activation refreshes a live process without a user event."""

import asyncio
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


def _runner():
    return SimpleNamespace(adapters={}, _agent_cache={}, _running_agents={})


@pytest.fixture
def skills(tmp_path, monkeypatch):
    import agent.skill_commands as commands
    import tools.skills_tool as skill_tools

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(skill_tools, "SKILLS_DIR", tmp_path / "skills")
    monkeypatch.setattr(commands, "_skill_commands", {})
    monkeypatch.setattr(commands, "_skill_commands_security_blocked", set())
    monkeypatch.setattr(commands, "_skill_commands_platform", None)
    # The trust provider is an external service; keep catalog and invocation real.
    monkeypatch.setattr(
        "tools.skill_security_gate.ensure_skill_certik_allowed_for_session_load",
        lambda path, **kwargs: SimpleNamespace(
            allowed=path.name != "blocked", reason="policy", archive=None
        ),
    )

    def install(name):
        directory = tmp_path / "skills" / name
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Test {name}\n---\nUse {name}.\n",
            encoding="utf-8",
        )

    return install


@pytest.mark.asyncio
async def test_reload_updates_live_catalog_without_interrupting_turn_or_prompt(skills):
    from agent.skill_commands import get_skill_commands, scan_skill_commands
    from gateway.platform_skill_reload import reload_platform_skills

    skills("before")
    scan_skill_commands()
    agent = SimpleNamespace(_cached_system_prompt="unchanged prefix")
    runner = _runner()
    runner._agent_cache["existing"] = (agent, "signature")
    running = asyncio.create_task(asyncio.Event().wait())
    runner._running_agents["existing"] = running
    skills("after")
    try:
        result = await reload_platform_skills(runner)
        assert "/after" in get_skill_commands()
        assert result["added"] == 1
        assert result["total"] == 2
        assert result["existingSessionCachesInvalidated"] is False
        assert not running.done()
        assert runner._agent_cache["existing"][0] is agent
        assert agent._cached_system_prompt == "unchanged prefix"
        assert "skills_list" in runner._pending_skills_reload_notes["existing"]
    finally:
        running.cancel()
        await asyncio.gather(running, return_exceptions=True)


@pytest.mark.asyncio
async def test_reload_preserves_security_rejection_and_refreshes_adapter(skills):
    from agent.skill_commands import get_skill_commands, build_skill_invocation_message
    from gateway.platform_skill_reload import reload_platform_skills

    skills("allowed")
    skills("blocked")
    visible = []

    async def refresh():
        visible.extend(get_skill_commands())

    runner = _runner()
    runner.adapters["test"] = SimpleNamespace(refresh_skill_group=refresh)
    result = await reload_platform_skills(runner)
    assert visible == ["/allowed"]
    assert result["blocked"] == 1
    assert build_skill_invocation_message("/blocked") is None


@pytest.mark.asyncio
async def test_internal_reload_requires_key_and_keeps_process_marker(skills):
    from aiohttp import web

    adapter = APIServerAdapter(
        PlatformConfig(enabled=True, extra={"key": "test-secret"})
    )
    adapter.gateway_runner = _runner()
    app = web.Application()
    # Register production routes, so omissions in the real route table fail.
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    skills("installed")
    marker = adapter._platform_process_marker()
    async with TestClient(TestServer(app)) as client:
        for headers in ({}, {"Authorization": "Bearer wrong"}):
            response = await client.post(
                "/internal/platform/skills/reload", headers=headers, json={}
            )
            assert response.status == 401
        response = await client.post(
            "/internal/platform/skills/reload",
            headers={"Authorization": "Bearer test-secret"},
            json={},
        )
        assert response.status == 200
        assert (await response.json())["ok"] is True
        assert adapter._platform_process_marker() == marker
        skills("merchant:tool")
        response = await client.post(
            "/internal/platform/skills/reload",
            headers={"Authorization": "Bearer test-secret"},
            json={"skill": "merchant:tool"},
        )
        assert response.status == 200
        skills("blocked")
        response = await client.post(
            "/internal/platform/skills/reload",
            headers={"Authorization": "Bearer test-secret"},
            json={"skill": "blocked"},
        )
        assert response.status == 422
        response = await client.post(
            "/internal/platform/skills/reload",
            headers={"Authorization": "Bearer test-secret"},
            json={"skill": "../escape"},
        )
        assert response.status == 400
        adapter._api_key = ""
        response = await client.post("/internal/platform/skills/reload", json={})
        assert response.status == 401


@pytest.mark.asyncio
async def test_builtin_command_name_skill_can_activate(skills):
    from gateway.platform_skill_reload import reload_platform_skills

    skills("status")
    result = await reload_platform_skills(_runner(), "status")
    assert result["existingSessionCachesInvalidated"] is False


@pytest.mark.asyncio
async def test_adapter_failure_does_not_hide_reload_from_other_sessions(skills):
    from gateway.platform_skill_reload import reload_platform_skills

    refreshed = []

    async def fail():
        raise RuntimeError("adapter unavailable")

    async def succeed():
        refreshed.append(True)

    skills("installed")
    runner = _runner()
    runner._agent_cache["existing"] = (object(), "signature")
    runner.adapters = {
        "bad": SimpleNamespace(refresh_skill_group=fail),
        "good": SimpleNamespace(refresh_skill_group=succeed),
    }
    result = await reload_platform_skills(runner, "installed")
    assert result["adapterRefreshFailures"] == 1
    assert refreshed == [True]
    assert "existing" in runner._pending_skills_reload_notes


@pytest.mark.asyncio
async def test_cancelled_reload_keeps_lock_until_worker_finishes(monkeypatch):
    import threading
    from gateway.platform_skill_reload import reload_platform_skills

    started = threading.Event()
    release = threading.Event()
    overlapped = []
    calls = 0

    def catalog(_skill):
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            release.wait(timeout=5)
        else:
            overlapped.append(not release.is_set())
        return {"added": 0, "removed": 0, "total": 0}

    monkeypatch.setattr("gateway.platform_skill_reload._reload_catalog", catalog)
    runner = _runner()
    first = asyncio.create_task(reload_platform_skills(runner))
    await asyncio.to_thread(started.wait, 5)
    first.cancel()
    # A scheduled callback is a deterministic event-loop barrier, not a sleep.
    second = asyncio.create_task(reload_platform_skills(runner))
    barrier = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(barrier.set_result, None)
    await barrier
    try:
        assert not first.done()
        assert runner._platform_skills_reload_lock.locked()
        assert calls == 1
    finally:
        release.set()
        await asyncio.gather(first, second, return_exceptions=True)
    assert overlapped == [False]
