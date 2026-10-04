"""Native REST conversations use the official background title generator."""

import asyncio
import threading
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from hermes_state import SessionDB


@pytest_asyncio.fixture
async def native_chat(tmp_path, monkeypatch):
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("native-chat", source="api_server")
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    started, release = threading.Event(), threading.Event()
    llm_requests = []
    outcome = {}

    def title_llm(**kwargs):
        llm_requests.append(kwargs)
        started.set()
        assert release.wait(5), "test must release the background title request"
        if outcome.get("title_error"):
            raise RuntimeError("auxiliary provider unavailable")
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content="Ethereum Spot Venue Comparison"),
        )])

    class ConversationAgent:
        session_id = "native-chat"
        model, provider = "existing-model", "existing-provider"
        base_url, api_key, api_mode = "https://provider.invalid", "test-key", "chat_completions"
        _session_db = db

        def run_conversation(self, user_message, conversation_history, **kwargs):
            db.append_message(self.session_id, "user", user_message)
            db.append_message(self.session_id, "assistant", "Here is the ETH spot comparison.")
            return {
                "final_response": "Here is the ETH spot comparison.",
                "messages": db.get_messages_as_conversation(self.session_id),
                **outcome,
            }

    monkeypatch.setattr(adapter, "_create_agent", lambda **kwargs: ConversationAgent())
    monkeypatch.setattr("agent.title_generator.call_llm", title_llm)
    app = web.Application(middlewares=[adapter._make_profile_prefix_middleware()])
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_post("/p/{profile}/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/p/{profile}/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
    app.router.add_get("/api/sessions/{session_id}", adapter._handle_get_session)
    app.router.add_post("/api/sessions/{session_id}/chat", adapter._handle_session_chat)
    app.router.add_post("/p/{profile}/api/sessions/{session_id}/chat", adapter._handle_session_chat)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        yield SimpleNamespace(
            client=client, adapter=adapter, db=db, started=started, release=release,
            requests=llm_requests, outcome=outcome,
        )
    finally:
        release.set()
        for task in list(adapter._active_run_tasks.values()):
            await task
        await client.close()
        for thread in threading.enumerate():
            if thread.name == "auto-title":
                await asyncio.to_thread(thread.join, 5)
        db.close()


async def send(chat, path, headers=None):
    message = "Please compare Ethereum spot markets across the supported exchanges."
    is_run = path.endswith("/v1/runs")
    body = {"input": message, "session_id": "native-chat"} if is_run else {"message": message}
    response = await chat.client.post(path, json=body, headers=headers)
    assert response.status == (202 if is_run else 200)
    result = await response.json()
    if is_run:
        run_id = result["run_id"]
        async with asyncio.timeout(3):
            while True:
                response = await chat.client.get(f"{path}/{run_id}", headers=headers)
                result = await response.json()
                if result["status"] not in ("queued", "running"):
                    break
                await asyncio.sleep(0.01)
    return result


async def wait_for_title(chat, expected):
    async with asyncio.timeout(3):
        while True:
            response = await chat.client.get("/api/sessions/native-chat")
            data = await response.json()
            if data["session"].get("title") == expected:
                return
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/runs", "/api/sessions/native-chat/chat"])
async def test_native_title_is_generated_without_delaying_reply_or_changing_history(native_chat, path):
    result = await send(native_chat, path)
    if path == "/v1/runs":
        assert result["status"] == "completed"
    assert await asyncio.to_thread(native_chat.started.wait, 2)
    assert native_chat.db.get_session_title("native-chat") is None
    native_chat.release.set()
    await wait_for_title(native_chat, "Ethereum Spot Venue Comparison")
    assert [message["role"] for message in native_chat.db.get_messages_as_conversation("native-chat")] == ["user", "assistant"]
    assert native_chat.requests[0]["main_runtime"]["model"] == "existing-model"


@pytest.mark.asyncio
async def test_manual_title_wins_while_official_generator_is_pending(native_chat):
    await send(native_chat, "/v1/runs")
    assert await asyncio.to_thread(native_chat.started.wait, 2)
    native_chat.db.set_session_title("native-chat", "My custom research")
    native_chat.release.set()
    for thread in threading.enumerate():
        if thread.name == "auto-title":
            await asyncio.to_thread(thread.join, 3)
    await wait_for_title(native_chat, "My custom research")


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [{"failed": True}, {"interrupted": True}, {"partial": True}, {"completed": False}])
async def test_incomplete_turn_does_not_generate_a_title(native_chat, outcome):
    native_chat.outcome.update(outcome)
    await send(native_chat, "/v1/runs")
    assert native_chat.requests == []
    assert native_chat.db.get_session_title("native-chat") is None


@pytest.mark.asyncio
async def test_title_provider_failure_does_not_fail_completed_chat(native_chat):
    native_chat.outcome["title_error"] = True
    native_chat.release.set()
    result = await send(native_chat, "/v1/runs")
    assert result["status"] == "completed"
    assert await asyncio.to_thread(native_chat.started.wait, 2)
    for thread in threading.enumerate():
        if thread.name == "auto-title":
            await asyncio.to_thread(thread.join, 3)
    assert native_chat.db.get_session_title("native-chat") is None


@pytest.mark.asyncio
async def test_real_agent_persists_exchange_and_generates_title_through_rest(native_chat, monkeypatch):
    from openai.types.chat import ChatCompletion
    from run_agent import AIAgent

    completion = ChatCompletion(
        id="offline-completion", object="chat.completion", created=0, model="test-model",
        choices=[{"index": 0, "finish_reason": "stop", "message": {
            "role": "assistant", "content": "Here is the ETH spot comparison.",
        }}],
        usage={"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
    )
    monkeypatch.setattr(AIAgent, "_interruptible_api_call", lambda self, api_kwargs: completion)
    monkeypatch.setattr(AIAgent, "_interruptible_streaming_api_call",
                        lambda self, api_kwargs, **options: completion)
    monkeypatch.setattr(native_chat.adapter, "_create_agent", lambda **kwargs: AIAgent(
        model="test-model", provider="openai", api_key="offline-test-key",
        base_url="https://provider.invalid/v1", enabled_toolsets=[],
        session_id=kwargs["session_id"], session_db=native_chat.db, platform="api_server",
        quiet_mode=True, skip_context_files=True, skip_memory=True,
    ))
    result = await send(native_chat, "/v1/runs")
    assert result["status"] == "completed"
    assert result["output"] == "Here is the ETH spot comparison."
    assert await asyncio.to_thread(native_chat.started.wait, 2)
    native_chat.release.set()
    await wait_for_title(native_chat, "Ethereum Spot Venue Comparison")
    messages = native_chat.db.get_messages_as_conversation("native-chat")
    assert [m["role"] for m in messages if m["role"] != "system"] == ["user", "assistant"]
    assert messages[-1]["content"] == "Here is the ETH spot comparison."


@pytest.mark.asyncio
async def test_stop_before_completion_does_not_generate_a_title(native_chat, monkeypatch):
    finishing, release_finish = threading.Event(), threading.Event()
    create_agent = native_chat.adapter._create_agent

    def create_delayed_agent(**kwargs):
        agent = create_agent(**kwargs)
        original = agent.run_conversation

        def delayed_finish(*args, **kwargs):
            result = original(*args, **kwargs)
            finishing.set()
            assert release_finish.wait(5)
            return result

        agent.run_conversation = delayed_finish
        return agent

    monkeypatch.setattr(native_chat.adapter, "_create_agent", create_delayed_agent)
    response = await native_chat.client.post("/v1/runs", json={
        "input": "Compare Ethereum spot venues", "session_id": "native-chat",
    })
    run_id = (await response.json())["run_id"]
    try:
        assert await asyncio.to_thread(finishing.wait, 2)
        stop = await native_chat.client.post(f"/v1/runs/{run_id}/stop")
        assert stop.status == 200
        release_finish.set()
        native_chat.release.set()
        async with asyncio.timeout(3):
            while True:
                response = await native_chat.client.get(f"/v1/runs/{run_id}")
                status = (await response.json())["status"]
                if status in ("cancelled", "completed"):
                    break
                await asyncio.sleep(0.01)
        assert status == "cancelled"
        assert native_chat.requests == []
        assert native_chat.db.get_session_title("native-chat") is None
    finally:
        release_finish.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/runs", "/api/sessions/native-chat/chat"])
@pytest.mark.parametrize("profile", ["default", "worker"])
async def test_context_scoped_profile_does_not_use_default_title_provider(
    native_chat, path, profile, tmp_path, monkeypatch,
):
    from agent import secret_scope
    from gateway.config import GatewayConfig

    worker_home = tmp_path / "profiles" / "worker"
    worker_home.mkdir(parents=True)
    profile_key = "a" * 32
    (worker_home / ".env").write_text(f"API_SERVER_KEY={profile_key}\n", encoding="utf-8")
    native_chat.adapter.gateway_runner = SimpleNamespace(config=GatewayConfig(multiplex_profiles=True))
    monkeypatch.setattr("hermes_cli.profiles.profiles_to_serve", lambda multiplex: [
        ("default", tmp_path), ("worker", worker_home),
    ])
    monkeypatch.setattr("hermes_cli.profiles.get_profile_dir", lambda name:
                        tmp_path if name == "default" else worker_home)
    secret_scope.set_multiplex_active(True)
    try:
        await send(native_chat, f"/p/{profile}{path}", headers={"Authorization": f"Bearer {profile_key}"})
        assert native_chat.requests == []
        assert native_chat.db.get_session_title("native-chat") is None
    finally:
        secret_scope.set_multiplex_active(False)
