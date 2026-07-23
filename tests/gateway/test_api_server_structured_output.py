"""Request-local structured-output controls for the API server."""

import asyncio
import json
import math
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.transports.chat_completions import ChatCompletionsTransport
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from providers import get_provider_profile


def _app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    return app


def _result(text: str = '{"status":"ok"}', reasoning: str | None = None):
    return (
        {
            "final_response": text,
            "last_reasoning": reasoning,
            "completed": True,
            "failed": False,
            "partial": False,
        },
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    )


@pytest.mark.asyncio
async def test_structured_contract_is_strict_and_passed_request_locally():
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
        run_agent.return_value = _result(reasoning='analysis\n{"status":"ok"}')
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"X-Hermes-Structured-Output": "devops-structured-v1"},
                json={
                    "model": "MiniMax-M3",
                    "stream": False,
                    "temperature": 0.1,
                    "thinking": {"type": "disabled"},
                    "messages": [{"role": "user", "content": "Return JSON."}],
                },
            )
            payload = await response.json()

        assert response.status == 200
        kwargs = run_agent.await_args.kwargs
        assert kwargs["request_overrides"] == {
            "temperature": 0.1,
            "extra_body": {"thinking": {"type": "disabled"}},
        }
        assert kwargs["reasoning_config_override"] == {"enabled": False}
        assert payload["choices"][0]["message"]["reasoning_content"] == (
            'analysis\n{"status":"ok"}'
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"temperature": 0.1},
        {"thinking": {"type": "disabled"}},
        {"temperature": True, "thinking": {"type": "disabled"}},
        {"temperature": 0.2, "thinking": {"type": "disabled"}},
        {"temperature": 0.1, "thinking": {"type": "enabled"}},
        {"temperature": 0.1, "thinking": {"type": "disabled", "extra": True}},
        {"stream": "garbage", "temperature": 0.1, "thinking": {"type": "disabled"}},
        {"stream": [], "temperature": 0.1, "thinking": {"type": "disabled"}},
        {"stream": {}, "temperature": 0.1, "thinking": {"type": "disabled"}},
        {"stream": 0, "temperature": 0.1, "thinking": {"type": "disabled"}},
        {"stream": None, "temperature": 0.1, "thinking": {"type": "disabled"}},
    ],
)
async def test_structured_contract_rejects_any_non_exact_controls(body):
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    request_body = {
        "model": "MiniMax-M3",
        "stream": False,
        "messages": [{"role": "user", "content": "Return JSON."}],
        **body,
    }
    with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"X-Hermes-Structured-Output": "devops-structured-v1"},
                json=request_body,
            )

        assert response.status == 400
        run_agent.assert_not_awaited()


@pytest.mark.asyncio
async def test_ordinary_request_controls_are_strict_and_passed_request_locally():
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
        run_agent.return_value = _result()
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "MiniMax-M3",
                    "temperature": 0.7,
                    "thinking": {"type": "adaptive"},
                    "messages": [{"role": "user", "content": "ordinary"}],
                },
            )

    assert response.status == 200
    assert run_agent.await_args.kwargs["request_overrides"] == {
        "temperature": 0.7,
        "extra_body": {"thinking": {"type": "adaptive"}},
    }
    assert run_agent.await_args.kwargs["reasoning_config_override"] == {
        "enabled": True
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("temperature", True),
        ("temperature", "0.1"),
        ("temperature", -0.01),
        ("temperature", 2.01),
        ("temperature", math.inf),
        ("temperature", math.nan),
        ("thinking", "disabled"),
        ("thinking", {"type": "enabled"}),
        ("thinking", {"type": "adaptive", "extra": True}),
    ],
)
async def test_ordinary_request_rejects_invalid_explicit_controls(field, value):
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    body = {
        "model": "MiniMax-M3",
        "messages": [{"role": "user", "content": "ordinary"}],
        field: value,
    }
    with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/chat/completions",
                data=json.dumps(body),
                headers={"Content-Type": "application/json"},
            )

    assert response.status == 400
    run_agent.assert_not_awaited()


@pytest.mark.asyncio
async def test_ordinary_controls_do_not_leak_to_subsequent_requests():
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
        run_agent.return_value = _result()
        async with TestClient(TestServer(_app(adapter))) as client:
            controlled = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "MiniMax-M3",
                    "temperature": 0.7,
                    "thinking": {"type": "adaptive"},
                    "messages": [{"role": "user", "content": "controlled"}],
                },
            )
            unrelated = await client.post(
                "/v1/chat/completions",
                json={"messages": [{"role": "user", "content": "unrelated"}]},
            )

    assert [controlled.status, unrelated.status] == [200, 200]
    first, second = run_agent.await_args_list
    assert first.kwargs["request_overrides"] == {
        "temperature": 0.7,
        "extra_body": {"thinking": {"type": "adaptive"}},
    }
    assert first.kwargs["reasoning_config_override"] == {"enabled": True}
    assert second.kwargs["request_overrides"] is None
    assert second.kwargs["reasoning_config_override"] is None


@pytest.mark.asyncio
async def test_structured_controls_do_not_leak_to_subsequent_or_concurrent_requests():
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    entered = asyncio.Event()
    release = asyncio.Event()
    seen = {}

    async def run_agent(**kwargs):
        seen[kwargs["user_message"]] = {
            "request_overrides": kwargs.get("request_overrides"),
            "reasoning_config_override": kwargs.get("reasoning_config_override"),
        }
        if len(seen) == 2:
            entered.set()
        await release.wait()
        return _result()

    with patch.object(adapter, "_run_agent", side_effect=run_agent):
        async with TestClient(TestServer(_app(adapter))) as client:
            structured = asyncio.create_task(
                client.post(
                    "/v1/chat/completions",
                    headers={"X-Hermes-Structured-Output": "devops-structured-v1"},
                    json={
                        "temperature": 0.1,
                        "thinking": {"type": "disabled"},
                        "messages": [{"role": "user", "content": "structured"}],
                    },
                )
            )
            unrelated = asyncio.create_task(
                client.post(
                    "/v1/chat/completions",
                    json={"messages": [{"role": "user", "content": "unrelated"}]},
                )
            )
            await entered.wait()
            release.set()
            responses = await asyncio.gather(structured, unrelated)

        assert [response.status for response in responses] == [200, 200]
        assert seen["structured"] == {
            "request_overrides": {
                "temperature": 0.1,
                "extra_body": {"thinking": {"type": "disabled"}},
            },
            "reasoning_config_override": {"enabled": False},
        }
        assert seen["unrelated"] == {
            "request_overrides": None,
            "reasoning_config_override": None,
        }


@pytest.mark.asyncio
async def test_ordinary_controls_do_not_leak_to_concurrent_requests():
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    entered = asyncio.Event()
    release = asyncio.Event()
    seen = {}

    async def run_agent(**kwargs):
        seen[kwargs["user_message"]] = {
            "request_overrides": kwargs.get("request_overrides"),
            "reasoning_config_override": kwargs.get("reasoning_config_override"),
        }
        if len(seen) == 2:
            entered.set()
        await release.wait()
        return _result()

    with patch.object(adapter, "_run_agent", side_effect=run_agent):
        async with TestClient(TestServer(_app(adapter))) as client:
            controlled = asyncio.create_task(
                client.post(
                    "/v1/chat/completions",
                    json={
                        "temperature": 0.7,
                        "thinking": {"type": "adaptive"},
                        "messages": [{"role": "user", "content": "controlled"}],
                    },
                )
            )
            unrelated = asyncio.create_task(
                client.post(
                    "/v1/chat/completions",
                    json={"messages": [{"role": "user", "content": "unrelated"}]},
                )
            )
            await entered.wait()
            release.set()
            responses = await asyncio.gather(controlled, unrelated)

    assert [response.status for response in responses] == [200, 200]
    assert seen["controlled"] == {
        "request_overrides": {
            "temperature": 0.7,
            "extra_body": {"thinking": {"type": "adaptive"}},
        },
        "reasoning_config_override": {"enabled": True},
    }
    assert seen["unrelated"] == {
        "request_overrides": None,
        "reasoning_config_override": None,
    }


@pytest.mark.asyncio
async def test_structured_response_omits_oversized_reasoning_content():
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
        run_agent.return_value = _result(reasoning="x" * ((48 * 1024) + 1))
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"X-Hermes-Structured-Output": "devops-structured-v1"},
                json={
                    "stream": False,
                    "temperature": 0.1,
                    "thinking": {"type": "disabled"},
                    "messages": [{"role": "user", "content": "Return JSON."}],
                },
            )
            payload = await response.json()

    assert response.status == 200
    assert "reasoning_content" not in payload["choices"][0]["message"]


def test_create_agent_keeps_structured_controls_on_one_fresh_agent(monkeypatch):
    captured = []

    class FakeAgent:
        def __init__(self, **kwargs):
            captured.append(kwargs)

    monkeypatch.setattr("run_agent.AIAgent", FakeAgent)
    monkeypatch.setattr(
        "gateway.run._resolve_runtime_agent_kwargs",
        lambda: {
            "provider": "minimax",
            "base_url": "https://api.minimax.io/v1",
            "api_mode": "chat_completions",
        },
    )
    monkeypatch.setattr("gateway.run._resolve_gateway_model", lambda: "MiniMax-M3")
    monkeypatch.setattr("gateway.run._load_gateway_config", lambda: {})
    monkeypatch.setattr(
        "gateway.run.GatewayRunner._load_reasoning_config",
        staticmethod(lambda: {"enabled": True, "effort": "medium"}),
    )
    monkeypatch.setattr(
        "gateway.run.GatewayRunner._load_fallback_model", staticmethod(lambda: None)
    )
    monkeypatch.setattr("gateway.run._current_max_iterations", lambda: 90)
    monkeypatch.setattr("hermes_cli.tools_config._get_platform_tools", lambda *_: set())

    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    monkeypatch.setattr(adapter, "_ensure_session_db", lambda: None)
    structured_overrides = {
        "temperature": 0.1,
        "extra_body": {"thinking": {"type": "disabled"}},
    }

    adapter._create_agent(
        session_id="structured",
        request_overrides=structured_overrides,
        reasoning_config_override={"enabled": False},
    )
    adapter._create_agent(session_id="unrelated")

    assert captured[0]["request_overrides"] == structured_overrides
    assert captured[0]["reasoning_config"] == {"enabled": False}
    assert captured[1].get("request_overrides") in (None, {})
    assert captured[1]["reasoning_config"] == {"enabled": True, "effort": "medium"}
    assert structured_overrides == {
        "temperature": 0.1,
        "extra_body": {"thinking": {"type": "disabled"}},
    }


def test_minimax_provider_wire_kwargs_keep_exact_structured_controls():
    transport = ChatCompletionsTransport()
    profile = get_provider_profile("minimax")
    kwargs = transport.build_kwargs(
        model="MiniMax-M3",
        messages=[{"role": "user", "content": "Return JSON."}],
        provider_profile=profile,
        base_url="https://api.minimax.io/v1",
        reasoning_config={"enabled": False},
        request_overrides={
            "temperature": 0.1,
            "extra_body": {"thinking": {"type": "disabled"}},
        },
    )

    assert kwargs["temperature"] == 0.1
    assert kwargs["extra_body"]["thinking"] == {"type": "disabled"}
