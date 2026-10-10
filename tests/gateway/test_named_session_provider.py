"""Named endpoints must survive session model selection and restart."""

import json
import threading

import pytest
import yaml

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.api_server import APIServerAdapter, _ProviderAuthResolutionError
from gateway.run import GatewayRunner
from gateway.session import SessionSource, SessionStore
from gateway.session import sanitize_model_override


@pytest.fixture
def profile(tmp_path, monkeypatch):
    import gateway.run as gateway_run

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("PIEVERSE_TEST_API_KEY", "test-pieverse-key")
    monkeypatch.setenv("OTHER_TEST_API_KEY", "test-other-key")
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    config = {
        "model": {"provider": "pieverse", "default": "auto/paid"},
        "providers": {
            "pieverse": {
                "base_url": "http://pieverse.test/v1",
                "key_env": "PIEVERSE_TEST_API_KEY",
            },
            "other": {
                "base_url": "http://other.test/v1",
                "key_env": "OTHER_TEST_API_KEY",
            },
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(config))
    return tmp_path


@pytest.fixture
def adapter(profile, monkeypatch):
    # Only replace the downstream model client. Config and auth resolution
    # remain real, so the test catches endpoint/credential changes.
    import run_agent

    class CapturingAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr(run_agent, "AIAgent", CapturingAgent)
    result = APIServerAdapter(PlatformConfig(enabled=True))
    monkeypatch.setattr(result, "_ensure_session_db", lambda: None)
    return result


@pytest.mark.parametrize("selection", ["session", "request"])
def test_model_selection_keeps_named_endpoint_credentials(adapter, selection):
    kwargs = (
        {"session_model": "selected-model"}
        if selection == "session"
        else {"requested_model": "selected-model"}
    )
    agent = adapter._create_agent(session_id="api-session", **kwargs)
    assert agent.kwargs["model"] == "selected-model"
    assert agent.kwargs["base_url"] == "http://pieverse.test/v1"
    assert agent.kwargs["api_key"] == "test-pieverse-key"
    assert agent.kwargs["provider"] == "custom"
    assert agent.kwargs["requested_provider"] == "pieverse"


def test_explicit_provider_selection_keeps_its_identity(adapter):
    agent = adapter._create_agent(
        requested_provider="other", requested_model="other-model"
    )
    assert agent.kwargs["base_url"] == "http://other.test/v1"
    assert agent.kwargs["api_key"] == "test-other-key"
    assert agent.kwargs["requested_provider"] == "other"


def test_session_model_refresh_reads_rotated_credentials(adapter, monkeypatch):
    adapter._create_agent(session_model="selected-model")
    monkeypatch.setenv("PIEVERSE_TEST_API_KEY", "test-rotated-key")
    agent = adapter._create_agent(session_model="selected-model")
    assert agent.kwargs["api_key"] == "test-rotated-key"
    assert agent.kwargs["base_url"] == "http://pieverse.test/v1"


def test_missing_explicit_provider_never_borrows_global_credentials(adapter):
    with pytest.raises(_ProviderAuthResolutionError):
        adapter._create_agent(
            requested_provider="missing-provider", requested_model="fixed-model"
        )


@pytest.mark.parametrize("stored_provider", ["pieverse", "custom"])
def test_restored_override_recovers_named_provider(profile, stored_provider):
    store = SessionStore(sessions_dir=profile / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(
        SessionSource(platform=Platform.TELEGRAM, chat_id="test", chat_type="dm")
    )
    key = entry.session_key
    store.set_model_override(
        key,
        {
            "model": "auto/adaptive",
            "provider": stored_provider,
            "base_url": "http://pieverse.test/v1",
            "api_key": "must-not-persist",
        },
    )
    runner = object.__new__(GatewayRunner)
    runner.session_store = SessionStore(
        sessions_dir=profile / "sessions", config=GatewayConfig()
    )
    runner._session_model_overrides = {}
    runner.config = None
    runner._rehydrate_session_model_override(key)
    model, runtime = runner._resolve_session_agent_runtime(session_key=key)
    assert model == "auto/adaptive"
    assert runtime["base_url"] == "http://pieverse.test/v1"
    assert runtime["api_key"] == "test-pieverse-key"
    assert runtime["provider"] == "custom"
    assert runtime["requested_provider"] in {"pieverse", "custom:pieverse"}
    persisted = store.get_model_override(key)
    assert "api_key" not in persisted
    assert "must-not-persist" not in json.dumps(persisted)


def test_unresolvable_session_provider_never_inherits_global_credentials(profile):
    runner = object.__new__(GatewayRunner)
    runner.session_store = None
    runner.config = None
    runner._session_model_overrides = {
        "session": {"model": "fixed-model", "provider": "missing-provider"}
    }
    with pytest.raises(RuntimeError):
        runner._resolve_session_agent_runtime(session_key="session")


def test_session_refresh_uses_current_provider_key_not_cached_key(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_session_model_override_for", lambda _: {
        "model": "selected-model", "provider": "custom", "requested_provider": "pieverse",
        "api_key": "old-key", "base_url": "http://pieverse.test/v1",
    })
    agent = adapter._create_agent(session_id="session")
    assert agent.kwargs["provider"] == "custom"
    assert agent.kwargs["requested_provider"] == "pieverse"
    assert agent.kwargs["api_key"] == "test-pieverse-key"


def test_session_auth_failure_does_not_reuse_cached_or_global_key(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_session_model_override_for", lambda _: {
        "model": "fixed-model", "provider": "missing-provider",
        "api_key": "old-key", "base_url": "http://removed.test/v1",
    })
    with pytest.raises(_ProviderAuthResolutionError):
        adapter._create_agent(session_id="session")


def test_provider_switch_drops_previous_credential_pool(adapter, monkeypatch):
    import gateway.run as gateway_run

    original = gateway_run._resolve_runtime_agent_kwargs
    def global_runtime():
        return {**original(), "credential_pool": object()}
    monkeypatch.setattr(gateway_run, "_resolve_runtime_agent_kwargs", global_runtime)
    agent = adapter._create_agent(requested_provider="other", requested_model="other-model")
    assert agent.kwargs["credential_pool"] is None
    assert agent.kwargs["api_key"] == "test-other-key"
    assert agent.kwargs["base_url"] == "http://other.test/v1"


def test_persistence_uses_logical_identity_without_auth_bundle():
    assert sanitize_model_override({
        "model": "selected-model", "provider": "custom", "requested_provider": "pieverse",
        "api_key": "secret", "credential_pool": object(),
    }) == {"model": "selected-model", "provider": "pieverse"}


def test_legacy_unknown_endpoint_cannot_borrow_current_provider(profile):
    runner = object.__new__(GatewayRunner)
    runner.session_store = None
    runner.config = None
    runner._session_model_overrides = {"session": {
        "model": "selected-model", "provider": "custom", "base_url": "http://removed.test/v1",
    }}
    with pytest.raises(RuntimeError, match="Cannot recover"):
        runner._resolve_session_agent_runtime(session_key="session")


@pytest.mark.asyncio
async def test_native_telegram_model_selection_persists_logical_provider(profile, monkeypatch):
    from gateway.platforms.base import MessageEvent

    # Catalog/context display data are offline; provider/auth resolution and
    # the native command, session store, and following turn remain real.
    monkeypatch.setattr("agent.models_dev.fetch_models_dev", lambda: {})
    monkeypatch.setattr("hermes_cli.models.validate_requested_model", lambda *a, **kw: {
        "accepted": True, "recognized": False, "persist": True,
    })
    runner = object.__new__(GatewayRunner)
    runner.config = None
    runner.adapters = {}
    runner._voice_mode = {}
    runner._running_agents = {}
    runner._agent_cache = {}
    runner._agent_cache_lock = threading.RLock()
    runner._session_model_overrides = {}
    runner.session_store = SessionStore(profile / "sessions", GatewayConfig())
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="test", chat_type="dm")
    entry = runner.session_store.get_or_create_session(source)
    reply = await runner._handle_model_command(MessageEvent(
        text="/model selected-model --provider pieverse --session", source=source,
    ))
    assert "selected-model" in reply
    model, runtime = runner._resolve_session_agent_runtime(session_key=entry.session_key)
    assert model == "selected-model"
    assert runtime["provider"] == "custom"
    assert runtime["requested_provider"] in {"pieverse", "custom:pieverse"}
    assert runtime["api_key"] == "test-pieverse-key"
    assert runtime["base_url"] == "http://pieverse.test/v1"
    persisted = runner.session_store.get_model_override(entry.session_key)
    assert persisted["provider"] in {"pieverse", "custom:pieverse"}
    assert "api_key" not in persisted
