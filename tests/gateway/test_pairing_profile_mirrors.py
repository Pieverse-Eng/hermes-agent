"""Pairing mirrors stay within their store's profile and current grant state."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from agent import secret_scope
from gateway import pairing
from gateway.config import Platform
from hermes_constants import reset_hermes_home_override, set_hermes_home_override


@contextmanager
def profile_scope(home):
    home_token = set_hermes_home_override(home)
    secret_token = secret_scope.set_secret_scope(secret_scope.build_profile_secret_scope(home))
    try:
        yield
    finally:
        secret_scope.reset_secret_scope(secret_token)
        reset_hermes_home_override(home_token)


@pytest.fixture
def profile_homes(tmp_path, monkeypatch):
    root = tmp_path / "hermes"
    root.mkdir()
    homes = {"default": root, "alpha": root / "profiles" / "alpha", "beta": root / "profiles" / "beta"}
    for name, home in homes.items():
        home.mkdir(parents=True, exist_ok=True)
        (home / ".env").write_text(f"TELEGRAM_ALLOWED_USERS={name}-owner,shared\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(pairing, "get_default_hermes_root", lambda: root)
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "default-owner,shared")
    monkeypatch.setattr(pairing, "PAIRING_DIR", root / "platforms" / "pairing")
    monkeypatch.setattr(secret_scope, "_MULTIPLEX_ACTIVE", True)
    return homes


@pytest.mark.parametrize("operation", ["approve", "revoke"])
def test_profile_mirror_does_not_mutate_process_allowlist(profile_homes, operation):
    store = pairing.PairingStore(profile="alpha")
    if operation == "revoke":
        store.replace_approved("telegram", ["shared"])
    root_before = (profile_homes["default"] / ".env").read_bytes()

    with profile_scope(profile_homes["alpha"]):
        if operation == "approve":
            code = store.generate_code("telegram", "new-user")
            assert store.approve_code("telegram", code)["user_id"] == "new-user"
            expected = "alpha-owner,shared,new-user"
        else:
            assert store.revoke("telegram", "shared") is True
            expected = "alpha-owner"

    assert secret_scope.load_env_file(profile_homes["alpha"] / ".env")["TELEGRAM_ALLOWED_USERS"] == expected
    assert (profile_homes["default"] / ".env").read_bytes() == root_before
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared"


def test_revoke_updates_only_the_owning_profiles_live_adapter(profile_homes, monkeypatch):
    import gateway.run as gateway_run

    stores = {name: pairing.PairingStore(profile=None if name == "default" else name)
              for name in profile_homes}
    stores["alpha"].replace_approved("telegram", ["shared"])

    def adapter(name):
        return SimpleNamespace(platform=Platform.TELEGRAM, _allow_from={name + "-owner", "shared"},
                               config=SimpleNamespace(extra={"allow_from": [name + "-owner", "shared"]}))

    adapters = {name: adapter(name) for name in profile_homes}
    runner = SimpleNamespace(
        pairing_store=stores["default"], pairing_stores=stores,
        adapters={Platform.TELEGRAM: adapters["default"]},
        _profile_adapters={name: {Platform.TELEGRAM: adapters[name]} for name in ("alpha", "beta")},
    )
    monkeypatch.setattr(gateway_run, "_gateway_runner_ref", lambda: runner)
    # A second control surface may use another store instance for the same home.
    store = pairing.PairingStore(profile="alpha")
    with profile_scope(profile_homes["alpha"]):
        assert store.revoke("telegram", "shared") is True

    assert adapters["alpha"]._allow_from == {"alpha-owner"}
    assert adapters["alpha"].config.extra["allow_from"] == ["alpha-owner"]
    for name in ("default", "beta"):
        assert adapters[name]._allow_from == {name + "-owner", "shared"}
        assert adapters[name].config.extra["allow_from"] == [name + "-owner", "shared"]


def test_multiple_revokes_in_one_scope_do_not_resurrect_prior_grants(profile_homes):
    store = pairing.PairingStore(profile="alpha")
    (profile_homes["alpha"] / ".env").write_text(
        "TELEGRAM_ALLOWED_USERS=alpha-owner,first-user,second-user\n", encoding="utf-8")
    store.replace_approved("telegram", ["first-user", "second-user"])

    with profile_scope(profile_homes["alpha"]):
        assert store.revoke("telegram", "first-user") is True
        assert store.revoke("telegram", "second-user") is True

    assert store.list_approved("telegram") == []
    assert secret_scope.load_env_file(profile_homes["alpha"] / ".env")["TELEGRAM_ALLOWED_USERS"] == "alpha-owner"


def test_multiple_approvals_in_one_scope_preserve_earlier_mirrors(profile_homes):
    store = pairing.PairingStore(profile="alpha")
    with profile_scope(profile_homes["alpha"]):
        for user_id in ("first-user", "second-user"):
            code = store.generate_code("telegram", user_id)
            assert store.approve_code("telegram", code)["user_id"] == user_id

    assert secret_scope.load_env_file(profile_homes["alpha"] / ".env")["TELEGRAM_ALLOWED_USERS"] == (
        "alpha-owner,shared,first-user,second-user"
    )


def test_explicit_profile_mirror_uses_store_home_without_request_scope(profile_homes):
    store = pairing.PairingStore(profile="alpha")
    root_before = (profile_homes["default"] / ".env").read_bytes()
    code = store.generate_code("telegram", "new-user")
    assert store.approve_code("telegram", code)["user_id"] == "new-user"

    assert secret_scope.load_env_file(profile_homes["alpha"] / ".env")["TELEGRAM_ALLOWED_USERS"] == (
        "alpha-owner,shared,new-user"
    )
    assert (profile_homes["default"] / ".env").read_bytes() == root_before
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared"


def test_profile_without_allowlist_does_not_borrow_process_allowlist(profile_homes):
    store = pairing.PairingStore(profile="alpha")
    (profile_homes["alpha"] / ".env").write_text("", encoding="utf-8")
    code = store.generate_code("telegram", "new-user")
    assert store.approve_code("telegram", code)["user_id"] == "new-user"
    assert store.is_approved("telegram", "new-user") is True
    assert (profile_homes["alpha"] / ".env").read_text(encoding="utf-8") == ""
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared"


@pytest.mark.parametrize(
    ("user_id", "pending_only", "removed", "pending_removed", "remaining", "pending_remaining"),
    [
        (None, False, 2, 2, [], []),
        ("first-user", False, 1, 1, ["second-user"], ["second-user"]),
        (None, True, 0, 2, ["first-user", "second-user"], []),
    ],
)
def test_batch_revoke_returns_current_state_and_updates_one_mirror(
    profile_homes, monkeypatch, user_id, pending_only, removed, pending_removed,
    remaining, pending_remaining,
):
    import hermes_cli.config as config

    store = pairing.PairingStore(profile="alpha")
    (profile_homes["alpha"] / ".env").write_text(
        "TELEGRAM_ALLOWED_USERS=alpha-owner,first-user,second-user\n", encoding="utf-8")
    store.replace_approved("telegram", ["first-user", "second-user"])
    for entry in ("first-user", "second-user"):
        assert store.generate_code("telegram", entry) is not None

    approved_writes = []
    mirror_writes = []
    save_json = store._save_json
    save_env = config.save_env_value

    def record_save_json(path, data):
        if path == store._approved_path("telegram"):
            approved_writes.append(dict(data))
        return save_json(path, data)

    def record_save_env(key, value, **kwargs):
        mirror_writes.append((key, value))
        return save_env(key, value, **kwargs)

    monkeypatch.setattr(store, "_save_json", record_save_json)
    monkeypatch.setattr(config, "save_env_value", record_save_env)
    with profile_scope(profile_homes["alpha"]):
        result = store.revoke_pairings("telegram", user_id, pending_only=pending_only)

    assert result[:2] == (removed, pending_removed)
    assert [record["user_id"] for record in result[2]] == remaining
    assert [record["user_id"] for record in store.list_pending("telegram")] == pending_remaining
    assert len(approved_writes) == (1 if removed else 0)
    assert len(mirror_writes) == (1 if removed else 0)
    expected_allowlist = ",".join(["alpha-owner", *remaining])
    assert secret_scope.load_env_file(profile_homes["alpha"] / ".env")["TELEGRAM_ALLOWED_USERS"] == expected_allowlist
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared"


def test_single_profile_mirrors_keep_process_environment_behavior(profile_homes, monkeypatch):
    monkeypatch.setattr(secret_scope, "_MULTIPLEX_ACTIVE", False)
    store = pairing.PairingStore()
    code = store.generate_code("telegram", "new-user")
    assert store.approve_code("telegram", code)["user_id"] == "new-user"
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared,new-user"
    assert store.revoke("telegram", "new-user") is True
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared"


def test_legacy_revoke_without_user_does_not_become_bulk_revoke(profile_homes):
    store = pairing.PairingStore(profile="alpha")
    store.replace_approved("telegram", ["shared"])
    assert store.revoke("telegram", None) is False
    assert store.is_approved("telegram", "shared") is True


def test_last_profile_allowlist_removal_keeps_process_allowlist(profile_homes):
    store = pairing.PairingStore(profile="alpha")
    (profile_homes["alpha"] / ".env").write_text(
        "TELEGRAM_ALLOWED_USERS=shared\n", encoding="utf-8")
    store.replace_approved("telegram", ["shared"])
    with profile_scope(profile_homes["alpha"]):
        assert store.revoke("telegram", "shared") is True
    assert "TELEGRAM_ALLOWED_USERS" not in secret_scope.load_env_file(profile_homes["alpha"] / ".env")
    assert os.environ["TELEGRAM_ALLOWED_USERS"] == "default-owner,shared"


@pytest.mark.parametrize("remaining_users", [[], ["Ukeeper"]])
def test_line_revoke_updates_live_user_gate_without_affecting_other_grants(
    profile_homes, monkeypatch, remaining_users,
):
    import gateway.platform_registry as registry_module
    import gateway.run as gateway_run
    from gateway.config import PlatformConfig
    from tests.gateway._plugin_adapter_loader import load_plugin_adapter

    line = load_plugin_adapter("line")
    registry = registry_module.PlatformRegistry()
    line.register(SimpleNamespace(register_platform=lambda **kwargs: registry.register(
        registry_module.PlatformEntry(**kwargs)
    )))
    monkeypatch.setattr(registry_module, "platform_registry", registry)
    for name in ("LINE_ALLOW_ALL_USERS", "LINE_ALLOWED_GROUPS", "LINE_ALLOWED_ROOMS"):
        monkeypatch.delenv(name, raising=False)

    user_ids = ["Ushared", *remaining_users]
    monkeypatch.setenv("LINE_ALLOWED_USERS", ",".join(user_ids))
    env_file = profile_homes["default"] / ".env"
    env_file.write_text(
        env_file.read_text(encoding="utf-8") + f"LINE_ALLOWED_USERS={','.join(user_ids)}\n",
        encoding="utf-8",
    )
    stores = {
        "default": pairing.PairingStore(),
        "alpha": pairing.PairingStore(profile="alpha"),
    }
    for store in stores.values():
        store.replace_approved("line", ["Ushared"])

    def make_adapter(users):
        with monkeypatch.context() as local_env:
            local_env.setenv("LINE_ALLOWED_USERS", ",".join(users))
            return line.LineAdapter(PlatformConfig(enabled=True, extra={
                "channel_access_token": "test-token",
                "channel_secret": "test-secret",
                "allowed_users": list(users),
                "allowed_groups": ["Gkeeper"],
                "allowed_rooms": ["Rkeeper"],
            }))

    adapter = make_adapter(user_ids)
    other_adapter = make_adapter(["Ushared", "Uother"])
    runner = SimpleNamespace(
        pairing_store=stores["default"], pairing_stores=stores,
        adapters={Platform("line"): adapter},
        _profile_adapters={"alpha": {Platform("line"): other_adapter}},
    )
    monkeypatch.setattr(gateway_run, "_gateway_runner_ref", lambda: runner)
    source = {"type": "user", "userId": "Ushared"}

    with profile_scope(profile_homes["default"]):
        assert adapter._is_source_allowed(source) is True
        assert stores["default"].revoke_pairings("line", "Ushared") == (1, 0, [])
        assert adapter._is_source_allowed(source) is False
        for user_id in remaining_users:
            assert adapter._is_source_allowed({"type": "user", "userId": user_id}) is True
        assert adapter._is_source_allowed({"type": "group", "groupId": "Gkeeper"}) is True
        assert adapter._is_source_allowed({"type": "room", "roomId": "Rkeeper"}) is True

    assert adapter.allowed_users == set(remaining_users)
    assert adapter.config.extra["allowed_users"] == remaining_users
    assert other_adapter.allowed_users == {"Ushared", "Uother"}
    assert other_adapter.config.extra["allowed_users"] == ["Ushared", "Uother"]
    assert other_adapter._is_source_allowed(source) is True
    assert stores["alpha"].is_approved("line", "Ushared") is True
    assert os.environ["LINE_ALLOWED_USERS"] == ",".join(user_ids)
