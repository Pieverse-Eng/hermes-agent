"""Unit tests for fail-closed per-platform slash command access control."""
from __future__ import annotations

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.session import SessionSource
from gateway.slash_access import policy_for_source, policy_from_extra


class TestPolicyFromExtra:
    def test_missing_admin_list_fails_closed_for_privileged_command(self):
        policy = policy_from_extra({}, "dm")
        assert policy.enabled is True
        assert policy.admin_user_ids == frozenset()
        assert policy.is_admin("anyone") is False
        assert policy.can_run("anyone", "stop") is False
        assert policy.can_run("anyone", "help") is True

    def test_empty_admin_list_fails_closed_for_privileged_command(self):
        policy = policy_from_extra({"allow_admin_from": []}, "dm")
        assert policy.can_run("anyone", "restart") is False

    def test_malformed_admin_list_fails_closed_for_privileged_command(self):
        for malformed in ({"id": "111"}, True, object()):
            policy = policy_from_extra({"allow_admin_from": malformed}, "dm")
            assert policy.admin_user_ids == frozenset()
            assert policy.can_run("111", "model") is False

    def test_admin_runs_builtin_and_unknown_plugin_commands(self):
        policy = policy_from_extra({"allow_admin_from": [111]}, "dm")
        assert policy.is_admin("111") is True
        assert policy.can_run("111", "stop") is True
        assert policy.can_run("111", "pieverse-byok") is True

    def test_user_allowlist_cannot_downgrade_admin_commands(self):
        policy = policy_from_extra(
            {
                "allow_admin_from": ["111"],
                "user_allowed_commands": ["status", "model", "pieverse-byok"],
            },
            "dm",
        )
        assert policy.can_run("999", "status") is True
        assert policy.can_run("999", "model") is False
        assert policy.can_run("999", "pieverse-byok") is False

    def test_help_and_whoami_remain_reachable(self):
        policy = policy_from_extra(
            {"allow_admin_from": ["111"], "user_allowed_commands": []},
            "dm",
        )
        assert policy.can_run("999", "help") is True
        assert policy.can_run("999", "whoami") is True
        assert policy.can_run("999", "status") is False

    def test_unknown_user_id_never_becomes_admin(self):
        policy = policy_from_extra(
            {"allow_admin_from": ["111"], "user_allowed_commands": ["status"]},
            "dm",
        )
        assert policy.is_admin(None) is False
        assert policy.can_run(None, "status") is True
        assert policy.can_run(None, "stop") is False

    def test_id_coercion_accepts_numeric_yaml_ids_and_csv(self):
        numeric = policy_from_extra({"allow_admin_from": [12345, 67890]}, "dm")
        csv = policy_from_extra({"allow_admin_from": "111, 222 ,333"}, "dm")
        assert numeric.admin_user_ids == frozenset({"12345", "67890"})
        assert numeric.is_admin(12345) is True
        assert csv.admin_user_ids == frozenset({"111", "222", "333"})

    def test_command_coercion_normalizes_names(self):
        policy = policy_from_extra(
            {
                "allow_admin_from": ["111"],
                "user_allowed_commands": ["/Status", "MODEL", "/help"],
            },
            "dm",
        )
        assert policy.user_allowed_commands == frozenset({"status", "model", "help"})

    def test_dm_and_group_admin_lists_are_isolated(self):
        extra = {
            "allow_admin_from": ["111"],
            "user_allowed_commands": ["status"],
            "group_allow_admin_from": ["222"],
            "group_user_allowed_commands": ["help"],
        }
        dm = policy_from_extra(extra, "dm")
        group = policy_from_extra(extra, "group")
        assert dm.is_admin("111") is True
        assert dm.is_admin("222") is False
        assert group.is_admin("222") is True
        assert group.is_admin("111") is False
        assert dm.can_run("999", "status") is True
        assert group.can_run("999", "status") is False

    def test_dm_user_commands_fall_back_to_group_without_promoting_admin(self):
        policy = policy_from_extra(
            {
                "group_allow_admin_from": ["222"],
                "group_user_allowed_commands": ["status", "model"],
            },
            "dm",
        )
        assert policy.admin_user_ids == frozenset()
        assert policy.can_run("999", "status") is True
        assert policy.can_run("999", "model") is False


class TestPolicyForSource:
    def test_missing_config_is_active_and_fail_closed(self):
        policy = policy_for_source(None, None)
        assert policy.enabled is True
        assert policy.is_admin("anyone") is False
        assert policy.can_run("anyone", "restart") is False
        assert policy.can_run("anyone", "whoami") is True

    def test_missing_platform_config_is_active_and_fail_closed(self):
        config = GatewayConfig(platforms={})
        source = SessionSource(
            platform=Platform.DISCORD,
            chat_id="42",
            chat_type="dm",
            user_id="7",
        )
        policy = policy_for_source(config, source)
        assert policy.enabled is True
        assert policy.can_run("7", "stop") is False

    def test_dm_scope_allows_configured_admin(self):
        config = GatewayConfig(
            platforms={
                Platform.DISCORD: PlatformConfig(
                    enabled=True,
                    extra={
                        "allow_admin_from": ["111"],
                        "user_allowed_commands": ["status"],
                    },
                )
            }
        )
        source = SessionSource(
            platform=Platform.DISCORD,
            chat_id="A",
            chat_type="dm",
            user_id="111",
        )
        policy = policy_for_source(config, source)
        assert policy.is_admin("111") is True
        assert policy.can_run("999", "status") is True
        assert policy.can_run("999", "kanban") is False

    def test_group_chat_shapes_use_group_scope(self):
        config = GatewayConfig(
            platforms={
                Platform.DISCORD: PlatformConfig(
                    enabled=True,
                    extra={
                        "allow_admin_from": ["111"],
                        "group_allow_admin_from": ["222"],
                    },
                )
            }
        )
        for chat_type in ("group", "channel", "thread", "supergroup"):
            source = SessionSource(
                platform=Platform.DISCORD,
                chat_id="G",
                chat_type=chat_type,
                user_id="222",
            )
            policy = policy_for_source(config, source)
            assert policy.is_admin("222") is True
            assert policy.is_admin("111") is False

    def test_platform_without_admin_list_does_not_inherit_another_platform(self):
        config = GatewayConfig(
            platforms={
                Platform.DISCORD: PlatformConfig(
                    enabled=True,
                    extra={"allow_admin_from": ["111"]},
                ),
                Platform.TELEGRAM: PlatformConfig(enabled=True, extra={}),
            }
        )
        source = SessionSource(
            platform=Platform.TELEGRAM,
            chat_id="T",
            chat_type="dm",
            user_id="111",
        )
        policy = policy_for_source(config, source)
        assert policy.is_admin("111") is False
        assert policy.can_run("111", "stop") is False
