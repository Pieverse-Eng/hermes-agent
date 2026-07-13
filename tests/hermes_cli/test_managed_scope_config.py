"""Config integration tests — managed scope wins over user config at the leaf."""
import textwrap

import pytest
import yaml


@pytest.fixture
def homes(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    managed = tmp_path / "managed"
    managed.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    import hermes_cli.config as cfg
    from hermes_cli import managed_scope

    cfg._LOAD_CONFIG_CACHE.clear()
    cfg._RAW_CONFIG_CACHE.clear()
    managed_scope.invalidate_managed_cache()
    return home, managed


def _write(path, body):
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    import hermes_cli.config as cfg
    from hermes_cli import managed_scope

    cfg._LOAD_CONFIG_CACHE.clear()
    cfg._RAW_CONFIG_CACHE.clear()
    managed_scope.invalidate_managed_cache()


def test_managed_beats_user(homes):
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "model:\n  default: user/model\n")
    _write(managed / "config.yaml", "model:\n  default: managed/model\n")
    assert cfg_get(load_config(), "model", "default") == "managed/model"


def test_managed_leaf_does_not_freeze_siblings(homes):
    """D3/Q4: pinning model.default leaves model.fallback user-controlled."""
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "model:\n  default: user/model\n  fallback: user/fb\n")
    _write(managed / "config.yaml", "model:\n  default: managed/model\n")
    cfg = load_config()
    assert cfg_get(cfg, "model", "default") == "managed/model"
    assert cfg_get(cfg, "model", "fallback") == "user/fb"  # sibling preserved


def test_no_managed_config_is_unchanged(homes):
    from hermes_cli.config import load_config, cfg_get

    home, _ = homes
    _write(home / "config.yaml", "model:\n  default: user/model\n")
    assert cfg_get(load_config(), "model", "default") == "user/model"


def test_managed_list_wins_wholesale(homes):
    """D3: a managed list value replaces the user's wholesale."""
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "toolsets:\n  enabled: [a, b, c]\n")
    _write(managed / "config.yaml", "toolsets:\n  enabled: [x]\n")
    assert cfg_get(load_config(), "toolsets", "enabled") == ["x"]


def test_managed_plugin_allow_list_is_additive(homes):
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "plugins:\n  enabled: [okx-a2a, local-helper]\n")
    _write(managed / "config.yaml", "plugins:\n  enabled: [ax, okx-a2a]\n")
    assert cfg_get(load_config(), "plugins", "enabled") == [
        "okx-a2a",
        "local-helper",
        "ax",
    ]


def test_managed_plugin_disabled_list_is_additive(homes):
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "plugins:\n  disabled: [local-plugin]\n")
    _write(managed / "config.yaml", "plugins:\n  disabled: [org-plugin, local-plugin]\n")
    assert cfg_get(load_config(), "plugins", "disabled") == [
        "local-plugin",
        "org-plugin",
    ]


def test_managed_skill_disabled_list_is_additive(homes):
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "skills:\n  disabled: [user-skill]\n")
    _write(managed / "config.yaml", "skills:\n  disabled: [org-skill, user-skill]\n")
    assert cfg_get(load_config(), "skills", "disabled") == ["user-skill", "org-skill"]


def test_managed_plugin_load_paths_replace_user_paths(homes):
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "plugins:\n  load:\n    paths: [/user/plugin]\n")
    _write(managed / "config.yaml", "plugins:\n  load:\n    paths: [/platform/plugin]\n")
    assert cfg_get(load_config(), "plugins", "load", "paths") == ["/platform/plugin"]


def test_save_config_persists_only_user_entries_for_additive_managed_list(homes):
    import hermes_cli.config as cfg
    from hermes_cli.config import load_config, save_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "plugins:\n  enabled: [okx-a2a]\n")
    _write(managed / "config.yaml", "plugins:\n  enabled: [ax]\n")

    config = load_config()
    config["plugins"]["enabled"].append("foo")
    save_config(config)

    raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert raw["plugins"]["enabled"] == ["okx-a2a", "foo"]

    cfg._LOAD_CONFIG_CACHE.clear()
    cfg._RAW_CONFIG_CACHE.clear()
    assert cfg_get(load_config(), "plugins", "enabled") == ["okx-a2a", "foo", "ax"]


def test_plugins_enable_save_path_preserves_user_entries_with_managed_plugins(homes):
    import hermes_cli.config as cfg
    from hermes_cli.config import load_config, cfg_get
    from hermes_cli.plugins_cmd import _save_enabled_set

    home, managed = homes
    _write(home / "config.yaml", "plugins:\n  enabled: [okx-a2a]\n")
    _write(managed / "config.yaml", "plugins:\n  enabled: [ax]\n")

    _save_enabled_set({"ax", "foo", "okx-a2a"})

    raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert raw["plugins"]["enabled"] == ["foo", "okx-a2a"]

    cfg._LOAD_CONFIG_CACHE.clear()
    cfg._RAW_CONFIG_CACHE.clear()
    assert cfg_get(load_config(), "plugins", "enabled") == ["foo", "okx-a2a", "ax"]


def test_editing_managed_file_invalidates_cache(homes):
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    _write(home / "config.yaml", "model:\n  default: user/model\n")
    _write(managed / "config.yaml", "model:\n  default: managed/v1\n")
    assert cfg_get(load_config(), "model", "default") == "managed/v1"
    _write(managed / "config.yaml", "model:\n  default: managed/v2\n")
    assert cfg_get(load_config(), "model", "default") == "managed/v2"


def test_user_cannot_shadow_managed_literal_via_envref(homes, monkeypatch):
    """A managed literal must NOT be expandable via a ${VAR} the user controls.

    The managed value is a plain literal 'managed/locked' with no ${...}, so a
    user-defined env var has nothing to substitute. This asserts the managed
    literal survives verbatim regardless of user env, and that managed wins.
    """
    from hermes_cli.config import load_config, cfg_get

    home, managed = homes
    monkeypatch.setenv("EVIL", "user/override")
    _write(home / "config.yaml", "model:\n  default: ${EVIL}\n")
    _write(managed / "config.yaml", "model:\n  default: managed/locked\n")
    assert cfg_get(load_config(), "model", "default") == "managed/locked"
