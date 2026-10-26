"""Confidential profiles must not interpolate or silently edit opaque secrets."""
import json
import os

import pytest

from hermes_cli.env_loader import load_hermes_dotenv


@pytest.mark.parametrize("literal", [False, True])
def test_profile_can_load_opaque_environment_values(tmp_path, monkeypatch, literal):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("FIXTURE_EXPANSION", "expanded")
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1" if literal else "0")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    (tmp_path / ".env").write_text('CUSTOM_FIXTURE_VALUE="prefix-${FIXTURE_EXPANSION}-suffix"\n')
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == (
        "prefix-${FIXTURE_EXPANSION}-suffix" if literal else "prefix-expanded-suffix")


def test_opaque_non_ascii_credential_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_KEY", raising=False)
    (tmp_path / ".env").write_text('CUSTOM_FIXTURE_KEY="fixture-秘密"\n')
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_KEY"] == "fixture-秘密"


@pytest.mark.parametrize("value", ['quotes-"-\\-\n-\r-\t', "control-\x01-秘密-${HOME}"])
def test_literal_json_settings_round_trip(tmp_path, monkeypatch, value):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    (tmp_path / ".env").write_text("CUSTOM_FIXTURE_VALUE=" + json.dumps(value) + "\n")
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == value


@pytest.mark.parametrize("reader", ["config", "preferred", "scope", "reload"])
@pytest.mark.parametrize("value", ["secret-秘密-\x01-\n-${HOME}", 'quoted-"-\\-\r-\t'])
def test_literal_values_reach_runtime_readers_unchanged(tmp_path, monkeypatch, reader, value):
    from agent.secret_scope import (
        build_profile_secret_scope,
        get_secret,
        reset_secret_scope,
        set_secret_scope,
    )
    from hermes_cli.config import get_env_value_prefer_dotenv, load_env, reload_env

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_KEY", raising=False)
    (tmp_path / ".env").write_text("CUSTOM_FIXTURE_KEY=" + json.dumps(value) + "\n")
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_KEY"] == value

    if reader == "config":
        actual = load_env()["CUSTOM_FIXTURE_KEY"]
    elif reader == "preferred":
        actual = get_env_value_prefer_dotenv("CUSTOM_FIXTURE_KEY")
    elif reader == "scope":
        token = set_secret_scope(build_profile_secret_scope(tmp_path))
        try:
            actual = get_secret("CUSTOM_FIXTURE_KEY")
        finally:
            reset_secret_scope(token)
    else:
        reload_env()
        actual = os.environ["CUSTOM_FIXTURE_KEY"]
    assert actual == value


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_literal_json_unicode_separators_are_value_data(tmp_path, monkeypatch, separator):
    from agent.secret_scope import load_env_file
    from hermes_cli.config import load_env

    value = f"prefix-{separator}-suffix"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    path = tmp_path / ".env"
    path.write_text(
        "CUSTOM_FIXTURE_VALUE=" + json.dumps(value, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == value
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == value
    assert load_env_file(path)["CUSTOM_FIXTURE_VALUE"] == value


def test_literal_mode_changes_invalidate_env_read_cache(tmp_path, monkeypatch):
    from hermes_cli.config import load_env

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "0")
    (tmp_path / ".env").write_text('CUSTOM_FIXTURE_VALUE="first\\nsecond"\n')
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == r"first\nsecond"
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == "first\nsecond"
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "0")
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == r"first\nsecond"


@pytest.mark.parametrize("value", ['credential-秘密-\n-\r-\t-"-\\-${HOME}', "tab\tinside"])
def test_literal_value_writer_preserves_opaque_credentials(tmp_path, monkeypatch, value):
    from agent.secret_scope import load_env_file
    from hermes_cli.config import load_env, save_env_value

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_KEY", raising=False)
    save_env_value("CUSTOM_FIXTURE_KEY", value)
    assert os.environ["CUSTOM_FIXTURE_KEY"] == value
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_KEY"] == value
    assert load_env()["CUSTOM_FIXTURE_KEY"] == value
    assert load_env_file(tmp_path / ".env")["CUSTOM_FIXTURE_KEY"] == value


@pytest.mark.parametrize("literal", [False, True])
def test_standalone_send_uses_selected_environment_format(tmp_path, monkeypatch, literal):
    from hermes_cli.send_cmd import _load_hermes_env

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1" if literal else "0")
    monkeypatch.setenv("FIXTURE_EXPANSION", "expanded")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    (tmp_path / ".env").write_text('CUSTOM_FIXTURE_VALUE="prefix-${FIXTURE_EXPANSION}"\n')
    _load_hermes_env()
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == (
        "prefix-${FIXTURE_EXPANSION}" if literal else "prefix-expanded"
    )


def test_standalone_send_preserves_literal_opaque_value(tmp_path, monkeypatch):
    from hermes_cli.send_cmd import _load_hermes_env

    value = "fixture-秘密-\x01-\n-${HOME}"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    (tmp_path / ".env").write_text("CUSTOM_FIXTURE_VALUE=" + json.dumps(value) + "\n")
    _load_hermes_env()
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == value


def test_literal_raw_values_survive_load_and_unrelated_edits(tmp_path, monkeypatch):
    from hermes_cli.config import load_env, remove_env_value, save_env_value

    value = " leading-${HOME}-trailing "
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    monkeypatch.delenv("OTHER_FIXTURE_VALUE", raising=False)
    path = tmp_path / ".env"
    original = "CUSTOM_FIXTURE_VALUE=" + value + "\n"
    path.write_text(original)
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == value
    assert path.read_text() == original

    save_env_value("OTHER_FIXTURE_VALUE", "updated")
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == value
    assert remove_env_value("OTHER_FIXTURE_VALUE")
    assert path.read_text() == original


def test_literal_values_cannot_define_profile_keys_through_unicode_separator(tmp_path, monkeypatch):
    value = "prefix\u2028HERMES_ACP_AUTH_METHOD=inside-the-value"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "stale-parent-setting")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    (tmp_path / ".env").write_text(
        "CUSTOM_FIXTURE_VALUE=" + json.dumps(value, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    load_hermes_dotenv(hermes_home=tmp_path)
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == value
    assert "HERMES_ACP_AUTH_METHOD" not in os.environ


def test_literal_managed_values_keep_existing_override_precedence(tmp_path, monkeypatch):
    home, managed = tmp_path / "home", tmp_path / "managed"
    home.mkdir()
    managed.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    monkeypatch.delenv("CUSTOM_FIXTURE_VALUE", raising=False)
    (home / ".env").write_text('CUSTOM_FIXTURE_VALUE="user"\n')
    project = tmp_path / "project.env"
    project.write_text('CUSTOM_FIXTURE_VALUE="project"\n')
    expected = "managed-秘密-\n-${HOME}"
    (managed / ".env").write_text("CUSTOM_FIXTURE_VALUE=" + json.dumps(expected) + "\n")
    load_hermes_dotenv(hermes_home=home, project_env=project)
    assert os.environ["CUSTOM_FIXTURE_VALUE"] == expected


def test_explicit_sanitization_preserves_literal_file_data(tmp_path, monkeypatch):
    from hermes_cli.config import load_env, sanitize_env_file

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1")
    path = tmp_path / ".env"
    original = "CUSTOM_FIXTURE_VALUE= leading-trailing \n"
    path.write_text(original)
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == " leading-trailing "
    assert sanitize_env_file() == 0
    assert path.read_text() == original
    assert load_env()["CUSTOM_FIXTURE_VALUE"] == " leading-trailing "


@pytest.mark.parametrize("literal", [False, True])
def test_env_writers_can_preserve_process_environment(tmp_path, monkeypatch, literal):
    from hermes_cli.config import load_env, remove_env_value, save_env_value

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1" if literal else "0")
    monkeypatch.setenv("CUSTOM_FIXTURE_KEY", "listener-value")
    save_env_value("CUSTOM_FIXTURE_KEY", "profile-value", update_process_env=False)
    assert load_env()["CUSTOM_FIXTURE_KEY"] == "profile-value"
    assert os.environ["CUSTOM_FIXTURE_KEY"] == "listener-value"
    assert remove_env_value("CUSTOM_FIXTURE_KEY", update_process_env=False)
    assert "CUSTOM_FIXTURE_KEY" not in load_env()
    assert os.environ["CUSTOM_FIXTURE_KEY"] == "listener-value"


def test_remove_without_env_file_can_preserve_process_environment(tmp_path, monkeypatch):
    from hermes_cli.config import remove_env_value

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("CUSTOM_FIXTURE_KEY", "listener-value")
    assert not remove_env_value("CUSTOM_FIXTURE_KEY", update_process_env=False)
    assert os.environ["CUSTOM_FIXTURE_KEY"] == "listener-value"


@pytest.mark.parametrize("literal", [False, True])
def test_env_writers_update_process_environment_by_default(tmp_path, monkeypatch, literal):
    from hermes_cli.config import remove_env_value, save_env_value

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_ENV_LITERAL_VALUES", "1" if literal else "0")
    monkeypatch.setenv("CUSTOM_FIXTURE_KEY", "before")
    save_env_value("CUSTOM_FIXTURE_KEY", "updated")
    assert os.environ["CUSTOM_FIXTURE_KEY"] == "updated"
    assert remove_env_value("CUSTOM_FIXTURE_KEY")
    assert "CUSTOM_FIXTURE_KEY" not in os.environ
