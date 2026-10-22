"""Confidential profiles must not interpolate or silently edit opaque secrets."""
import os
import json
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
