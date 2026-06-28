"""Regression tests for Hermes pairing store layout selection."""

import importlib


def _reload_layout_modules():
    import hermes_constants
    import hermes_cli.config

    importlib.reload(hermes_constants)
    importlib.reload(hermes_cli.config)
    return hermes_constants, hermes_cli.config


def test_ensure_hermes_home_does_not_seed_legacy_pairing(monkeypatch, tmp_path):
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_MANAGED", raising=False)

    hermes_constants, config = _reload_layout_modules()

    config.ensure_hermes_home()

    assert home.exists()
    assert not (home / "pairing").exists()
    assert hermes_constants.get_hermes_dir("platforms/pairing", "pairing") == (
        home / "platforms" / "pairing"
    )


def test_get_hermes_dir_keeps_existing_legacy_pairing(monkeypatch, tmp_path):
    home = tmp_path / "hermes-home"
    legacy = home / "pairing"
    legacy.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_MANAGED", raising=False)

    hermes_constants, _config = _reload_layout_modules()

    assert hermes_constants.get_hermes_dir("platforms/pairing", "pairing") == legacy
