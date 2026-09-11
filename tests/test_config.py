from pathlib import Path

import pytest

from cvedeck.config import FeedSettings, Settings, load_settings, save_settings


def test_settings_round_trip_and_atomic_validation(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    expected = Settings(8.5, 12, True, FeedSettings(False, True, False))
    save_settings(expected, path)
    assert load_settings(path) == expected
    original = path.read_bytes()
    with pytest.raises(ValueError):
        save_settings(Settings(11.0), path)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".config-*"))


def test_manual_toml_is_validated(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("critical_cvss = 9.0\nunknown = true\n")
    with pytest.raises(ValueError, match="Unknown settings"):
        load_settings(path)
