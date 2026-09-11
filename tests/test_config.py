from pathlib import Path

import pytest

from cvedeck.config import FeedSettings, Settings, _validate, load_settings, save_settings


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


def test_default_export_dir_is_under_documents(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "missing.toml")
    assert settings.export_dir == "~/Documents/CVEDeck/exports"


def test_export_dir_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    expected = Settings(export_dir="/absolute/exports")
    save_settings(expected, path)
    assert load_settings(path).export_dir == "/absolute/exports"


@pytest.mark.parametrize("bad", ["relative/dir", "./here", "", 42, None])
def test_export_dir_must_be_tilde_or_absolute(bad: str | int | None) -> None:
    with pytest.raises((ValueError, TypeError)):
        _validate({"export_dir": bad})


@pytest.mark.parametrize("bad", ["~root/exports", "~otheruser/x"])
def test_export_dir_rejects_other_user_tilde(bad: str) -> None:
    with pytest.raises(ValueError):
        _validate({"export_dir": bad})
