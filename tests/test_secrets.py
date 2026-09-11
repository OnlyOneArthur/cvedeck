from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cvedeck.secrets import read_stored_key, remove_key, resolve_key, save_key, secret_env_path

KEY = "test-key-abc123"


@pytest.fixture
def secret_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect CVEDeck secrets to a temp XDG config dir; never touch real config."""
    config_root = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_root))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    path = secret_env_path()
    assert config_root in path.parents
    return path


def test_env_var_has_highest_precedence(secret_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_key("stored-key", secret_path)
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    key, source = resolve_key(secret_path)
    assert key == "env-key"
    assert source == "environment"


def test_secret_file_used_without_env_var(secret_path: Path) -> None:
    assert resolve_key(secret_path) == (None, "Not configured")
    save_key(KEY, secret_path)
    key, source = resolve_key(secret_path)
    assert key == KEY
    assert source == "CVEDeck secret file"


def test_saved_file_has_0600_permissions(secret_path: Path) -> None:
    save_key(KEY, secret_path)
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    save_key("replacement-key", secret_path)
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600


def test_missing_and_invalid_secret_files_are_ignored(tmp_path: Path) -> None:
    missing = tmp_path / "missing.env"
    assert read_stored_key(missing) is None
    assert resolve_key(missing, environment={})[1] == "Not configured"
    invalid = tmp_path / "invalid.env"
    invalid.write_bytes(b"\xff\xfe binary \x00")
    assert read_stored_key(invalid) is None
    garbage = tmp_path / "garbage.env"
    garbage.write_text("not a dotenv line\nrandom junk\n", encoding="utf-8")
    assert read_stored_key(garbage) is None


def test_save_replaces_and_preserves_other_lines(secret_path: Path) -> None:
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_text("OTHER_SECRET=keep-me\n", encoding="utf-8")
    save_key("first-key", secret_path)
    save_key("second-key", secret_path)
    content = secret_path.read_text(encoding="utf-8")
    assert "OTHER_SECRET=keep-me" in content
    assert "first-key" not in content
    assert read_stored_key(secret_path) == "second-key"


def test_remove_key(secret_path: Path) -> None:
    assert remove_key(secret_path) is False
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_text("OTHER_SECRET=keep-me\nNVD_API_KEY=doomed\n", encoding="utf-8")
    assert remove_key(secret_path) is True
    content = secret_path.read_text(encoding="utf-8")
    assert "doomed" not in content
    assert "OTHER_SECRET=keep-me" in content
    assert read_stored_key(secret_path) is None


def test_save_rejects_empty_and_multiline_keys(secret_path: Path) -> None:
    for bad in ("", "   ", "line1\nline2"):
        with pytest.raises(ValueError):
            save_key(bad, secret_path)
    assert not secret_path.exists()


def test_status_labels_never_contain_key(secret_path: Path) -> None:
    save_key(KEY, secret_path)
    _key, source = resolve_key(secret_path)
    assert KEY not in source


def test_never_touches_real_user_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    save_key(KEY)
    assert secret_env_path() == fake_home / ".config" / "cvedeck" / ".env"
    assert fake_home.exists()
    assert not (Path(os.environ.get("XDG_CONFIG_HOME", "/nonexistent-real-check")) / "cvedeck").exists()


def test_quoted_values_are_unquoted(tmp_path: Path) -> None:
    target = tmp_path / "quoted.env"
    target.write_text('NVD_API_KEY="quoted-key"\n', encoding="utf-8")
    assert read_stored_key(target) == "quoted-key"
