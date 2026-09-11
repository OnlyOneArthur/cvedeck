from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

ENV_VAR = "NVD_API_KEY"
SECRET_FILE_MODE = 0o600
_LINE = re.compile(r"^\s*NVD_API_KEY\s*=\s*(.*)$")


def secret_env_path() -> Path:
    """CVEDeck-specific secret file location (honors XDG_CONFIG_HOME)."""
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "cvedeck" / ".env"


def _parse_value(raw: str) -> str | None:
    value = raw.strip()
    for quote in ("'", '"'):
        if len(value) >= 2 and value.startswith(quote) and value.endswith(quote):
            value = value[1:-1]
            break
    return value or None


def read_stored_key(path: Path | None = None) -> str | None:
    """Read NVD_API_KEY from the CVEDeck secret file; None when absent/invalid."""
    target = path or secret_env_path()
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    for line in text.splitlines():
        match = _LINE.match(line)
        if match:
            return _parse_value(match.group(1))
    return None


def _atomic_write(target: Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".env-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, SECRET_FILE_MODE)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def save_key(key: str, path: Path | None = None) -> None:
    """Persist NVD_API_KEY to the secret file with 0600 permissions."""
    key = key.strip()
    if not key or any(character in key for character in "\r\n"):
        raise ValueError("API key must be a single non-empty line")
    target = path or secret_env_path()
    existing = []
    if target.exists():
        try:
            existing = [
                line for line in target.read_text(encoding="utf-8").splitlines()
                if line and not _LINE.match(line)
            ]
        except UnicodeDecodeError:
            existing = []
    _atomic_write(target, "\n".join([*existing, f"NVD_API_KEY={key}", ""]))


def remove_key(path: Path | None = None) -> bool:
    """Remove NVD_API_KEY from the secret file. True when removed, False if absent."""
    target = path or secret_env_path()
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    remaining = [line for line in text.splitlines() if line and not _LINE.match(line)]
    if len(remaining) == len([l for l in text.splitlines() if l]):
        return False
    if remaining:
        _atomic_write(target, "\n".join(remaining) + "\n")
    else:
        target.unlink(missing_ok=True)
    return True


def resolve_key(path: Path | None = None, environment: dict[str, str] | None = None) -> tuple[str | None, str]:
    """Resolve the active NVD API key and its source label.

    Precedence: process environment variable, then CVEDeck secret file.
    The returned label never contains the key value.
    """
    env = os.environ if environment is None else environment
    if env.get(ENV_VAR):
        return env[ENV_VAR], "environment"
    stored = read_stored_key(path)
    if stored:
        return stored, "CVEDeck secret file"
    return None, "Not configured"
