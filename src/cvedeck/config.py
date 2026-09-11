from __future__ import annotations

import os
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli_w

from .export import resolve_export_dir


@dataclass(frozen=True)
class FeedSettings:
    krebs: bool = True
    the_hacker_news: bool = True
    securityweek: bool = True


@dataclass(frozen=True)
class Settings:
    critical_cvss: float = 9.0
    startup_sync_interval_hours: int = 0
    desktop_notifications: bool = False
    feeds: FeedSettings = field(default_factory=FeedSettings)
    export_dir: str = "~/Documents/CVEDeck/exports"


def config_path() -> Path:
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "cvedeck" / "config.toml"


def data_path() -> Path:
    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "cvedeck" / "cvedeck.db"


def _validate(raw: dict[str, Any]) -> Settings:
    allowed = {
        "critical_cvss", "startup_sync_interval_hours", "desktop_notifications",
        "feeds", "export_dir",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"Unknown settings: {', '.join(sorted(unknown))}")
    score = float(raw.get("critical_cvss", 9.0))
    interval = int(raw.get("startup_sync_interval_hours", 0))
    notify = raw.get("desktop_notifications", False)
    if not 0 <= score <= 10:
        raise ValueError("critical_cvss must be between 0 and 10")
    if interval < 0:
        raise ValueError("startup_sync_interval_hours must be non-negative")
    if not isinstance(notify, bool):
        raise TypeError("desktop_notifications must be boolean")
    export_dir = raw.get("export_dir", "~/Documents/CVEDeck/exports")
    if not isinstance(export_dir, str):
        raise TypeError("export_dir must be a string")
    try:
        resolve_export_dir(export_dir)
    except ValueError as error:
        raise ValueError(f"export_dir {error}") from error
    feed_raw = raw.get("feeds", {})
    if not isinstance(feed_raw, dict):
        raise TypeError("feeds must be a table")
    feed_allowed = {"krebs", "the_hacker_news", "securityweek"}
    feed_unknown = set(feed_raw) - feed_allowed
    if feed_unknown:
        raise ValueError(f"Unknown feeds: {', '.join(sorted(feed_unknown))}")
    values: dict[str, bool] = {}
    for name in feed_allowed:
        value = feed_raw.get(name, True)
        if not isinstance(value, bool):
            raise TypeError(f"feeds.{name} must be boolean")
        values[name] = value
    return Settings(score, interval, notify, FeedSettings(**values), export_dir)


def load_settings(path: Path | None = None) -> Settings:
    target = path or config_path()
    if not target.exists():
        return Settings()
    with target.open("rb") as handle:
        raw = tomllib.load(handle)
    return _validate(raw)


def save_settings(settings: Settings, path: Path | None = None) -> None:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "critical_cvss": settings.critical_cvss,
        "startup_sync_interval_hours": settings.startup_sync_interval_hours,
        "desktop_notifications": settings.desktop_notifications,
        "feeds": {
            "krebs": settings.feeds.krebs,
            "the_hacker_news": settings.feeds.the_hacker_news,
            "securityweek": settings.feeds.securityweek,
        },
        "export_dir": settings.export_dir,
    }
    encoded = tomli_w.dumps(data).encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".config-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate(tomllib.loads(encoded.decode()))
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
