"""Tests for CLI sync progress output (stderr) and final summary (stdout)."""
from __future__ import annotations

from pathlib import Path

import pytest

from cvedeck.cli import main
from cvedeck.db import Database
from cvedeck.sync import SyncProgress, SyncResult


async def fake_sync(db: Database, settings: object, database_path: Path, notify: bool = False,
                    progress: object = None) -> SyncResult:
    if callable(progress):
        progress(SyncProgress("kev", "running"))
        progress(SyncProgress("kev", "success", count=2, elapsed=0.1))
        progress(SyncProgress("sync", "complete", elapsed=0.5))
    return SyncResult(discovered=1)


async def fake_failing_sync(db: Database, settings: object, database_path: Path,
                            notify: bool = False, progress: object = None) -> SyncResult:
    if callable(progress):
        progress(SyncProgress("feed:krebs", "error", elapsed=0.3, error="feed down"))
    return SyncResult(errors={"feed:krebs": "feed down"})


@pytest.fixture
def isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))


def test_sync_progress_streams_to_stderr_and_summary_to_stdout(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
        isolated_paths: None) -> None:
    monkeypatch.setattr("cvedeck.cli.sync_database", fake_sync)
    exit_code = main(["--database", str(tmp_path / "db.sqlite"), "sync"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "kev running" in captured.err
    assert "kev success 2 records" in captured.err
    assert "sync complete" in captured.err
    assert "Discovered 1" in captured.out
    assert "kev" not in captured.out


def test_sync_failure_keeps_progress_and_final_summary(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
        isolated_paths: None) -> None:
    monkeypatch.setattr("cvedeck.cli.sync_database", fake_failing_sync)
    exit_code = main(["--database", str(tmp_path / "db.sqlite"), "sync"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "feed:krebs error" in captured.err
    assert "Discovered 0" in captured.out
    assert "feed:krebs: feed down" in captured.err
