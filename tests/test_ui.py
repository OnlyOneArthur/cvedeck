from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from textual.widgets import Button, DataTable, Input, Static

from cvedeck.cli import main
from cvedeck.config import load_settings
from cvedeck.db import Database
from cvedeck.tui import CVEDeckApp

NOW = "2026-09-11T00:00:00+00:00"


def test_cli_status_and_version(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database = tmp_path / "db.sqlite"
    assert main(["--database", str(database), "status"]) == 0
    assert "No synchronization" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0


@pytest.mark.asyncio
async def test_tui_smoke_filter_and_settings_round_trip(tmp_path: Path) -> None:
    database = tmp_path / "db.sqlite"
    config = tmp_path / "config.toml"
    db = Database(database)
    with db.transaction():
        db.upsert_cve({"cve_id": "CVE-2026-1234", "description": "Example issue", "hydrated": True}, NOW)
        db.replace_metrics("CVE-2026-1234", "CNA", [{"version": "4.0", "score": 9.5}])
    db.close()
    app = CVEDeckApp(database, config, offline=True)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#priority", DataTable).row_count == 1
        await pilot.click("#priority")
        await pilot.pause()
        assert "CNA v4.0 9.5" in str(app.query_one("#detail", Static).render())
        search = app.query_one("#search", Input)
        search.value = "severity:critical kev:false"
        await search.action_submit()
        await pilot.pause()
        assert app.query_one("#cves", DataTable).row_count == 1
        search.value = "missing"
        await search.action_submit()
        await pilot.pause()
        assert app.query_one("#cves", DataTable).row_count == 0
        app.query_one("#critical-cvss", Input).value = "8.5"
        app.query_one("#save-settings").press()
        await pilot.pause()
        assert "saved" in str(app.query_one("#settings-status", Static).render()).lower()
    assert load_settings(config).critical_cvss == 8.5


@pytest.mark.asyncio
async def test_tui_displays_zero_cvss_score(tmp_path: Path) -> None:
    database = tmp_path / "db.sqlite"
    db = Database(database)
    with db.transaction():
        db.upsert_cve({"cve_id": "CVE-2026-0000", "hydrated": True}, NOW)
        db.replace_metrics("CVE-2026-0000", "CNA", [{"version": "4.0", "score": 0.0}])
    db.close()

    app = CVEDeckApp(database, tmp_path / "config.toml", offline=True)
    async with app.run_test() as pilot:
        await pilot.pause()
        row = app.query_one("#cves", DataTable).get_row("cve:CVE-2026-0000")
        assert row[2] == 0.0


@pytest.mark.asyncio
async def test_tui_api_key_save_and_remove(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_root = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_root))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    app = CVEDeckApp(tmp_path / "db.sqlite", tmp_path / "config.toml")
    async with app.run_test() as pilot:
        field = app.query_one("#api-key", Input)
        field.value = "tui-key-1"
        app.query_one("#api-save", Button).press()
        await pilot.pause()
        assert "configured (cvedeck secret file)" in str(
            app.query_one("#api-key-status", Static).render()
        ).lower()
        stored = (config_root / "cvedeck" / ".env").read_text(encoding="utf-8")
        assert "tui-key-1" in stored
        import stat as stat_module
        assert stat_module.S_IMODE((config_root / "cvedeck" / ".env").stat().st_mode) == 0o600
        assert field.value == ""
        app.query_one("#api-remove", Button).press()
        await pilot.pause()
        assert "not configured" in str(
            app.query_one("#api-key-status", Static).render()
        ).lower()
        env_file = config_root / "cvedeck" / ".env"
        assert not env_file.exists() or "tui-key-1" not in env_file.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_tui_reports_concurrent_sync_lock(tmp_path: Path) -> None:
    app = CVEDeckApp(tmp_path / "db.sqlite", tmp_path / "config.toml")
    with patch(
        "cvedeck.tui.sync_database", new=AsyncMock(side_effect=RuntimeError("sync already running"))
    ):
        async with app.run_test() as pilot:
            app.action_sync()
            await pilot.pause()
            assert "Sync not started: sync already running" == app.sub_title
