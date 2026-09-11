from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from textual.widgets import DataTable, Input, Static

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
async def test_tui_reports_concurrent_sync_lock(tmp_path: Path) -> None:
    app = CVEDeckApp(tmp_path / "db.sqlite", tmp_path / "config.toml")
    with patch(
        "cvedeck.tui.sync_database", new=AsyncMock(side_effect=RuntimeError("sync already running"))
    ):
        async with app.run_test() as pilot:
            app.action_sync()
            await pilot.pause()
            assert "Sync not started: sync already running" == app.sub_title
