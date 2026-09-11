from pathlib import Path

import pytest
from textual.widgets import DataTable, Input, Static

from cvedeck.db import Database
from cvedeck.tui import CVEDeckApp


@pytest.mark.asyncio
async def test_navigation_preview_help_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    db = Database(tmp_path / "db")
    with db.transaction():
        for number in range(3):
            key = f"CVE-2026-100{number}"
            db.upsert_cve({"cve_id": key, "description": "Literal [red] <script> text", "hydrated": True}, "2026-09-11T00:00:00+00:00")
            db.replace_metrics(key, "CNA", [{"version": "4.0", "score": 9.5}])
    db.close()
    app = CVEDeckApp(tmp_path / "db", tmp_path / "settings", offline=True)
    async with app.run_test(size=(80, 30)) as pilot:
        table = app.query_one("#priority", DataTable)
        table.focus()
        await pilot.press("j")
        assert table.cursor_row == 1
        await pilot.press("G")
        assert table.cursor_row == 2
        await pilot.press("g", "g")
        assert table.cursor_row == 0
        await pilot.press("enter")
        assert len(app.screen_stack) == 2
        assert "CVE-2026-100" in str(app.screen.query_one("#preview-body", Static).render())
        await pilot.press("question_mark")
        assert len(app.screen_stack) == 3
        await pilot.press("escape", "escape")
        assert table.has_focus
        field = app.query_one("#export-dir", Input)
        field.value = str(tmp_path / "exports")
        app.query_one("#save-settings").press()
        await pilot.pause()
        table.focus()
        await pilot.press("e")
        assert len(list((tmp_path / "exports").glob("*.md"))) == 1
        search = app.query_one("#search", Input)
        search.focus()
        await pilot.press("q", "j", "k", "e", "question_mark")
        assert search.value == "qjke?"
        assert app.is_running
        from textual.widgets import TabbedContent
        app.query_one(TabbedContent).active = "cves-tab"
        await pilot.pause()
        cves = app.query_one("#cves", DataTable)
        cves.focus()
        await pilot.press("down", "k", "enter")
        assert len(app.screen_stack) == 2
        assert "## CVSS" in str(app.screen.query_one("#preview-body", Static).render())
        await pilot.press("escape")
        assert cves.has_focus


@pytest.mark.asyncio
async def test_news_snapshot_refresh_scroll_and_urls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from textual.widgets import TabbedContent

    from cvedeck.preview import VimScroll

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    app = CVEDeckApp(tmp_path / "db", tmp_path / "settings", offline=True)
    with app.db.transaction():
        for number in range(3):
            app.db.upsert_article({"source": "fixture", "feed_guid": str(number),
                "normalized_url": f"https://example.org/{number}",
                "original_url": f"https://example.org/{number}", "title": f"Story {number}",
                "excerpt": "Long publisher text. " * 100, "scraped_at": "2026-09-11"})
    opened: list[str] = []
    copied: list[str] = []
    monkeypatch.setattr("cvedeck.tui.webbrowser.open", opened.append)
    monkeypatch.setattr(app, "copy_to_clipboard", copied.append)
    async with app.run_test(size=(60, 22)) as pilot:
        app.query_one(TabbedContent).active = "news-tab"
        await pilot.pause()
        table = app.query_one("#news", DataTable)
        table.focus()
        await pilot.press("j", "enter")
        body = str(app.screen.query_one("#preview-body", Static).render())
        app.refresh_tables()
        await pilot.pause()
        assert str(app.screen.query_one("#preview-body", Static).render()) == body
        await pilot.press("o", "y", "G")
        scroll = app.screen.query_one(VimScroll)
        assert scroll.scroll_y > 0
        await pilot.press("g", "g")
        assert scroll.scroll_y == 0
        assert opened == copied == ["https://example.org/1"]
        await pilot.press("escape")
        assert table.has_focus
        assert table.cursor_row == 1
        await pilot.press("enter", "q")
        assert not app.is_running


@pytest.mark.asyncio
async def test_tui_progress_cancel_and_export_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from cvedeck.sync import SyncProgress

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def fake_sync(*args, progress=None, **kwargs):
        progress(SyncProgress("nvd", "running", count=7))
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr("cvedeck.tui.sync_database", fake_sync)
    app = CVEDeckApp(tmp_path / "db", tmp_path / "settings", offline=True)
    async with app.run_test() as pilot:
        worker = app.background_sync()
        await started.wait()
        assert "nvd" in app.sub_title
        app._tick_progress()
        assert "7" in app.sub_title
        worker.cancel()
        await pilot.pause()
        assert cancelled.is_set()
        assert "interrupted" in app.sub_title.lower()
        assert app._progress is None


@pytest.mark.asyncio
async def test_export_failure_missing_excerpt_and_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from textual.widgets import TabbedContent

    from cvedeck.config import load_settings

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    app = CVEDeckApp(tmp_path / "db", tmp_path / "settings", offline=True)
    with app.db.transaction():
        app.db.upsert_article({"source": "fixture", "feed_guid": "1", "normalized_url": "https://example.org",
                              "original_url": "https://example.org", "title": "Missing excerpt", "scraped_at": "2026-09-11"})
    notices: list[str] = []
    monkeypatch.setattr(app, "notify", lambda message, **kwargs: notices.append(str(message)))
    async with app.run_test() as pilot:
        field = app.query_one("#export-dir", Input)
        field.value = "~/custom-exports"
        app.query_one("#save-settings").press()
        await pilot.pause()
        assert load_settings(tmp_path / "settings").export_dir == "~/custom-exports"
        field.value = "relative/path"
        app.query_one("#save-settings").press()
        await pilot.pause()
        assert "Invalid" in str(app.query_one("#settings-status", Static).render())
        assert load_settings(tmp_path / "settings").export_dir == "~/custom-exports"
        blocked = tmp_path / "blocked"
        blocked.write_text("existing file")
        field.value = str(blocked)
        app.query_one("#save-settings").press()
        await pilot.pause()
        app.query_one(TabbedContent).active = "news-tab"
        await pilot.pause()
        app.query_one("#news", DataTable).focus()
        await pilot.press("enter", "e")
        assert "Not yet available" in str(app.screen.query_one("#preview-body", Static).render())
        assert any("Export failed" in text for text in notices)
        assert blocked.read_text() == "existing file"
        assert app.is_running
