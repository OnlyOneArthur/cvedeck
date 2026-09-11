from __future__ import annotations

import asyncio
import json
import webbrowser
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

from .config import FeedSettings, Settings, load_settings, save_settings
from .db import Database
from .sync import sync_database


class CVEDeckApp(App[None]):
    TITLE = "CVEDeck"
    SUB_TITLE = "Authoritative vulnerability intelligence"
    CSS = """
    DataTable { height: 1fr; }
    #detail { height: 9; border-top: solid $accent; padding: 1; overflow-y: auto; }
    .setting { height: 3; }
    .setting Label { width: 32; content-align: left middle; }
    .setting Input { width: 20; }
    #settings-status { height: 3; }
    """
    BINDINGS: ClassVar = [
        ("q", "quit", "Quit"), ("r", "sync", "Sync"), ("o", "open_url", "Open URL"),
        ("y", "copy_url", "Copy URL"), ("slash", "focus_search", "Search"),
    ]

    def __init__(self, database_path: Path, config_file: Path, offline: bool = False):
        super().__init__()
        self.database_path = database_path
        self.config_file = config_file
        self.offline = offline
        self.db = Database(database_path)
        self.settings = load_settings(config_file)
        self.urls: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(
            placeholder="Filter: keyword severity:critical kev:true after:YYYY-MM-DD before:YYYY-MM-DD",
            id="search",
        )
        with TabbedContent():
            with TabPane("Priority", id="priority-tab"):
                yield DataTable(id="priority", cursor_type="row")
            with TabPane("CVEs", id="cves-tab"):
                yield DataTable(id="cves", cursor_type="row")
            with TabPane("News", id="news-tab"):
                yield DataTable(id="news", cursor_type="row")
            with TabPane("Settings", id="settings-tab"), Vertical():
                    with Horizontal(classes="setting"):
                        yield Label("Critical CVSS threshold")
                        yield Input(str(self.settings.critical_cvss), id="critical-cvss", type="number")
                    with Horizontal(classes="setting"):
                        yield Label("Startup sync interval (hours)")
                        yield Input(str(self.settings.startup_sync_interval_hours), id="sync-interval", type="integer")
                    with Horizontal(classes="setting"):
                        yield Label("Desktop notifications")
                        yield Switch(self.settings.desktop_notifications, id="desktop-notifications")
                    for label, widget_id, value in (
                        ("Krebs on Security", "feed-krebs", self.settings.feeds.krebs),
                        ("The Hacker News", "feed-thn", self.settings.feeds.the_hacker_news),
                        ("SecurityWeek", "feed-securityweek", self.settings.feeds.securityweek),
                    ):
                        with Horizontal(classes="setting"):
                            yield Label(label)
                            yield Switch(value, id=widget_id)
                    yield Button("Save settings", id="save-settings", variant="primary")
                    yield Static("", id="settings-status")
                    yield Static(
                        "Glossary — CVE: vulnerability identifier · CVSS: severity score · "
                        "CNA: authoritative record publisher · CWE: weakness category · "
                        "CPE: affected platform identifier · KEV: confirmed known exploitation"
                    )
        yield Static("Select a row for details.", id="detail")
        yield Footer()

    def on_mount(self) -> None:
        for table_id, columns in {
            "priority": ("CVE", "KEV", "CVSS", "Source", "Published", "Description"),
            "cves": ("CVE", "KEV", "CVSS", "Source", "Published", "Description"),
            "news": ("Published", "Source", "Title", "CVEs"),
        }.items():
            self.query_one(f"#{table_id}", DataTable).add_columns(*columns)
        self.refresh_tables()
        if not self.offline and self._sync_due():
            self.background_sync()

    def _sync_due(self) -> bool:
        interval = self.settings.startup_sync_interval_hours
        if interval == 0:
            return True
        rows = self.db.rows("SELECT MAX(last_success_at) AS last_success FROM sync_state")
        value = rows[0]["last_success"] if rows else None
        if not value:
            return True
        then = datetime.fromisoformat(str(value))
        return datetime.now(UTC) - then >= timedelta(hours=interval)

    @work(exclusive=True, group="sync")
    async def background_sync(self) -> None:
        self.sub_title = "Synchronizing… cached data remains available"
        try:
            result = await sync_database(self.db, self.settings, self.database_path)
        except RuntimeError as error:
            self.sub_title = f"Sync not started: {error}"
            self.notify(str(error), severity="warning")
            return
        self.sub_title = (f"Sync complete: {result.discovered} discovered, {result.hydrated} hydrated"
                          if result.ok else f"Sync partial: {len(result.errors)} source error(s)")
        self.refresh_tables()

    def action_sync(self) -> None:
        if self.offline:
            self.notify("Offline mode: sync disabled", severity="warning")
        else:
            self.background_sync()

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def _selected_url(self) -> str | None:
        for table_id in ("priority", "cves", "news"):
            table = self.query_one(f"#{table_id}", DataTable)
            if table.has_focus and table.row_count:
                key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
                return self.urls.get(str(key.value))
        return None

    def action_open_url(self) -> None:
        url = self._selected_url()
        if url:
            webbrowser.open(url)
        else:
            self.notify("Selected row has no URL", severity="warning")

    def action_copy_url(self) -> None:
        url = self._selected_url()
        if url:
            self.copy_to_clipboard(url)
            self.notify("URL copied")
        else:
            self.notify("Selected row has no URL", severity="warning")

    @on(Input.Submitted, "#search")
    def filter_submitted(self) -> None:
        self.refresh_tables(self.query_one("#search", Input).value)

    @on(Button.Pressed, "#save-settings")
    def save_button(self) -> None:
        try:
            settings = Settings(
                critical_cvss=float(self.query_one("#critical-cvss", Input).value),
                startup_sync_interval_hours=int(self.query_one("#sync-interval", Input).value),
                desktop_notifications=self.query_one("#desktop-notifications", Switch).value,
                feeds=FeedSettings(
                    krebs=self.query_one("#feed-krebs", Switch).value,
                    the_hacker_news=self.query_one("#feed-thn", Switch).value,
                    securityweek=self.query_one("#feed-securityweek", Switch).value,
                ),
            )
            save_settings(settings, self.config_file)
            self.settings = load_settings(self.config_file)
            self.query_one("#settings-status", Static).update("Settings saved atomically.")
        except (TypeError, ValueError, OSError) as error:
            self.query_one("#settings-status", Static).update(f"Invalid settings: {error}")

    @on(DataTable.RowHighlighted)
    def show_detail(self, event: DataTable.RowHighlighted) -> None:
        key = str(event.row_key.value)
        if key.startswith(("cve:", "priority:")):
            detail = self._cve_detail(key.split(":", 1)[1])
            self.query_one("#detail", Static).update(Text(detail))
            return
        values = event.data_table.get_row(event.row_key)
        detail = "  |  ".join(str(value or "Not yet available") for value in values)
        self.query_one("#detail", Static).update(Text(detail))

    def _cve_detail(self, cve_id: str) -> str:
        cve = self.db.rows("SELECT * FROM cves WHERE cve_id=?", (cve_id,))[0]
        metrics = self.db.ordered_metrics(cve_id)
        products = self.db.rows(
            "SELECT vendor,product,versions_json FROM affected_products WHERE cve_id=?", (cve_id,)
        )
        weaknesses = self.db.rows("SELECT cwe_id,source FROM weaknesses WHERE cve_id=?", (cve_id,))
        references = self.db.rows("SELECT url FROM cve_references WHERE cve_id=?", (cve_id,))
        kev_rows = self.db.rows(
            "SELECT date_added,due_date,required_action,ransomware_use FROM kev WHERE cve_id=?",
            (cve_id,),
        )
        metric_text = ", ".join(
            f"{row['source']} v{row['version']} {row['score']} {row['vector'] or ''}".strip()
            for row in metrics
        ) or "Not yet available"
        product_text = ", ".join(
            f"{row['vendor'] or '?'} {row['product'] or '?'} "
            f"({len(json.loads(row['versions_json']))} version rule(s))" for row in products
        ) or "Not yet available"
        weakness_text = ", ".join(
            f"{row['cwe_id']} ({row['source']})" for row in weaknesses
        ) or "Not yet available"
        reference_text = "  ".join(row["url"] for row in references[:3]) or "Not yet available"
        kev_text = "Not listed"
        if kev_rows:
            kev = kev_rows[0]
            kev_text = (
                f"listed {kev['date_added'] or '?'}; due {kev['due_date'] or '?'}; "
                f"ransomware {kev['ransomware_use'] or 'Unknown'}; "
                f"action {kev['required_action'] or 'Not yet available'}"
            )
        return (
            f"{cve_id} | KEV: {'Yes' if cve['is_kev'] else 'No'} | "
            f"Published: {cve['published_at'] or 'Not yet available'}\n"
            f"{cve['description'] or 'Not yet available'}\nCVSS: {metric_text}\n"
            f"Affected: {product_text}\nWeaknesses: {weakness_text}\nKEV: {kev_text}\n"
            f"References: {reference_text}"
        )

    def _severity(self, score: float | None) -> str:
        if score is None:
            return "unavailable"
        if score >= self.settings.critical_cvss:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"

    @staticmethod
    def _parse_filters(term: str) -> tuple[str, dict[str, str]]:
        controls: dict[str, str] = {}
        words = []
        for token in term.strip().lower().split():
            if ":" in token and token.split(":", 1)[0] in {
                "severity", "kev", "after", "before",
            }:
                key, value = token.split(":", 1)
                controls[key] = value
            else:
                words.append(token)
        return " ".join(words), controls

    def refresh_tables(self, term: str = "") -> None:
        keyword, filters = self._parse_filters(term)
        self.urls.clear()
        rows = self.db.cve_listing()
        cve_table = self.query_one("#cves", DataTable)
        priority_table = self.query_one("#priority", DataTable)
        cve_table.clear()
        priority_table.clear()
        for row in rows:
            haystack = f"{row['cve_id']} {row['description'] or ''} {row['score'] or ''}".lower()
            published = (row["published_at"] or "")[:10]
            score = float(row["score"]) if row["score"] is not None else None
            if keyword and keyword not in haystack:
                continue
            if filters.get("kev") in {"true", "yes"} and not row["is_kev"]:
                continue
            if filters.get("kev") in {"false", "no"} and row["is_kev"]:
                continue
            if filters.get("severity") and filters["severity"] != self._severity(score):
                continue
            if filters.get("after") and published < filters["after"]:
                continue
            if filters.get("before") and published > filters["before"]:
                continue
            values = (row["cve_id"], "Yes" if row["is_kev"] else "No", row["score"] or "—",
                      f"{row['source']} {row['version']}" if row["source"] else "—",
                      (row["published_at"] or "—")[:10],
                      Text(row["description"] or "Not yet available"))
            key = f"cve:{row['cve_id']}"
            cve_table.add_row(*values, key=key)
            self.urls[key] = f"https://www.cve.org/CVERecord?id={row['cve_id']}"
            if row["is_kev"] or (row["score"] is not None and row["score"] >= self.settings.critical_cvss):
                priority_table.add_row(*values, key=f"priority:{row['cve_id']}")
                self.urls[f"priority:{row['cve_id']}"] = self.urls[key]
        news_table = self.query_one("#news", DataTable)
        news_table.clear()
        articles = self.db.article_listing()
        for row in articles:
            haystack = f"{row['title']} {row['source']} {row['cves'] or ''}".lower()
            published = (row["published_at"] or "")[:10]
            if keyword and keyword not in haystack:
                continue
            if filters.get("after") and published < filters["after"]:
                continue
            if filters.get("before") and published > filters["before"]:
                continue
            key = f"article:{row['id']}"
            news_table.add_row((row["published_at"] or "—")[:10], row["source"],
                               Text(row["title"]), row["cves"] or "—", key=key)
            self.urls[key] = row["original_url"]

    async def action_quit(self) -> None:
        await asyncio.sleep(0)
        self.exit()

    def on_unmount(self) -> None:
        self.db.close()
