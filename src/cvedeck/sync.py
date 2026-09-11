from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import Settings
from .db import Database
from .locking import SyncLock
from .notifications import desktop_notify
from .parsers import extract_cve_ids, parse_cve_record, parse_feed, parse_kev, parse_nvd_page
from .sources import FEEDS, SourceClient

Clock = Callable[[], datetime]


@dataclass
class SyncResult:
    discovered: int = 0
    hydrated: int = 0
    kev_entries: int = 0
    articles: int = 0
    notifications: int = 0
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors


def utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            result = result.replace(tzinfo=UTC)
        return result.astimezone(UTC)
    except ValueError:
        try:
            return datetime.fromisoformat(value).replace(tzinfo=UTC)
        except ValueError:
            return None


class Synchronizer:
    def __init__(self, db: Database, settings: Settings, client: SourceClient,
                 lock_path: Path, clock: Clock = utc_now):
        self.db = db
        self.settings = settings
        self.client = client
        self.lock_path = lock_path
        self.clock = clock

    def _first_run(self) -> bool:
        return not self.db.rows("SELECT 1 FROM sync_state WHERE source='kev' AND last_success_at IS NOT NULL")

    def _last_nvd_sync(self, now: datetime) -> datetime:
        rows = self.db.rows("SELECT last_success_at FROM sync_state WHERE source='nvd'")
        parsed = _parse_date(rows[0][0]) if rows else None
        return parsed or now - timedelta(days=7)

    def _state(self, source: str, now: str, error: str | None = None) -> None:
        self.db.connection.execute(
            """INSERT INTO sync_state(source,last_attempt_at,last_success_at,error) VALUES(?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,
               last_success_at=CASE WHEN excluded.error IS NULL THEN excluded.last_success_at ELSE sync_state.last_success_at END,
               error=excluded.error""",
            (source, now, now if error is None else None, error),
        )

    async def run(self, notify: bool = False) -> SyncResult:
        with SyncLock(self.lock_path):
            return await self._run_locked(notify)

    async def _run_locked(self, notify: bool) -> SyncResult:
        result = SyncResult()
        now_dt = self.clock()
        now = _iso(now_dt)
        first_run = self._first_run()
        hydrate_ids: set[str] = set()
        previous_scores: dict[str, float | None] = {}

        try:
            kev_items = parse_kev(await self.client.kev())
            recent_cutoff = now_dt - timedelta(days=7)
            with self.db.transaction():
                for item in kev_items:
                    is_new, became_kev = self.db.upsert_kev(item, now)
                    added = _parse_date(item.get("date_added"))
                    if became_kev:
                        self.db.queue_transition(item["cve_id"], "BECAME_KEV", now, first_run)
                    if (added and added >= recent_cutoff) or (is_new and not first_run):
                        hydrate_ids.add(item["cve_id"])
                self._state("kev", now)
            result.kev_entries = len(kev_items)
        except Exception as error:  # noqa: BLE001 -- isolate upstream failure
            result.errors["kev"] = str(error)
            with self.db.transaction():
                self._state("kev", now, str(error))

        for cve_id in hydrate_ids:
            previous = self.db.best_cvss(cve_id)
            previous_scores[cve_id] = float(previous["score"]) if previous else None

        try:
            nvd_records = parse_nvd_page(await self.client.nvd_since(self._last_nvd_sync(now_dt)))
            with self.db.transaction():
                for record in nvd_records:
                    cve_id = record["cve_id"]
                    if cve_id not in previous_scores:
                        previous = self.db.best_cvss(cve_id)
                        previous_scores[cve_id] = float(previous["score"]) if previous else None
                    self.db.upsert_cve(record, now)
                    self.db.replace_metrics(cve_id, "NVD", record["metrics"])
                    self.db.replace_weaknesses(cve_id, "NVD", record["cwes"])
                    self.db.replace_products(cve_id, record["products"])
                    hydrate_ids.add(cve_id)
                self._state("nvd", now)
            result.discovered = len(nvd_records)
        except Exception as error:  # noqa: BLE001 -- isolate upstream failure
            result.errors["nvd"] = str(error)
            with self.db.transaction():
                self._state("nvd", now, str(error))

        semaphore = asyncio.Semaphore(8)

        async def fetch_record(cve_id: str) -> tuple[str, dict[str, Any] | Exception]:
            async with semaphore:
                try:
                    return cve_id, parse_cve_record(await self.client.cve(cve_id))
                except Exception as error:  # noqa: BLE001 -- isolate upstream failure
                    return cve_id, error

        fetched = await asyncio.gather(*(fetch_record(cve_id) for cve_id in sorted(hydrate_ids)))
        failures = 0
        with self.db.transaction():
            for cve_id, fetched_record in fetched:
                if isinstance(fetched_record, Exception):
                    failures += 1
                    continue
                self.db.upsert_cve(fetched_record, now, authoritative=True)
                self.db.replace_metrics(cve_id, "CNA", fetched_record["metrics"])
                if fetched_record["products"]:
                    self.db.replace_products(cve_id, fetched_record["products"])
                self.db.replace_weaknesses(cve_id, "CNA", fetched_record["cwes"])
                self.db.replace_references(cve_id, fetched_record.get("references", []))
                result.hydrated += 1
            for cve_id in hydrate_ids:
                after = self.db.best_cvss(cve_id)
                after_score = float(after["score"]) if after else None
                before_score = previous_scores.get(cve_id)
                if after_score is not None and after_score >= self.settings.critical_cvss and (
                    before_score is None or before_score < self.settings.critical_cvss
                ):
                    self.db.queue_transition(cve_id, "NEW_CRITICAL", now, first_run)
            self._state("cve_program", now, f"{failures} record(s) failed" if failures else None)
        if failures:
            result.errors["cve_program"] = f"{failures} record(s) failed"

        enabled = {
            "krebs": self.settings.feeds.krebs,
            "the_hacker_news": self.settings.feeds.the_hacker_news,
            "securityweek": self.settings.feeds.securityweek,
        }
        for source in FEEDS:
            if not enabled[source]:
                continue
            try:
                articles = parse_feed(source, await self.client.feed(source), now)
                with self.db.transaction():
                    for article in articles:
                        article_id = self.db.upsert_article(article)
                        text = f"{article['title']} {article.get('excerpt', '')}"
                        for cve_id in extract_cve_ids(text):
                            self.db.upsert_cve({"cve_id": cve_id}, now)
                            self.db.link_article(article_id, cve_id)
                    self._state(f"feed:{source}", now)
                result.articles += len(articles)
            except Exception as error:  # noqa: BLE001 -- isolate upstream failure
                result.errors[f"feed:{source}"] = str(error)
                with self.db.transaction():
                    self._state(f"feed:{source}", now, str(error))

        if notify or self.settings.desktop_notifications:
            with self.db.transaction():
                for row in self.db.pending_notifications():
                    if desktop_notify(row["cve_id"], row["event"]):
                        self.db.mark_delivered(row["cve_id"], row["event"], now)
                        result.notifications += 1
                    else:
                        result.errors.setdefault(
                            "notifications", "desktop notification delivery failed"
                        )
                        break
        return result


def default_lock_path(database_path: Path) -> Path:
    return database_path.with_suffix(".sync.lock")


async def sync_database(db: Database, settings: Settings, database_path: Path,
                        notify: bool = False) -> SyncResult:
    async with SourceClient(os.environ.get("NVD_API_KEY")) as client:
        return await Synchronizer(db, settings, client, default_lock_path(database_path)).run(notify)
