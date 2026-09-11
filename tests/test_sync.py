from datetime import UTC, datetime
from pathlib import Path

import pytest

from cvedeck.config import FeedSettings, Settings
from cvedeck.db import Database
from cvedeck.sync import Synchronizer

NOW = datetime(2026, 9, 11, tzinfo=UTC)
RSS = b'<rss version="2.0"><channel><item><guid>g1</guid><title>CVE-2026-3000 fixed</title><link>https://news.test/a?utm_source=rss</link><description>Details</description></item></channel></rss>'


def cve_payload(cve_id: str, score: float = 9.5) -> dict:
    return {"cveMetadata": {"cveId": cve_id, "datePublished": "2026-09-10T00:00:00Z"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": f"Details for {cve_id}"}],
            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": score}}]}}}


class FakeClient:
    def __init__(self, fail_feed: str | None = None):
        self.cve_calls: list[str] = []
        self.fail_feed = fail_feed

    async def kev(self) -> dict:
        return {"vulnerabilities": [
            {"cveID": "CVE-2019-1000", "dateAdded": "2020-01-01"},
            {"cveID": "CVE-2026-2000", "dateAdded": "2026-09-10"},
        ]}

    async def nvd_since(self, since: datetime) -> dict:
        return {"vulnerabilities": [{"cve": {"id": "CVE-2026-3000", "published": "2026-09-10T00:00:00Z",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]}

    async def cve(self, cve_id: str) -> dict:
        self.cve_calls.append(cve_id)
        return cve_payload(cve_id)

    async def feed(self, name: str) -> bytes:
        if name == self.fail_feed:
            raise RuntimeError("feed down")
        return RSS


@pytest.mark.asyncio
async def test_first_run_full_kev_lazy_hydration_and_silent_baseline(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    client = FakeClient()
    sync = Synchronizer(db, Settings(feeds=FeedSettings(True, False, False)), client,
                        tmp_path / "sync.lock", clock=lambda: NOW)
    result = await sync.run()
    assert result.ok
    assert result.kev_entries == 2
    assert set(client.cve_calls) == {"CVE-2026-2000", "CVE-2026-3000"}
    old = db.rows("SELECT hydrated,is_kev FROM cves WHERE cve_id='CVE-2019-1000'")[0]
    assert (old["hydrated"], old["is_kev"]) == (0, 1)
    baseline = db.rows("SELECT event,delivered_at FROM notifications ORDER BY event")
    assert {row["event"] for row in baseline} == {"BECAME_KEV", "NEW_CRITICAL"}
    assert all(row["delivered_at"] for row in baseline)
    article = db.rows("SELECT original_url,normalized_url FROM articles")[0]
    assert article["original_url"].endswith("utm_source=rss")
    assert article["normalized_url"] == "https://news.test/a"


@pytest.mark.asyncio
async def test_existing_cve_state_transitions_are_queued(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    with db.transaction():
        db.upsert_cve({"cve_id": "CVE-2026-2000", "hydrated": True}, "2026-09-01T00:00:00+00:00")
        db.replace_metrics("CVE-2026-2000", "CNA", [{"version": "3.1", "score": 8.0}])
        db.connection.execute("INSERT INTO sync_state(source,last_success_at) VALUES('kev',?)",
                              ("2026-09-01T00:00:00+00:00",))
    client = FakeClient()
    sync = Synchronizer(db, Settings(feeds=FeedSettings(False, False, False)), client,
                        tmp_path / "sync.lock", clock=lambda: NOW)
    await sync.run()
    pending = {(row["cve_id"], row["event"]) for row in db.pending_notifications()}
    assert ("CVE-2026-2000", "BECAME_KEV") in pending
    assert ("CVE-2026-2000", "NEW_CRITICAL") in pending


@pytest.mark.asyncio
async def test_feed_failure_preserves_previous_data_and_reports_partial_sync(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    with db.transaction():
        db.upsert_article({"source": "krebs", "feed_guid": "old", "normalized_url": "https://old.test/",
                           "original_url": "https://old.test/", "title": "Cached", "scraped_at": "old"})
    sync = Synchronizer(db, Settings(feeds=FeedSettings(True, False, False)), FakeClient("krebs"),
                        tmp_path / "sync.lock", clock=lambda: NOW)
    result = await sync.run()
    assert result.errors["feed:krebs"] == "feed down"
    assert db.rows("SELECT title FROM articles WHERE feed_guid='old'")[0]["title"] == "Cached"
