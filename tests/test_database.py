from pathlib import Path

import pytest

from cvedeck.db import Database
from cvedeck.locking import SyncLock

NOW = "2026-09-11T00:00:00+00:00"


def test_migration_creates_current_schema(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    assert db.rows("SELECT version FROM schema_version")[0][0] == 1
    tables = {row[0] for row in db.rows("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"cves", "cvss_metrics", "cve_references", "kev", "articles", "notifications"} <= tables
    db.close()


@pytest.mark.parametrize("expected,metrics", [
    (("CNA", "4.0", 8.0), [("NVD", "4.0", 9.9), ("CNA", "3.0", 9.0), ("CNA", "4.0", 8.0)]),
    (("CNA", "3.1", 7.5), [("NVD", "4.0", 9.9), ("CNA", "3.1", 7.5)]),
    (("CNA", "3.0", 7.0), [("NVD", "4.0", 9.9), ("CNA", "3.0", 7.0)]),
    (("NVD", "4.0", 9.0), [("NVD", "3.1", 9.8), ("NVD", "4.0", 9.0)]),
    (("NVD", "3.1", 8.8), [("NVD", "3.0", 9.9), ("NVD", "3.1", 8.8)]),
    (("NVD", "3.0", 6.0), [("NVD", "3.0", 6.0)]),
])
def test_cvss_precedence(tmp_path: Path, expected: tuple[str, str, float], metrics: list[tuple[str, str, float]]) -> None:
    db = Database(tmp_path / "db.sqlite")
    with db.transaction():
        db.upsert_cve({"cve_id": "CVE-2026-1234"}, NOW)
        for source, version, score in metrics:
            db.connection.execute(
                "INSERT INTO cvss_metrics(cve_id,source,version,score) VALUES(?,?,?,?)",
                ("CVE-2026-1234", source, version, score),
            )
    row = db.best_cvss("CVE-2026-1234")
    assert row is not None
    assert (row["source"], row["version"], row["score"]) == expected


def test_article_guid_then_normalized_url_deduplication(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    base = {"source": "krebs", "feed_guid": "post-1", "normalized_url": "https://e.test/a",
            "original_url": "https://e.test/a?utm_source=rss", "title": "First", "scraped_at": NOW}
    with db.transaction():
        first = db.upsert_article(base)
        second = db.upsert_article({**base, "normalized_url": "https://mirror.test/a", "title": "Updated"})
        third = db.upsert_article({**base, "feed_guid": None, "normalized_url": "https://mirror.test/a", "title": "Updated"})
    assert first == second == third
    row = db.rows("SELECT title,original_url FROM articles")[0]
    assert row["title"] == "Updated"
    assert row["original_url"] == base["original_url"]


def test_sync_lock_rejects_concurrency(tmp_path: Path) -> None:
    path = tmp_path / "sync.lock"
    with SyncLock(path), pytest.raises(RuntimeError, match="already running"), SyncLock(path):
        pass


def test_non_authoritative_update_cannot_clobber_cna_state(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    with db.transaction():
        db.upsert_cve(
            {"cve_id": "CVE-2026-1234", "state": "REJECTED", "description": "CNA text"},
            NOW,
            authoritative=True,
        )
        db.upsert_cve(
            {"cve_id": "CVE-2026-1234", "state": "PUBLISHED", "description": "feed text"},
            NOW,
        )
    row = db.rows("SELECT state,description FROM cves WHERE cve_id='CVE-2026-1234'")[0]
    assert (row["state"], row["description"]) == ("REJECTED", "CNA text")


def test_listing_and_detail_share_cvss_precedence(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite")
    with db.transaction():
        db.upsert_cve({"cve_id": "CVE-2026-1234"}, NOW)
        db.replace_metrics("CVE-2026-1234", "NVD", [{"version": "4.0", "score": 9.8}])
        db.replace_metrics("CVE-2026-1234", "CNA", [{"version": "3.1", "score": 7.5}])
    assert db.cve_listing()[0]["score"] == 7.5
    assert [(row["source"], row["version"]) for row in db.ordered_metrics("CVE-2026-1234")] == [
        ("CNA", "3.1"), ("NVD", "4.0"),
    ]
