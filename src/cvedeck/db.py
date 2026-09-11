from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

SCHEMA_VERSION = 1

CVSS_PRECEDENCE_SQL = """CASE source||':'||version
  WHEN 'CNA:4.0' THEN 1 WHEN 'CNA:3.1' THEN 2 WHEN 'CNA:3.0' THEN 3
  WHEN 'NVD:4.0' THEN 4 WHEN 'NVD:3.1' THEN 5 WHEN 'NVD:3.0' THEN 6 ELSE 99 END"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cves(
  cve_id TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'PUBLISHED',
  published_at TEXT,
  updated_at TEXT,
  description TEXT,
  hydrated INTEGER NOT NULL DEFAULT 0,
  is_kev INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cvss_metrics(
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK(source IN ('CNA','NVD')),
  version TEXT NOT NULL CHECK(version IN ('4.0','3.1','3.0')),
  score REAL NOT NULL CHECK(score BETWEEN 0 AND 10),
  vector TEXT,
  UNIQUE(cve_id, source, version, vector)
);
CREATE TABLE IF NOT EXISTS affected_products(
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  vendor TEXT, product TEXT, versions_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS weaknesses(
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  cwe_id TEXT NOT NULL,
  source TEXT NOT NULL,
  PRIMARY KEY(cve_id, cwe_id, source)
);
CREATE TABLE IF NOT EXISTS cve_references(
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(cve_id, url)
);
CREATE TABLE IF NOT EXISTS kev(
  cve_id TEXT PRIMARY KEY REFERENCES cves(cve_id) ON DELETE CASCADE,
  vendor TEXT, product TEXT, vulnerability_name TEXT,
  date_added TEXT, short_description TEXT, required_action TEXT,
  due_date TEXT, ransomware_use TEXT
);
CREATE TABLE IF NOT EXISTS articles(
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  feed_guid TEXT,
  normalized_url TEXT NOT NULL,
  original_url TEXT NOT NULL,
  title TEXT NOT NULL,
  published_at TEXT,
  excerpt TEXT,
  scraped_at TEXT NOT NULL,
  UNIQUE(source, feed_guid),
  UNIQUE(source, normalized_url)
);
CREATE TABLE IF NOT EXISTS article_cves(
  article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  PRIMARY KEY(article_id, cve_id)
);
CREATE TABLE IF NOT EXISTS sync_state(
  source TEXT PRIMARY KEY,
  last_attempt_at TEXT,
  last_success_at TEXT,
  cursor TEXT,
  error TEXT
);
CREATE TABLE IF NOT EXISTS notifications(
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK(event IN ('NEW_CRITICAL','BECAME_KEV')),
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  PRIMARY KEY(cve_id, event)
);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);
"""


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=10)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    def close(self) -> None:
        self.connection.close()

    def migrate(self) -> None:
        with self.connection:
            self.connection.executescript(SCHEMA)
            row = self.connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                self.connection.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise RuntimeError(f"Unsupported database schema version: {row[0]}")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection:
            yield self.connection

    def upsert_cve(self, record: dict[str, Any], now: str,
                   authoritative: bool = False) -> tuple[bool, bool]:
        cve_id = record["cve_id"]
        previous = self.connection.execute(
            "SELECT is_kev FROM cves WHERE cve_id=?", (cve_id,)
        ).fetchone()
        was_kev = bool(previous[0]) if previous else False
        is_new = previous is None
        is_kev = bool(record.get("is_kev", was_kev))
        self.connection.execute(
            """INSERT INTO cves(cve_id,state,published_at,updated_at,description,hydrated,is_kev,first_seen_at,last_seen_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(cve_id) DO UPDATE SET
                 state=CASE WHEN ? THEN excluded.state ELSE cves.state END,
                 published_at=CASE WHEN ? OR cves.published_at IS NULL
                   THEN COALESCE(excluded.published_at,cves.published_at) ELSE cves.published_at END,
                 updated_at=CASE WHEN ? OR cves.updated_at IS NULL
                   THEN COALESCE(excluded.updated_at,cves.updated_at) ELSE cves.updated_at END,
                 description=CASE WHEN ? OR cves.description IS NULL
                   THEN COALESCE(excluded.description,cves.description) ELSE cves.description END,
                 hydrated=MAX(cves.hydrated,excluded.hydrated),
                 is_kev=MAX(cves.is_kev,excluded.is_kev),
                 last_seen_at=excluded.last_seen_at""",
            (cve_id, record.get("state", "PUBLISHED"), record.get("published_at"),
             record.get("updated_at"), record.get("description"), int(record.get("hydrated", False)),
             int(is_kev), now, now, authoritative, authoritative, authoritative, authoritative),
        )
        return is_new, (not was_kev and is_kev)

    def replace_metrics(self, cve_id: str, source: str, metrics: list[dict[str, Any]]) -> None:
        self.connection.execute("DELETE FROM cvss_metrics WHERE cve_id=? AND source=?", (cve_id, source))
        self.connection.executemany(
            "INSERT OR IGNORE INTO cvss_metrics(cve_id,source,version,score,vector) VALUES(?,?,?,?,?)",
            [(cve_id, source, m["version"], m["score"], m.get("vector")) for m in metrics],
        )

    def replace_products(self, cve_id: str, products: list[dict[str, Any]]) -> None:
        self.connection.execute("DELETE FROM affected_products WHERE cve_id=?", (cve_id,))
        self.connection.executemany(
            "INSERT INTO affected_products(cve_id,vendor,product,versions_json) VALUES(?,?,?,?)",
            [(cve_id, p.get("vendor"), p.get("product"), json.dumps(p.get("versions", []))) for p in products],
        )

    def replace_weaknesses(self, cve_id: str, source: str, cwes: list[str]) -> None:
        self.connection.execute("DELETE FROM weaknesses WHERE cve_id=? AND source=?", (cve_id, source))
        self.connection.executemany(
            "INSERT OR IGNORE INTO weaknesses(cve_id,cwe_id,source) VALUES(?,?,?)",
            [(cve_id, cwe, source) for cwe in cwes],
        )

    def replace_references(self, cve_id: str, references: list[dict[str, Any]]) -> None:
        self.connection.execute("DELETE FROM cve_references WHERE cve_id=?", (cve_id,))
        self.connection.executemany(
            "INSERT OR IGNORE INTO cve_references(cve_id,url,tags_json) VALUES(?,?,?)",
            [(cve_id, reference["url"], json.dumps(reference.get("tags", [])))
             for reference in references if reference.get("url")],
        )

    def upsert_kev(self, item: dict[str, Any], now: str) -> tuple[bool, bool]:
        record = {"cve_id": item["cve_id"], "is_kev": True}
        is_new, became_kev = self.upsert_cve(record, now)
        self.connection.execute(
            """INSERT INTO kev(cve_id,vendor,product,vulnerability_name,date_added,short_description,required_action,due_date,ransomware_use)
               VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET
               vendor=excluded.vendor,product=excluded.product,vulnerability_name=excluded.vulnerability_name,
               date_added=excluded.date_added,short_description=excluded.short_description,
               required_action=excluded.required_action,due_date=excluded.due_date,ransomware_use=excluded.ransomware_use""",
            (item["cve_id"], item.get("vendor"), item.get("product"), item.get("name"),
             item.get("date_added"), item.get("description"), item.get("action"), item.get("due_date"),
             item.get("ransomware_use")),
        )
        return is_new, became_kev

    def upsert_article(self, article: dict[str, Any]) -> int:
        guid = article.get("feed_guid") or None
        existing = None
        if guid:
            existing = self.connection.execute(
                "SELECT id FROM articles WHERE source=? AND feed_guid=?", (article["source"], guid)
            ).fetchone()
        if existing is None:
            existing = self.connection.execute(
                "SELECT id FROM articles WHERE source=? AND normalized_url=?",
                (article["source"], article["normalized_url"]),
            ).fetchone()
        if existing:
            article_id = int(existing[0])
            self.connection.execute(
                """UPDATE articles SET feed_guid=COALESCE(feed_guid,?), normalized_url=?, original_url=?, title=?,
                   published_at=COALESCE(?,published_at), excerpt=? WHERE id=?""",
                (guid, article["normalized_url"], article["original_url"], article["title"],
                 article.get("published_at"), article.get("excerpt"), article_id),
            )
            return article_id
        cursor = self.connection.execute(
            """INSERT INTO articles(source,feed_guid,normalized_url,original_url,title,published_at,excerpt,scraped_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (article["source"], guid, article["normalized_url"], article["original_url"],
             article["title"], article.get("published_at"), article.get("excerpt"), article["scraped_at"]),
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def best_cvss(self, cve_id: str) -> sqlite3.Row | None:
        return cast(sqlite3.Row | None, self.connection.execute(
            f"""SELECT source,version,score,vector FROM cvss_metrics WHERE cve_id=?
               ORDER BY {CVSS_PRECEDENCE_SQL} LIMIT 1""",
            (cve_id,),
        ).fetchone())

    def ordered_metrics(self, cve_id: str) -> list[sqlite3.Row]:
        return self.rows(
            f"""SELECT source,version,score,vector FROM cvss_metrics WHERE cve_id=?
                ORDER BY {CVSS_PRECEDENCE_SQL}""", (cve_id,),
        )

    def cve_listing(self) -> list[sqlite3.Row]:
        return self.rows(f"""SELECT c.cve_id,c.is_kev,c.published_at,c.description,
            m.score,m.source,m.version FROM cves c LEFT JOIN cvss_metrics m ON m.id=(
              SELECT id FROM cvss_metrics x WHERE x.cve_id=c.cve_id
              ORDER BY {CVSS_PRECEDENCE_SQL} LIMIT 1)
            ORDER BY c.published_at DESC""")

    def article_listing(self) -> list[sqlite3.Row]:
        return self.rows("""SELECT a.*,GROUP_CONCAT(ac.cve_id) AS cves FROM articles a
            LEFT JOIN article_cves ac ON ac.article_id=a.id
            GROUP BY a.id ORDER BY a.published_at DESC""")

    def link_article(self, article_id: int, cve_id: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO article_cves(article_id,cve_id) VALUES(?,?)",
            (article_id, cve_id),
        )

    def queue_transition(self, cve_id: str, event: str, now: str, baseline: bool) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO notifications(cve_id,event,created_at,delivered_at) VALUES(?,?,?,?)",
            (cve_id, event, now, now if baseline else None),
        )

    def pending_notifications(self) -> list[sqlite3.Row]:
        return list(self.connection.execute(
            "SELECT cve_id,event,created_at FROM notifications WHERE delivered_at IS NULL ORDER BY created_at"
        ))

    def mark_delivered(self, cve_id: str, event: str, now: str) -> None:
        self.connection.execute(
            "UPDATE notifications SET delivered_at=? WHERE cve_id=? AND event=?", (now, cve_id, event)
        )

    def rows(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(self.connection.execute(query, parameters))
