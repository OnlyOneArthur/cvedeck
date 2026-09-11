# Architecture

```text
NVD API ──discovery/fallback──┐
CISA KEV ─discovery/exploit───┼─> Synchronizer ─> SQLite ─> CLI/Textual TUI
CVE API ─authoritative record─┤         │
RSS feeds ─metadata only──────┘         └─> transition queue ─> notify-send
```

`Synchronizer` owns orchestration but source adapters own HTTP behavior and parsers own untrusted-payload conversion. Each source updates SQLite in its own transaction. A failed source records its error without erasing cached rows from successful prior runs.

SQLite stores CVEs, all CVSS metrics, affected products, weaknesses, KEV metadata, article metadata, exact article/CVE edges, source cursors/status, and notification transitions. The effective score is selected at read time so no source score is destroyed or silently merged.

The process lock is adjacent to the database. Configuration is independent of the database and saved through a temporary file, validation, fsync, and atomic rename.
