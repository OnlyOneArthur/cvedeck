# CVEDeck implementation specification

This document records the approved v0.1 implementation contract.

## Scope

CVEDeck is a Python 3.11+ Textual TUI and CLI using HTTPX, feedparser, SQLite, `tomllib`, and a minimal TOML writer. It is local-only, has no telemetry, account, AI, ORM, scheduler, web server, article scraper, or package-vulnerability resolver.

## Required behavior

1. NVD and KEV discover identifiers and transitions. CVE Program records are authoritative; NVD provides fallback CVSS/CWE enrichment.
2. First run imports full KEV metadata, hydrates only seven-day recent NVD results and recent/new KEVs, and leaves older KEVs lazy.
3. Effective CVSS precedence is CNA 4.0, CNA 3.1, CNA 3.0, NVD 4.0, NVD 3.1, NVD 3.0, unavailable. Every available score remains stored separately with source/version.
4. Articles deduplicate by source plus feed GUID when present, otherwise source plus normalized URL. Original URLs remain available for opening.
5. Notifications represent durable `NEW_CRITICAL` and `BECAME_KEV` state transitions. First-run findings are silently marked delivered.
6. Sync is protected by a nonblocking process lock. Source writes are independent transactions. Previous data survives source failure.
7. TUI and manual editing use one strictly validated TOML file; application writes are fsync-backed and atomically replaced.
8. Priority means KEV or effective CVSS at/above the configured threshold. Missing data is never inferred.
9. News association uses only exact `CVE-YYYY-NNNN...` matches in feed-provided title/excerpt.
10. The TUI serves cached data immediately, syncs in the background when due, and supports explicit offline mode.

## Public seams and verification gates

- Configuration load/save and validation
- SQLite migration and domain persistence
- CVSS precedence
- Article/CVE deduplication and extraction
- Transition generation and first-run suppression
- Concurrent-sync rejection
- Source parser fixtures and HTTP pagination
- Partial-source failure preservation
- CLI status/version behavior
- Textual offline UI smoke, filtering, and settings round trip
- Optional live upstream compatibility smoke
- Package build and Linux scheduling documentation
