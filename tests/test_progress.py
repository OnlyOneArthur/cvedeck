"""Tests for sync progress reporting on the Synchronizer and sync_database seams."""
from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cvedeck import sync as sync_module
from cvedeck.config import FeedSettings, Settings
from cvedeck.db import Database
from cvedeck.locking import SyncLock
from cvedeck.sync import Synchronizer, SyncProgress, sync_database

NOW = datetime(2026, 9, 11, tzinfo=UTC)
RSS = b'<rss version="2.0"><channel><item><guid>g1</guid><title>CVE-2026-3000 fixed</title><link>https://news.test/a?utm_source=rss</link><description>Details</description></item></channel></rss>'


def cve_payload(cve_id: str, score: float = 9.5) -> dict:
    return {"cveMetadata": {"cveId": cve_id, "datePublished": "2026-09-10T00:00:00Z"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": f"Details for {cve_id}"}],
            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": score}}]}}}


class FakeClient:
    def __init__(self, trace: list[Any] | None = None, slow_kev: bool = False,
                 fail_feed: str | None = None):
        self.trace: list[Any] = trace if trace is not None else []
        self.slow_kev = slow_kev
        self.fail_feed = fail_feed

    async def kev(self) -> dict:
        self.trace.append("fetch:kev")
        if self.slow_kev:
            await asyncio.sleep(30)
        return {"vulnerabilities": [
            {"cveID": "CVE-2019-1000", "dateAdded": "2020-01-01"},
            {"cveID": "CVE-2026-2000", "dateAdded": "2026-09-10"},
        ]}

    async def nvd_since(self, since: datetime) -> dict:
        self.trace.append("fetch:nvd")
        return {"vulnerabilities": [{"cve": {"id": "CVE-2026-3000", "published": "2026-09-10T00:00:00Z",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]}

    async def cve(self, cve_id: str) -> dict:
        self.trace.append(f"fetch:cve:{cve_id}")
        return cve_payload(cve_id)

    async def feed(self, name: str) -> bytes:
        self.trace.append(f"fetch:feed:{name}")
        if name == self.fail_feed:
            raise RuntimeError("feed down")
        return RSS


def make_sync(tmp_path: Path, client: FakeClient,
              progress: Any) -> tuple[Database, Synchronizer]:
    db = Database(tmp_path / "db.sqlite")
    sync = Synchronizer(db, Settings(feeds=FeedSettings(True, False, False)), client,
                        tmp_path / "sync.lock", clock=lambda: NOW, progress=progress)
    return db, sync


@pytest.mark.asyncio
async def test_stage_start_emitted_before_blocking_fetch(tmp_path: Path) -> None:
    trace: list[Any] = []

    def record(event: SyncProgress) -> None:
        trace.append(f"{event.source}:{event.status}")

    _, sync = make_sync(tmp_path, FakeClient(trace), record)
    result = await sync.run()
    assert result.ok
    assert trace.index("kev:running") < trace.index("fetch:kev")
    assert trace.index("nvd:running") < trace.index("fetch:nvd")
    assert trace.index("cve_program:running") < trace.index("fetch:cve:CVE-2026-2000")
    assert trace.index("feed:krebs:running") < trace.index("fetch:feed:krebs")


@pytest.mark.asyncio
async def test_success_events_carry_genuine_counts_and_elapsed(tmp_path: Path) -> None:
    events: list[SyncProgress] = []
    _, sync = make_sync(tmp_path, FakeClient(), events.append)
    result = await sync.run()
    terminal = {(event.source, event.status): event for event in events}
    assert terminal["kev", "success"].count == 2
    assert terminal["nvd", "success"].count == 1
    assert terminal["cve_program", "success"].count == result.hydrated == 2
    assert terminal["feed:krebs", "success"].count == 1
    assert ("sync", "complete") in terminal
    for event in events:
        assert event.elapsed >= 0.0


@pytest.mark.asyncio
async def test_error_event_carries_stage_and_message(tmp_path: Path) -> None:
    events: list[SyncProgress] = []
    _, sync = make_sync(tmp_path, FakeClient(fail_feed="krebs"), events.append)
    result = await sync.run()
    assert not result.ok
    error = next(event for event in events
                 if event.source == "feed:krebs" and event.status == "error")
    assert error.error == "feed down"


@pytest.mark.asyncio
async def test_hydration_reports_incremental_processed_counts(tmp_path: Path) -> None:
    events: list[SyncProgress] = []
    _, sync = make_sync(tmp_path, FakeClient(), events.append)
    await sync.run()
    counts = [event.count for event in events
              if event.source == "cve_program" and event.status == "running"
              and event.count is not None]
    assert counts == [1, 2]


@pytest.mark.asyncio
async def test_cancellation_never_emits_complete_and_releases_lock(tmp_path: Path) -> None:
    events: list[SyncProgress] = []
    _, sync = make_sync(tmp_path, FakeClient(slow_kev=True), events.append)
    task = asyncio.create_task(sync.run())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(event.status != "complete" for event in events)
    with SyncLock(tmp_path / "sync.lock"):
        pass  # lock was released during cancellation cleanup


def test_sync_database_progress_callback_is_optional_keyword() -> None:
    parameters = inspect.signature(sync_database).parameters
    assert parameters["progress"].default is None


@pytest.mark.asyncio
async def test_sync_database_forwards_progress_to_synchronizer(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeContext:
        def __init__(self, inner: FakeClient) -> None:
            self.inner = inner

        async def __aenter__(self) -> FakeClient:
            return self.inner

        async def __aexit__(self, *args: object) -> None:
            return None

    def fake_resolve_key(*args: Any, **kwargs: Any) -> tuple[str | None, str]:
        return None, "test"

    client = FakeClient()
    monkeypatch.setattr(sync_module, "resolve_key", fake_resolve_key)
    monkeypatch.setattr(sync_module, "SourceClient", lambda key: FakeContext(client))
    events: list[SyncProgress] = []
    db = Database(tmp_path / "db.sqlite")
    result = await sync_database(db, Settings(feeds=FeedSettings(True, False, False)),
                                 tmp_path / "db.sqlite", progress=events.append)
    assert result.ok
    assert any(event.source == "kev" and event.status == "success" for event in events)


def test_progress_str_is_human_readable() -> None:
    assert str(SyncProgress("kev", "success", count=2, elapsed=0.1)) == \
        "kev success 2 records (0.1s)"
    rendered = str(SyncProgress("feed:krebs", "error", elapsed=0.3, error="feed down"))
    assert "feed:krebs error" in rendered
    assert "feed down" in rendered
