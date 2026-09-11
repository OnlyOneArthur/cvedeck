from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .config import config_path, data_path, load_settings
from .db import Database
from .sync import SyncProgress, sync_database


def _report_progress(event: SyncProgress) -> None:
    print(f"sync: {event}", file=sys.stderr, flush=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="cvedeck", description="Local CVE intelligence dashboard")
    result.add_argument("--version", action="version", version=f"CVEDeck {__version__}")
    result.add_argument("--offline", action="store_true", help="open cached data without network access")
    result.add_argument("--database", type=Path, help=argparse.SUPPRESS)
    result.add_argument("--config", type=Path, help=argparse.SUPPRESS)
    sub = result.add_subparsers(dest="command")
    sub.add_parser("tui", help="open the terminal interface")
    sync = sub.add_parser("sync", help="synchronize all enabled sources")
    sync.add_argument("--notify", action="store_true", help="deliver pending desktop notifications")
    sub.add_parser("status", help="show local source status")
    return result


def _status(database: Path) -> int:
    db = Database(database)
    try:
        rows = db.rows("SELECT source,last_success_at,error FROM sync_state ORDER BY source")
        if not rows:
            print("No synchronization has completed yet.")
            return 0
        for row in rows:
            state = f"ERROR: {row['error']}" if row["error"] else "OK"
            print(f"{row['source']:<24} {state:<12} {row['last_success_at'] or 'never'}")
        return 1 if any(row["error"] for row in rows) else 0
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    database = args.database or data_path()
    config_file = args.config or config_path()
    try:
        settings = load_settings(config_file)
    except (TypeError, ValueError, OSError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    if args.command == "status":
        return _status(database)
    if args.command == "sync":
        db = Database(database)
        try:
            result = asyncio.run(sync_database(db, settings, database, args.notify,
                                               progress=_report_progress))
        except RuntimeError as error:
            print(str(error), file=sys.stderr)
            return 2
        finally:
            db.close()
        print(f"Discovered {result.discovered}; hydrated {result.hydrated}; "
              f"KEV {result.kev_entries}; articles {result.articles}; notifications {result.notifications}")
        for source, message in result.errors.items():
            print(f"{source}: {message}", file=sys.stderr)
        return 0 if result.ok else 1
    from .tui import CVEDeckApp
    CVEDeckApp(database, config_file, offline=args.offline).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
