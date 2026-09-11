import asyncio
from pathlib import Path

import pytest
from test_progress import FakeClient, make_sync


@pytest.mark.asyncio
async def test_cancelling_hydration_awaits_children(tmp_path: Path) -> None:
    started = asyncio.Event()
    active = set()

    class SlowClient(FakeClient):
        async def cve(self, cve_id: str) -> dict:
            active.add(cve_id)
            started.set()
            try:
                await asyncio.Event().wait()
                return {}
            finally:
                active.remove(cve_id)

    events = []
    db, sync = make_sync(tmp_path, SlowClient(), events.append)
    task = asyncio.create_task(sync.run())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert not active
        assert not any(event.status == 'complete' for event in events)
    finally:
        # Clean up leaked fetch tasks in the failing (red) version.
        children = [task for task in asyncio.all_tasks() if 'fetch_record' in task.get_coro().__qualname__]
        for child in children:
            child.cancel()
        await asyncio.gather(*children, return_exceptions=True)
        db.close()
