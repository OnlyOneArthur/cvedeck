import os
from datetime import UTC, datetime, timedelta

import pytest

from cvedeck.parsers import parse_cve_record, parse_feed, parse_kev, parse_nvd_page
from cvedeck.sources import FEEDS, SourceClient

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("RUN_LIVE_CVEDECK_TESTS") != "1",
        reason="set RUN_LIVE_CVEDECK_TESTS=1 to contact public upstream services",
    ),
]


@pytest.mark.asyncio
async def test_public_upstreams_are_parseable() -> None:
    async with SourceClient(os.environ.get("NVD_API_KEY")) as client:
        assert parse_cve_record(await client.cve("CVE-2024-3094"))["cve_id"] == "CVE-2024-3094"
        assert parse_kev(await client.kev())
        since = datetime.now(UTC) - timedelta(minutes=5)
        parse_nvd_page(await client.nvd_since(since))
        for source in FEEDS:
            assert parse_feed(source, await client.feed(source), datetime.now(UTC).isoformat())