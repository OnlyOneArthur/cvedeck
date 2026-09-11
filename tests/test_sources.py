import json
from datetime import UTC, datetime

import httpx
import pytest

from cvedeck.sources import SourceClient


@pytest.mark.asyncio
async def test_nvd_pagination_and_api_key_header() -> None:
    starts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["apiKey"] == "secret"
        starts.append(request.url.params["startIndex"])
        start = int(request.url.params["startIndex"])
        payload = {"totalResults": 2, "resultsPerPage": 1,
                   "vulnerabilities": [{"cve": {"id": f"CVE-2026-{1000 + start}"}}]}
        return httpx.Response(200, content=json.dumps(payload), request=request)

    async with SourceClient("secret", httpx.MockTransport(handler)) as client:
        result = await client.nvd_since(datetime(2026, 9, 1, tzinfo=UTC))
    assert starts == ["0", "1"]
    assert [item["cve"]["id"] for item in result["vulnerabilities"]] == ["CVE-2026-1000", "CVE-2026-1001"]


@pytest.mark.asyncio
async def test_non_retryable_source_error_is_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, request=request)

    async with SourceClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.cve("CVE-2026-9999")
