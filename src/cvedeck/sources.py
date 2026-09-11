from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Self, cast

import httpx

USER_AGENT = "CVEDeck/0.1 (+https://github.com/OnlyOneArthur/cvedeck)"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_URL = "https://cveawg.mitre.org/api/cve"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEEDS = {
    "krebs": "https://krebsonsecurity.com/feed/",
    "the_hacker_news": "https://thehackernews.com/feeds/posts/default",
    "securityweek": "https://www.securityweek.com/feed/",
}


class SourceClient:
    def __init__(self, nvd_api_key: str | None = None, transport: httpx.AsyncBaseTransport | None = None):
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        self.client = httpx.AsyncClient(headers=headers, timeout=30, follow_redirects=True, transport=transport)
        self.nvd_api_key = nvd_api_key

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.client.aclose()

    async def _get(self, url: str, **params: Any) -> httpx.Response:
        last: Exception | None = None
        for delay in (0, 1, 3):
            if delay:
                await asyncio.sleep(delay)
            try:
                response = await self.client.get(url, params=params or None)
                response.raise_for_status()
                return response
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as error:
                last = error
                if (isinstance(error, httpx.HTTPStatusError)
                        and error.response.status_code < 500
                        and error.response.status_code != 429):
                    break
        assert last is not None
        raise last

    async def kev(self) -> dict[str, Any]:
        return cast(dict[str, Any], (await self._get(KEV_URL)).json())

    async def feed(self, name: str) -> bytes:
        return (await self._get(FEEDS[name])).content

    async def cve(self, cve_id: str) -> dict[str, Any]:
        return cast(dict[str, Any], (await self._get(f"{CVE_URL}/{cve_id}")).json())

    async def nvd_since(self, since: datetime) -> dict[str, Any]:
        end = datetime.now(UTC)
        since = max(since, end - timedelta(days=119))
        params: dict[str, Any] = {
            "lastModStartDate": since.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "lastModEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "resultsPerPage": 2000,
        }
        records: list[dict[str, Any]] = []
        start = 0
        while True:
            response = await self._get(NVD_URL, **params, startIndex=start)
            page = response.json()
            records.extend(page.get("vulnerabilities", []))
            start += int(page.get("resultsPerPage", 0))
            if start >= int(page.get("totalResults", 0)) or not page.get("resultsPerPage"):
                break
            await asyncio.sleep(0.7 if self.nvd_api_key else 6.0)
        return {"vulnerabilities": records}
