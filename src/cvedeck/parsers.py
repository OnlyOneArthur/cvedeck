from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import feedparser

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
TRACKING = {"fbclid", "gclid"}


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in CVE_PATTERN.findall(text or "")})


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
             if not key.lower().startswith("utm_") and key.lower() not in TRACKING]
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, urlencode(query), ""))


def _text(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item.get("lang") in ("en", None):
                return str(item.get("value", ""))
        return ""
    return str(value or "")


def _score(metric: dict[str, Any]) -> tuple[str, float, str | None] | None:
    data = metric.get("cvssData", metric)
    version = str(data.get("version", ""))
    if version not in {"4.0", "3.1", "3.0"} or data.get("baseScore") is None:
        return None
    return version, float(data["baseScore"]), data.get("vectorString")


def parse_cve_record(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("cveMetadata", {})
    cna = payload.get("containers", {}).get("cna", {})
    metrics: list[dict[str, Any]] = []
    for item in cna.get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in item:
                parsed = _score(item[key])
                if parsed:
                    version, score, vector = parsed
                    metrics.append({"version": version, "score": score, "vector": vector})
    products = []
    for affected in cna.get("affected", []):
        products.append({
            "vendor": affected.get("vendor"), "product": affected.get("product"),
            "versions": affected.get("versions", []),
        })
    cwes = []
    for weakness in cna.get("problemTypes", []):
        for description in weakness.get("descriptions", []):
            value = description.get("cweId") or description.get("description", "")
            if re.fullmatch(r"CWE-\d+", value):
                cwes.append(value)
    return {
        "cve_id": metadata["cveId"], "state": metadata.get("state", "PUBLISHED"),
        "published_at": metadata.get("datePublished"), "updated_at": metadata.get("dateUpdated"),
        "description": _text(cna.get("descriptions", [])), "hydrated": True,
        "metrics": metrics, "products": products, "cwes": sorted(set(cwes)),
        "references": [{"url": item.get("url"), "tags": item.get("tags", [])}
                       for item in cna.get("references", []) if item.get("url")],
    }


def parse_nvd_page(payload: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for wrapper in payload.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        metrics: list[dict[str, Any]] = []
        for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
            for metric in cve.get("metrics", {}).get(key, []):
                data = metric.get("cvssData", {})
                if data.get("baseScore") is not None:
                    metrics.append({"version": version, "score": float(data["baseScore"]),
                                    "vector": data.get("vectorString")})
        cwes = [d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", [])
                if re.fullmatch(r"CWE-\d+", d.get("value", ""))]
        cpe_products: dict[tuple[str, str], list[dict[str, Any]]] = {}
        pending = [node for configuration in cve.get("configurations", [])
                   for node in configuration.get("nodes", [])]
        while pending:
            node = pending.pop()
            pending.extend(node.get("children", []))
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product = unquote(parts[3]), unquote(parts[4])
                cpe_version = {key: value for key, value in match.items()
                               if key == "criteria" or key.startswith("version")}
                cpe_products.setdefault((vendor, product), []).append(cpe_version)
        records.append({"cve_id": cve["id"], "published_at": cve.get("published"),
                        "updated_at": cve.get("lastModified"), "metrics": metrics,
                        "cwes": sorted(set(cwes)),
                        "products": [{"vendor": key[0], "product": key[1], "versions": versions}
                                     for key, versions in cpe_products.items()]})
    return records


def parse_kev(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [{
        "cve_id": item["cveID"], "vendor": item.get("vendorProject"),
        "product": item.get("product"), "name": item.get("vulnerabilityName"),
        "date_added": item.get("dateAdded"), "description": item.get("shortDescription"),
        "action": item.get("requiredAction"), "due_date": item.get("dueDate"),
        "ransomware_use": item.get("knownRansomwareCampaignUse"),
    } for item in payload.get("vulnerabilities", [])]


def parse_feed(source: str, payload: bytes, scraped_at: str) -> list[dict[str, Any]]:
    feed = feedparser.parse(payload)
    if feed.bozo and not feed.entries:
        raise ValueError(f"Invalid feed for {source}: {feed.bozo_exception}")
    articles = []
    for entry in feed.entries:
        original = entry.get("link", "").strip()
        if not original:
            continue
        published = entry.get("published_parsed") or entry.get("updated_parsed")
        published_at = None
        if published:
            published_at = datetime(
                published.tm_year, published.tm_mon, published.tm_mday,
                published.tm_hour, published.tm_min, published.tm_sec, tzinfo=UTC,
            ).isoformat()
        excerpt = entry.get("summary", "")
        excerpt = re.sub(r"<[^>]+>", " ", html.unescape(excerpt))
        excerpt = " ".join(excerpt.split())
        articles.append({
            "source": source, "feed_guid": entry.get("id") or entry.get("guid"),
            "normalized_url": normalize_url(original), "original_url": original,
            "title": html.unescape(entry.get("title", "Untitled")).strip(),
            "published_at": published_at, "excerpt": excerpt[:1000], "scraped_at": scraped_at,
        })
    return articles
