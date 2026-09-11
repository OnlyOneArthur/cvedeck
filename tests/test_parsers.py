from cvedeck.parsers import (
    extract_cve_ids,
    normalize_url,
    parse_cve_record,
    parse_feed,
    parse_kev,
    parse_nvd_page,
)


def test_exact_cve_extraction_and_url_normalization() -> None:
    text = "cve-2026-1234, CVE-2026-12345; CVE-26-9999"
    assert extract_cve_ids(text) == ["CVE-2026-1234", "CVE-2026-12345"]
    assert normalize_url("HTTPS://Example.COM/post/?utm_source=x&b=2#part") == "https://example.com/post?b=2"


def test_parse_sources_keep_all_scores_separate() -> None:
    cve = parse_cve_record({"cveMetadata": {"cveId": "CVE-2026-1234"}, "containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "Description"}],
        "metrics": [{"cvssV4_0": {"version": "4.0", "baseScore": 9.1}},
                    {"cvssV3_1": {"version": "3.1", "baseScore": 8.8}}],
        "affected": [{"vendor": "Acme", "product": "Widget", "versions": [{"version": "1"}]}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
        "references": [{"url": "https://advisory.test/1", "tags": ["vendor-advisory"]}],
    }}})
    assert [(m["version"], m["score"]) for m in cve["metrics"]] == [("4.0", 9.1), ("3.1", 8.8)]
    assert cve["description"] == "Description"
    assert cve["references"] == [{"url": "https://advisory.test/1", "tags": ["vendor-advisory"]}]
    nvd = parse_nvd_page({"vulnerabilities": [{"cve": {"id": "CVE-2026-1234", "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/..."}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"
        }]}]}]
    }}]})
    assert nvd[0]["metrics"][0] == {"version": "3.1", "score": 9.8, "vector": "CVSS:3.1/..."}
    assert nvd[0]["products"][0]["product"] == "widget"


def test_kev_and_feed_parsing() -> None:
    kev = parse_kev({"vulnerabilities": [{"cveID": "CVE-2026-1234", "dateAdded": "2026-09-10"}]})
    assert kev[0]["cve_id"] == "CVE-2026-1234"
    feed = b'<rss version="2.0"><channel><item><guid>g1</guid><title>CVE-2026-1234 fixed</title><link>https://e.test/a?utm_medium=rss</link><description>&lt;b&gt;Patch now&lt;/b&gt;</description></item></channel></rss>'
    article = parse_feed("test", feed, "now")[0]
    assert article["feed_guid"] == "g1"
    assert article["original_url"].endswith("utm_medium=rss")
    assert article["normalized_url"] == "https://e.test/a"
    assert article["excerpt"] == "Patch now"
