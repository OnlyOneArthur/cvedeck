"""Tests for the e-key Markdown export of stored CVEDeck records."""
from __future__ import annotations

from pathlib import Path

import pytest

from cvedeck.export import (
    export_filename,
    format_article_markdown,
    format_cve_markdown,
    resolve_export_dir,
    write_export,
)


def test_resolve_export_dir_expands_tilde() -> None:
    assert resolve_export_dir(
        "~/Documents/CVEDeck/exports", home=Path("/home/tester")
    ) == Path("/home/tester/Documents/CVEDeck/exports")


def test_resolve_export_dir_accepts_absolute() -> None:
    assert resolve_export_dir("/tmp/exports") == Path("/tmp/exports")


@pytest.mark.parametrize("bad", ["exports", "relative/dir", "./here", ""])
def test_resolve_export_dir_rejects_relative(bad: str) -> None:
    with pytest.raises(ValueError, match="absolute"):
        resolve_export_dir(bad)


def test_export_filename_contains_id_and_timestamp() -> None:
    name = export_filename("CVE-2026-1234", "20260911T161700")
    assert name == "CVE-2026-1234-20260911T161700.md"


def test_write_export_is_exclusive_and_never_overwrites(tmp_path: Path) -> None:
    first = write_export(tmp_path, "CVE-2026-1234-20260911T161700.md", "# One\n")
    assert first.read_text(encoding="utf-8") == "# One\n"
    second = write_export(tmp_path, "CVE-2026-1234-20260911T161700.md", "# Two\n")
    assert second != first
    assert first.read_text(encoding="utf-8") == "# One\n"
    assert second.read_text(encoding="utf-8") == "# Two\n"
    assert sorted(path.name for path in tmp_path.glob("*.md")) == [
        "CVE-2026-1234-20260911T161700-1.md",
        "CVE-2026-1234-20260911T161700.md",
    ]


def test_write_export_failure_raises_oserror(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    with pytest.raises(OSError):
        write_export(blocker / "nested", "CVE-2026-1234-20260911T161700.md", "# x\n")


def test_format_cve_markdown_uses_stored_facts_only() -> None:
    markdown = format_cve_markdown(
        cve_id="CVE-2026-1234",
        is_kev=True,
        published_at="2026-09-10T00:00:00+00:00",
        description="Example issue",
        metrics=[("CNA", "4.0", 9.5, "CVSS:4.0/AV:N")],
        products=[("Acme", "Widget", 2)],
        weaknesses=[("CWE-79", "CNA")],
        references=["https://advisory.test/1"],
        kev=("2026-09-01", "2026-09-30", "Apply patch", "Known"),
        cve_url="https://www.cve.org/CVERecord?id=CVE-2026-1234",
    )
    assert "# CVE-2026-1234" in markdown
    assert "Example issue" in markdown
    assert "CNA 4.0 9.5" in markdown
    assert "Acme Widget" in markdown
    assert "CWE-79" in markdown
    assert "https://advisory.test/1" in markdown
    assert "2026-09-01" in markdown
    assert "https://www.cve.org/CVERecord?id=CVE-2026-1234" in markdown
    assert "api_key" not in markdown.lower()


def test_format_cve_markdown_marks_missing_facts_unavailable() -> None:
    markdown = format_cve_markdown(
        cve_id="CVE-2026-0000",
        is_kev=False,
        published_at=None,
        description=None,
        metrics=[],
        products=[],
        weaknesses=[],
        references=[],
        kev=None,
        cve_url="https://www.cve.org/CVERecord?id=CVE-2026-0000",
    )
    assert "Not yet available" in markdown
    assert "Not listed" in markdown


def test_resolve_export_dir_rejects_other_user_tilde() -> None:
    with pytest.raises(ValueError, match="absolute"):
        resolve_export_dir("~root/exports", home=Path("/home/tester"))


@pytest.mark.parametrize("bad", ["~/x\x00", "/tmp/\x00exports"])
def test_resolve_export_dir_rejects_nul(bad: str) -> None:
    with pytest.raises(ValueError, match="NUL"):
        resolve_export_dir(bad)


def test_write_export_sanitizes_traversal_filename(tmp_path: Path) -> None:
    target = write_export(tmp_path, "../evil.md", "# x\n")
    assert target.parent == tmp_path
    assert target.name == "evil.md"
    assert not (tmp_path.parent / "evil.md").exists()


def test_write_export_flattens_subdirectory_filenames(tmp_path: Path) -> None:
    target = write_export(tmp_path, "sub/dir/x.md", "# x\n")
    assert target.parent == tmp_path
    assert target.name == "x.md"


def test_write_export_rejects_dot_filenames(tmp_path: Path) -> None:
    for bad in ("..", ".", ""):
        with pytest.raises(ValueError):
            write_export(tmp_path, bad, "# x\n")


def test_write_export_rejects_nul_filename(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="NUL"):
        write_export(tmp_path, "x\x00.md", "# x\n")


def test_write_export_cleans_up_partial_file_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = Path.open

    def failing_open(self: Path, mode: str, *args: object, **kwargs: object):
        handle = real_open(self, mode, *args, **kwargs)  # type: ignore[arg-type]
        real_write = handle.write

        def broken_write(data: str) -> int:
            raise OSError("disk full")

        handle.write = broken_write  # type: ignore[method-assign]
        assert real_write is not None
        return handle

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(OSError, match="disk full"):
        write_export(tmp_path, "partial.md", "# partial\n")
    assert not (tmp_path / "partial.md").exists()


def test_format_article_markdown_labels_publisher_excerpt() -> None:
    markdown = format_article_markdown(
        title="Vendor patch released",
        source="krebs",
        published_at=None,
        original_url="https://news.test/a",
        excerpt="Details about CVE-2026-1234",
        linked_cves=[],
    )
    assert "Publisher excerpt: Details about CVE-2026-1234" in markdown


def test_format_article_markdown_escapes_unsafe_excerpt() -> None:
    markdown = format_article_markdown(
        title="Vendor patch released",
        source="krebs",
        published_at=None,
        original_url="https://news.test/a",
        excerpt="<script>alert(1)</script>\n# Forged heading\n[click](https://evil.test)",
        linked_cves=[],
    )
    assert "<script>" not in markdown
    assert "alert(1)" in markdown
    assert "\n# Forged heading" not in markdown
    assert "[click]" not in markdown
    assert "https://evil.test" in markdown


def test_format_cve_markdown_escapes_unsafe_description() -> None:
    markdown = format_cve_markdown(
        cve_id="CVE-2026-1234",
        is_kev=False,
        published_at=None,
        description="<img src=x onerror=alert(1)> & \x07bell",
        metrics=[],
        products=[],
        weaknesses=[],
        references=[],
        kev=None,
        cve_url="https://www.cve.org/CVERecord?id=CVE-2026-1234",
    )
    assert "<img" not in markdown
    assert "\x07" not in markdown
    assert "onerror=alert(1)" in markdown


def test_format_article_markdown_uses_stored_metadata_only() -> None:
    markdown = format_article_markdown(
        title="Vendor patch released",
        source="krebs",
        published_at="2026-09-10T00:00:00+00:00",
        original_url="https://news.test/a",
        excerpt="Details about CVE-2026-1234",
        linked_cves=["CVE-2026-1234"],
    )
    assert "# Vendor patch released" in markdown
    assert "krebs" in markdown
    assert "https://news.test/a" in markdown
    assert "Details about CVE-2026-1234" in markdown
    assert "CVE-2026-1234" in markdown
