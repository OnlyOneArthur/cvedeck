"""Markdown export of stored CVEDeck records.

Presentation-layer module: formats already-persisted facts only. It never
reads configuration values, secret files, or raw JSON payloads.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

_UNAVAILABLE = "Not yet available"

_NUL = "\x00"
# Control characters except tab and newline; upstream text never needs them.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")
# Markdown inline specials that forge links, code spans, or images.
_MD_INLINE_RE = re.compile(r"([\\`[\]])")
# Markdown block structure at line start: headings, quotes, lists, rules.
# Ordered-list markers need trailing whitespace (so "4.0" stays untouched).
_MD_LEAD_RE = re.compile(r"(?m)^([ \t]*)([#>*+-]|\d+[.)](?=[ \t]))")


def _sanitize(text: str) -> str:
    """Make upstream-derived text safe as Markdown body text.

    Strips control characters, escapes HTML, and defuses Markdown structure
    so imported content stays inert quoted text inside the exported document.
    """
    text = _CONTROL_RE.sub("\ufffd", text)
    text = html.escape(text, quote=False)
    text = _MD_INLINE_RE.sub(r"\\\1", text)
    return _MD_LEAD_RE.sub(r"\1\\\2", text)


def _safe_filename(filename: str) -> str:
    """Reduce a filename to a flat, traversal-free basename."""
    if _NUL in filename:
        raise ValueError("Export filename must not contain NUL")
    name = Path(filename).name
    if name in ("", ".", ".."):
        raise ValueError(f"Export filename is empty or a path: {filename!r}")
    return name


def resolve_export_dir(path_text: str, home: Path | None = None) -> Path:
    """Accept ``~/...`` or an absolute path; reject anything relative.

    ``~otheruser/...`` is rejected: only the caller's own home is expanded.
    """
    text = path_text.strip()
    if _NUL in text:
        raise ValueError(f"Export path must not contain NUL: {path_text!r}")
    if text.startswith("~/"):
        if home is None:
            return Path(text).expanduser()
        return Path(str(home) + text[1:])
    candidate = Path(text)
    if not candidate.is_absolute():
        raise ValueError(f"Export path must be absolute or start with ~/: {path_text}")
    return candidate


def export_filename(record_id: str, timestamp: str) -> str:
    return _safe_filename(f"{record_id}-{timestamp}.md")


def write_export(directory: Path, filename: str, content: str) -> Path:
    """Create the directory and write exclusively; collisions never overwrite.

    The filename is flattened to its basename so traversal components cannot
    move the write outside ``directory``. A failed write removes the partial
    file.
    """
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / _safe_filename(filename)
    stem, suffix = target.stem, target.suffix
    counter = 0
    while True:
        try:
            with target.open("x", encoding="utf-8") as handle:
                handle.write(content)
            return target
        except FileExistsError:
            counter += 1
            target = directory / f"{stem}-{counter}{suffix}"
        except BaseException:
            target.unlink(missing_ok=True)
            raise


def format_cve_markdown(
    cve_id: str,
    is_kev: bool,
    published_at: str | None,
    description: str | None,
    metrics: list[tuple[str, str, float, str | None]],
    products: list[tuple[str | None, str | None, int]],
    weaknesses: list[tuple[str, str]],
    references: list[str],
    kev: tuple[str | None, str | None, str | None, str | None] | None,
    cve_url: str,
) -> str:
    """Compact Markdown built from stored, sourced facts."""
    metric_text = ", ".join(
        f"{_sanitize(source)} {_sanitize(version)} {score:g}"
        + (f" ({_sanitize(vector)})" if vector else "")
        for source, version, score, vector in metrics
    ) or _UNAVAILABLE
    product_text = ", ".join(
        f"{_sanitize(vendor or '?')} {_sanitize(product or '?')} ({rules} version rule(s))"
        for vendor, product, rules in products
    ) or _UNAVAILABLE
    weakness_text = ", ".join(
        f"{_sanitize(cwe)} ({_sanitize(source)})" for cwe, source in weaknesses
    ) or _UNAVAILABLE
    reference_text = "\n".join(f"- {_sanitize(url)}" for url in references) or _UNAVAILABLE
    if kev:
        date_added, due_date, action, ransomware = kev
        kev_text = (
            f"- Listed: {_sanitize(date_added or _UNAVAILABLE)}\n"
            f"- Due: {_sanitize(due_date or _UNAVAILABLE)}\n"
            f"- Required action: {_sanitize(action or _UNAVAILABLE)}\n"
            f"- Ransomware use: {_sanitize(ransomware or 'Unknown')}"
        )
    else:
        kev_text = "Not listed"
    return (
        f"# {_sanitize(cve_id)}\n\n"
        f"KEV: {'Yes' if is_kev else 'No'}\n\n"
        f"Published: {_sanitize(published_at or _UNAVAILABLE)}\n\n"
        f"{_sanitize(description or _UNAVAILABLE)}\n\n"
        f"## CVSS\n\n{metric_text}\n\n"
        f"## Affected products\n\n{product_text}\n\n"
        f"## Weaknesses\n\n{weakness_text}\n\n"
        f"## References\n\n{reference_text}\n\n"
        f"## KEV\n\n{kev_text}\n\n"
        f"Source record: {_sanitize(cve_url)}\n"
    )


def format_article_markdown(
    title: str,
    source: str,
    published_at: str | None,
    original_url: str,
    excerpt: str | None,
    linked_cves: list[str],
) -> str:
    """Compact Markdown from stored article metadata (no scraping, no AI)."""
    cve_text = ", ".join(_sanitize(cve) for cve in linked_cves) or _UNAVAILABLE
    excerpt_text = f"Publisher excerpt: {_sanitize(excerpt)}" if excerpt else _UNAVAILABLE
    return (
        f"# {_sanitize(title)}\n\n"
        f"Source: {_sanitize(source)}\n\n"
        f"Published: {_sanitize(published_at or _UNAVAILABLE)}\n\n"
        f"URL: {_sanitize(original_url)}\n\n"
        f"{excerpt_text}\n\n"
        f"Linked CVEs: {cve_text}\n"
    )