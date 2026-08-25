"""
report_parser/ingest.py

Single entry point for report ingestion: pass raw bytes (or a URL) plus a
declared/detected format, get back (IRDetection, warnings, metadata). This
is what the CLI/GUI should call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .format_loaders import (
    ReportLoadError,
    load_text_from_docx,
    load_text_from_html,
    load_text_from_pdf,
    load_text_from_plain,
)
from .ioc_extraction import extract_iocs
from .attck_matcher import match_techniques
from .builder import build_ir_from_report
from .url_fetcher import fetch_report_url, UnsafeUrlError
from ir.schema import IRDetection

SUPPORTED_FORMATS = {"pdf", "docx", "html", "text"}


@dataclass
class ReportMetadata:
    title: str
    source: str                 # filename or URL
    format: str
    fetched_at: datetime = field(default_factory=datetime.utcnow)


def detect_format(data: bytes, filename: str = "") -> str:
    lower_name = filename.lower()
    if data.startswith(b"%PDF-") or lower_name.endswith(".pdf"):
        return "pdf"
    if data[:2] == b"PK" or lower_name.endswith(".docx"):
        return "docx"
    stripped = data.lstrip()[:200].lower()
    if stripped.startswith(b"<!doctype html") or stripped.startswith(b"<html") or lower_name.endswith((".html", ".htm")):
        return "html"
    return "text"


def ingest_report(
    *,
    data: Optional[bytes] = None,
    url: Optional[str] = None,
    filename: str = "",
    title: Optional[str] = None,
    format_hint: Optional[str] = None,
    publish_date: Optional[datetime] = None,
) -> tuple[IRDetection, list[str], ReportMetadata]:
    """
    Provide either `data` (raw file bytes) or `url` (fetched with SSRF
    protections — see url_fetcher.py), not both. Returns
    (IRDetection, warnings, ReportMetadata).
    """
    warnings: list[str] = []

    if data is None and url is None:
        raise ValueError("must provide either data or url")
    if data is not None and url is not None:
        raise ValueError("provide only one of data or url, not both")

    source = filename or "unknown"
    if url is not None:
        try:
            data = fetch_report_url(url)
        except UnsafeUrlError as exc:
            raise ReportLoadError(f"could not fetch report URL: {exc}") from exc
        source = url

    fmt = format_hint or detect_format(data, filename)
    if fmt not in SUPPORTED_FORMATS:
        raise ReportLoadError(f"unsupported format '{fmt}' (supported: {sorted(SUPPORTED_FORMATS)})")

    if fmt == "pdf":
        text, pdf_warnings = load_text_from_pdf(data)
        warnings.extend(pdf_warnings)
    elif fmt == "docx":
        text = load_text_from_docx(data)
    elif fmt == "html":
        text = load_text_from_html(data)
    else:
        text = load_text_from_plain(data)

    if not text.strip():
        warnings.append("no text content could be extracted from this document")

    iocs = extract_iocs(text)
    techniques = match_techniques(text)

    report_title = title or filename or (url if url else "untitled report")

    detection = build_ir_from_report(
        iocs, techniques,
        report_title=report_title,
        report_source=source,
        report_bytes_for_fingerprint=data,
        report_publish_date=publish_date,
    )

    metadata = ReportMetadata(title=report_title, source=source, format=fmt)
    return detection, warnings, metadata
