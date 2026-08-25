"""
report_parser/tests/test_report_parser.py

Run with: pytest report_parser/tests/ -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from report_parser.format_loaders import (  # noqa: E402
    load_text_from_html, load_text_from_docx, load_text_from_pdf,
    load_text_from_plain, ReportLoadError,
)
from report_parser.ioc_extraction import extract_iocs  # noqa: E402
from report_parser.attck_matcher import match_techniques  # noqa: E402
from report_parser.url_fetcher import is_safe_url, UnsafeUrlError  # noqa: E402
from report_parser.ingest import ingest_report, detect_format  # noqa: E402

from .report_fixtures import build_minimal_docx, build_minimal_pdf_uncompressed, build_minimal_pdf_flate_compressed


def test_load_text_from_html_strips_tags_and_scripts():
    html = b"<html><body><p>Hello <b>World</b></p><script>evil()</script></body></html>"
    text = load_text_from_html(html)
    assert "Hello" in text and "World" in text
    assert "evil()" not in text


def test_load_text_from_docx_roundtrip():
    docx_bytes = build_minimal_docx(["First paragraph.", "Second paragraph with 203.0.113.5"])
    text = load_text_from_docx(docx_bytes)
    assert "First paragraph." in text
    assert "203.0.113.5" in text


def test_load_text_from_docx_rejects_bad_zip():
    with pytest.raises(ReportLoadError):
        load_text_from_docx(b"not a zip file at all")


def test_load_text_from_pdf_uncompressed():
    pdf_bytes = build_minimal_pdf_uncompressed("Malware contacted evil.example.com")
    text, warnings = load_text_from_pdf(pdf_bytes)
    assert "evil.example.com" in text


def test_load_text_from_pdf_flate_compressed():
    pdf_bytes = build_minimal_pdf_flate_compressed("Compressed indicator 203.0.113.9")
    text, warnings = load_text_from_pdf(pdf_bytes)
    assert "203.0.113.9" in text


def test_load_text_from_pdf_rejects_non_pdf():
    with pytest.raises(ReportLoadError):
        load_text_from_pdf(b"not a pdf")


def test_detect_format():
    assert detect_format(b"%PDF-1.4", "x.pdf") == "pdf"
    assert detect_format(build_minimal_docx(["x"]), "x.docx") == "docx"
    assert detect_format(b"<html><body>x</body></html>") == "html"
    assert detect_format(b"just some plain text") == "text"


def test_extract_iocs_basic():
    text = "The C2 server at 203.0.113.5 used domain evil-example.com and hash " + "a" * 64
    iocs = extract_iocs(text)
    types = {i.ioc_type for i in iocs}
    assert "ip" in types and "domain" in types and "sha256" in types


def test_extract_iocs_defanged():
    text = "Beacon to 185[.]220[.]101[.]1 and evil[.]example[.]com via hxxp://bad-example.com/payload"
    iocs = extract_iocs(text)
    values = {i.value for i in iocs}
    assert "185.220.101.1" in values
    assert any("evil.example.com" in v for v in values)
    assert any(v.startswith("http://bad-example.com") for v in values)


def test_extract_iocs_cve_and_email():
    text = "Exploited via CVE-2024-12345, contact analyst@example.com for details"
    iocs = extract_iocs(text)
    cve = [i for i in iocs if i.ioc_type == "cve"]
    email = [i for i in iocs if i.ioc_type == "email"]
    assert cve and cve[0].value == "CVE-2024-12345"
    assert email and email[0].value == "analyst@example.com"


def test_extract_iocs_does_not_double_count_domain_inside_url():
    text = "Payload hosted at https://evil.example.com/drop.exe"
    iocs = extract_iocs(text)
    domain_matches = [i for i in iocs if i.ioc_type == "domain" and "evil.example.com" in i.value]
    assert domain_matches == []


def test_extract_iocs_hash_type_by_length():
    text = f"md5={'a'*32} sha1={'b'*40} sha256={'c'*64}"
    iocs = extract_iocs(text)
    kinds = {i.ioc_type for i in iocs}
    assert {"md5", "sha1", "sha256"} <= kinds


def test_match_techniques_explicit_id():
    matches = match_techniques("The actor used T1071.001 for C2 communication.")
    assert any(m.technique_id == "T1071.001" and m.match_basis == "explicit_id" for m in matches)


def test_match_techniques_name_mention():
    matches = match_techniques("The malware abused PowerShell to execute commands.")
    assert any(m.technique_id == "T1059.001" and m.match_basis == "name_mention" for m in matches)


def test_match_techniques_empty_text():
    assert match_techniques("nothing relevant here") == []


def test_is_safe_url_rejects_http():
    safe, reason = is_safe_url("http://example.com/report")
    assert not safe and "https" in reason


def test_is_safe_url_rejects_ip_literal():
    safe, reason = is_safe_url("https://203.0.113.5/report")
    assert not safe and "IP literal" in reason


def test_is_safe_url_rejects_private_resolved_address():
    def fake_resolver(hostname):
        return ["10.0.0.5"]
    safe, reason = is_safe_url("https://internal.example.com/report", resolver=fake_resolver)
    assert not safe and "private/reserved" in reason


def test_is_safe_url_rejects_loopback_resolved_address():
    def fake_resolver(hostname):
        return ["127.0.0.1"]
    safe, reason = is_safe_url("https://sneaky.example.com/report", resolver=fake_resolver)
    assert not safe


def test_is_safe_url_accepts_public_resolved_address():
    def fake_resolver(hostname):
        return ["8.8.8.8"]
    safe, reason = is_safe_url("https://cti-vendor.example.com/report", resolver=fake_resolver)
    assert safe


def test_is_safe_url_rejects_credentials_in_url():
    safe, reason = is_safe_url("https://user:pass@example.com/report")
    assert not safe and "credentials" in reason


def test_ingest_report_text_end_to_end():
    text = (
        "Threat Report: Operation Example\n"
        "The actor used T1071.001 for command and control, beaconing to "
        "203.0.113.5 and evil-example.com. A dropped payload had hash " + "a" * 64 + ". "
        "This activity is tracked under CVE-2024-99999."
    ).encode("utf-8")

    detection, warnings, metadata = ingest_report(data=text, filename="report.txt", title="Operation Example")

    assert detection.validate() == []
    assert detection.reviewed is False
    assert metadata.format == "text"
    fields = {c.field for c in detection.conditions.items}
    assert "network.dst_ip" in fields
    assert "dns.query" in fields
    assert "file.hash_sha256" in fields
    assert "T1071.001" in detection.mitre_techniques
    assert any("cve:CVE-2024-99999" in t for t in detection.tags)


def test_ingest_report_docx_end_to_end():
    docx_bytes = build_minimal_docx([
        "Threat Report", "Indicators observed: 203.0.113.9 and hxxp://bad-example.net/x",
    ])
    detection, warnings, metadata = ingest_report(data=docx_bytes, filename="report.docx")
    assert metadata.format == "docx"
    values = {c.value for c in detection.conditions.items}
    assert "203.0.113.9" in values
    assert any("bad-example.net" in v for v in values)


def test_ingest_report_requires_data_or_url():
    with pytest.raises(ValueError):
        ingest_report()


def test_ingest_report_into_kql_and_spl_backends():
    from backends.ms_kql import MsKqlBackend
    from backends.splunk_spl import SplunkSplBackend

    text = "C2 at 203.0.113.5 using T1071.001".encode()
    detection, _, _ = ingest_report(data=text, filename="r.txt")

    kql_results = MsKqlBackend().render(detection)
    spl_results = SplunkSplBackend().render(detection)
    assert all(r.validated for r in kql_results)
    assert all(r.validated for r in spl_results)
