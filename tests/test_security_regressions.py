"""
tests/test_security_regressions.py

One regression test per vulnerability fixed in v1.1.0 (see SECURITY.md).
Run with `pytest tests/` or standalone: `python tests/test_security_regressions.py`.
"""
from __future__ import annotations

import os
import sys
import zlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backends.ms_kql import MsKqlBackend  # noqa: E402
from backends.splunk_spl import SplunkSplBackend  # noqa: E402
from connectors.base import ConnectorQueryScopeError  # noqa: E402
from connectors.query_guard import (  # noqa: E402
    enforce_kql_scope, enforce_lql_scope, filter_techniques, validate_identifier)
from ir import IRCondition, IRConditionGroup, IRDetection, Logic, Operator  # noqa: E402

TABLES = {"DeviceProcessEvents", "SecurityAlert", "DeviceNetworkEvents"}


def _det(op, val, field="network.dst_port"):
    return IRDetection(name="t", conditions=IRConditionGroup(Logic.AND, [IRCondition(field, op, val)]),
                       reviewed=True, reviewer="test")


def _raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    return False


# --- VULN-01 Sentinel table allow-list bypass ------------------------------
def test_kql_guard_blocks_scope_escapes():
    for q in ["AuditLogs | take 5", "union AuditLogs, DeviceProcessEvents", "DeviceProcessEvents | union AuditLogs",
              "let x = AuditLogs; DeviceProcessEvents | take 1", "union *", ".show tables",
              "DeviceProcessEvents | join (AuditLogs) on X", "DeviceProcessEvents | evaluate bag_unpack(x)",
              "DeviceProcessEvents | where x == 1; AuditLogs", "DeviceProcessEvents | externaldata(a:string)[h@'http://x']"]:
        assert _raises(lambda q=q: enforce_kql_scope(q, TABLES), ConnectorQueryScopeError), q


def test_sentinel_connector_allowlist_function_itself():
    from connectors.sentinel import _enforce_table_allowlist
    for q in ["union AuditLogs, DeviceProcessEvents", "DeviceProcessEvents | union AuditLogs", "union *"]:
        assert _raises(lambda q=q: _enforce_table_allowlist(q), ConnectorQueryScopeError), q


def test_kql_guard_allows_generated_shape_and_ignores_words_in_strings():
    enforce_kql_scope('DeviceProcessEvents\n| where TimeGenerated > ago(1h)\n| where FileName == "union.exe"', TABLES)
    enforce_kql_scope("SecurityAlert | where TimeGenerated > ago(24h) | sort by TimeGenerated desc | take 50", TABLES)


def test_lql_guard():
    assert _raises(lambda: enforce_lql_scope('repo=other | join({x}, field=a)'), ConnectorQueryScopeError)
    enforce_lql_scope('#event_simpleName=ProcessRollup2 | ImageFileName=/cmd\\.exe/i')


# --- VULN-02 numeric-field injection (KQL + SPL) ---------------------------
def test_numeric_injection_rejected_everywhere():
    payloads = [(Operator.EQUALS, "443 or 1==1"), (Operator.GREATER_THAN, "0 | delete index=main"),
                (Operator.LESS_THAN, "1 | outputlookup x.csv"), (Operator.IN, ["1) or (1==1"]),
                (Operator.NOT_EQUALS, "1 union X")]
    for backend in (MsKqlBackend(), SplunkSplBackend()):
        for op, val in payloads:
            for q in backend.render(_det(op, val)):
                assert q.query_text == "" and not q.validated and q.caveats, (backend, op, val)


def test_numeric_values_still_render():
    for backend in (MsKqlBackend(), SplunkSplBackend()):
        out = backend.render(_det(Operator.IN, [80, "443"]))
        assert out and "80, 443" in out[0].query_text


# --- VULN-03 PDF FlateDecode bomb -------------------------------------------
def test_pdf_decompression_is_capped():
    import tracemalloc
    from report_parser import format_loaders as fl
    old = fl.MAX_PDF_STREAM_DECOMPRESSED
    fl.MAX_PDF_STREAM_DECOMPRESSED = 1024 * 1024
    try:
        bomb = zlib.compress(b"A" * (96 * 1024 * 1024), 9)
        pdf = (b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " + str(len(bomb)).encode()
               + b" >>\nstream\n" + bomb + b"\nendstream\nendobj\n")
        tracemalloc.start()
        _text, warnings = fl.load_text_from_pdf(pdf)
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert any("bomb" in w or "oversized" in w for w in warnings), warnings
        assert peak < 16 * 1024 * 1024, f"peak allocation {peak // 2**20} MiB: output was not capped while decompressing"
    finally:
        fl.MAX_PDF_STREAM_DECOMPRESSED = old


# --- VULN-04 identifier path traversal / injection --------------------------
def test_identifier_validation():
    for bad in ["../../x", "..", ".", 'a"b', "a/b", "a?b=1", "", "x" * 200, "a b", "a\nb"]:
        assert _raises(lambda b=bad: validate_identifier(b), ConnectorQueryScopeError), bad
    assert validate_identifier("da:ec2f1a-0001.x_y") == "da:ec2f1a-0001.x_y"


# --- VULN-05 Sentinel Tactics mapped into mitre_techniques ------------------
def test_only_wellformed_techniques_survive():
    assert filter_techniques(["T1059.001", "Execution", "t1071", "T1059.001", "T99", "<script>"]) == ["T1059.001", "T1071"]


# --- VULN-06 markdown injection in hunt package -----------------------------
def test_markdown_escape():
    import cli
    out = cli.md_escape("# H <img src=x onerror=1> [a](http://e) ```\n- i")
    import re
    assert "<" not in out and "```" not in out
    assert not re.search(r"(?<!\\)\]\(", out), "unescaped markdown link opener survived"
    assert not re.search(r"(?<!\\)\[", out)


# --- VULN-07 DNS rebinding: connect-time re-validation ----------------------
def test_fetcher_revalidates_at_connect_time():
    from report_parser import url_fetcher as uf
    calls = []

    def resolver(host):                       # public at check time, cloud-metadata IP at connect time
        calls.append(host)
        return ["8.8.8.8"] if len(calls) == 1 else ["169.254.169.254"]

    assert _raises(lambda: uf.fetch_report_url("https://example.test/r.html", resolver=resolver), uf.UnsafeUrlError)
    assert len(calls) >= 2, "hostname was not re-resolved at connect time"


# --- VULN-08 sandbox must not hang on a large result ------------------------
def test_sandbox_returns_large_result():
    import struct
    from parser.sandbox import parse_pcap_sandboxed
    eth_ip_tcp = bytes(12) + b"\x08\x00" + bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8]) \
        + struct.pack("!HHIIBBHHH", 40000, 443, 0, 0, 0x50, 2, 1024, 0, 0)
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt = struct.pack("<IIII", 1, 0, len(eth_ip_tcp), len(eth_ip_tcp)) + eth_ip_tcp
    res = parse_pcap_sandboxed(hdr + pkt * 20000, timeout_seconds=20)
    assert res.packets_processed == 20000


# --- VULN-09 KQL/LQL guard: string and comment handling must follow the real lexer ---
def test_kql_guard_verbatim_string_and_comment_bypass():
    tables = {"SigninLogs"}
    # `@"\\"` is a complete KQL verbatim string; the union after it is live code.
    bypasses = [
        'SigninLogs | where UserPrincipalName == @"\\" | union AuditLogs | where Category == "x"',
        "SigninLogs | where A == 1 // \"\n| union AuditLogs\n| where B == \"x\"",
        "SigninLogs | where A == 'x",            # unterminated string
        "SigninLogs | where A == ```x```",       # multi-line string literal
    ]
    for q in bypasses:
        assert _raises(lambda q=q: enforce_kql_scope(q, tables), ConnectorQueryScopeError), q
    # legitimate shapes still pass
    enforce_kql_scope('SigninLogs | where A == @"C:\\x" and B == "it\\"s" // note union', tables)


def test_lql_guard_comment_quote_bypass():
    q = '#type=x // "\n| join({#repo=other}, field=a)\n// "'
    assert _raises(lambda: enforce_lql_scope(q), ConnectorQueryScopeError)


# --- VULN-10 PDF: many small streams must not multiply the per-stream decompression cap ---
def test_pdf_total_decompression_budget():
    import report_parser.format_loaders as fl
    old = getattr(fl, "MAX_PDF_TOTAL_DECOMPRESSED", None)
    fl.MAX_PDF_TOTAL_DECOMPRESSED = 1024 * 1024        # shrink the budget so the test is fast
    try:
        payload = zlib.compress(b"(A) Tj\n" * (600 * 1024 // 7), 9)
        pdf = b"%PDF-1.4\n" + b"".join(
            b"1 0 obj\n<</Filter /FlateDecode>>\nstream\n" + payload + b"\nendstream\nendobj\n" for _ in range(20))
        text, warnings = fl.load_text_from_pdf(pdf)
    finally:
        if old is not None:
            fl.MAX_PDF_TOTAL_DECOMPRESSED = old
    assert len(text) < 3 * 1024 * 1024, "decompression budget was not enforced across streams"
    assert any("limit" in w or "bomb" in w for w in warnings)


# --- VULN-11 Markdown injection through the per-query explanation (summary / caveats) ---
def test_hunt_package_explanation_is_escaped(tmp_path=None):
    import re
    import tempfile
    from pathlib import Path
    import cli
    evil = "R <img src=x onerror=alert(1)> [c](http://e.example/x) ![i](http://e.example/p.png)\n# Injected heading"
    det = IRDetection(name=evil, description="d", conditions=IRConditionGroup(Logic.OR, [
        IRCondition("process.cmdline", Operator.CONTAINS, "abc"),
        IRCondition("host.name", Operator.EQUALS, "v")]))
    out = Path(tempfile.mkdtemp(prefix="hc_md_"))
    pkg = cli.write_outputs(det, cli.render_all(det, ["kql", "sigma"]), out).read_text()
    prose = re.sub(r"```.*?```", "", pkg, flags=re.S)          # query text sits in code fences
    assert "<img" not in prose and "<" not in prose.replace("&lt;", "")
    assert not re.search(r"(?m)^#+ Injected", prose)
    assert not re.search(r"(?<!\\)\]\(", prose) and not re.search(r"(?<!\\)!\[", prose)


# --- VULN-12 IOC regexes were quadratic (ReDoS) on dotted input --------------------------
def test_ioc_regexes_are_linear_on_dotted_input():
    import time
    from report_parser import ioc_extraction as ie
    for text in ("a." * 12000, "a@" + "b." * 12000, "1." * 12000):
        start = time.monotonic()
        ie.extract_iocs(text)
        assert time.monotonic() - start < 3, "IOC extraction is superlinear on dotted input"


# --- VULN-13 PDF stream scanning was quadratic on repeated `stream` keywords --------------
def test_pdf_stream_scan_is_linear():
    import time
    import report_parser.format_loaders as fl
    start = time.monotonic()
    fl.load_text_from_pdf(b"%PDF-1.4\n" + b"stream\n" * 20000)
    assert time.monotonic() - start < 3, "PDF stream scan is superlinear"
    # a normal stream is still found and decoded
    pdf = b"%PDF-1.4\n1 0 obj\n<</Filter /FlateDecode>>\nstream\n" + zlib.compress(b"(hello) Tj") + b"\nendstream\nendobj\n"
    assert "hello" in fl.load_text_from_pdf(pdf)[0]


# --- VULN-14 IOC extraction: URL-containment check was quadratic ---------------------------
def test_ioc_extraction_many_urls_is_linear():
    import time
    import report_parser.ioc_extraction as ie
    text = "http://a.com " * 16000      # old code: ~6.5 s, grows with the square of the input
    start = time.monotonic()
    found = ie.extract_iocs(text)
    assert time.monotonic() - start < 2, "URL-containment check is superlinear"
    assert sum(1 for i in found if i.ioc_type == "url") == 16000
    # a domain outside a URL is still found, one inside a URL is still skipped
    kinds = [(i.ioc_type, i.value) for i in ie.extract_iocs("see http://in.example.com/x and out.example.org end")]
    assert ("domain", "out.example.org") in kinds and ("domain", "in.example.com") not in kinds


# --- VULN-15 STIX comparison regex was quadratic ---------------------------------------------
def test_stix_comparison_regex_is_linear():
    import json
    import time
    from manual_input.stix_parser import parse_stix_bundle
    bundle = json.dumps({"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern": "a" * 40000}]})
    start = time.monotonic()
    parse_stix_bundle(bundle)          # old code: ~11 s
    assert time.monotonic() - start < 3, "STIX pattern parsing is superlinear"
    ok = json.dumps({"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--2", "pattern": "[ipv4-addr:value = '203.0.113.9']"}]})
    inds, _ = parse_stix_bundle(ok)
    assert [(i.indicator_type, i.value) for i in inds] == [("ip", "203.0.113.9")]


# --- VULN-16 SSRF filter missed shared address space (100.64/10), site-local and NAT64 -----
def test_url_fetcher_blocks_cgnat_sitelocal_nat64():
    from report_parser.url_fetcher import _is_private_or_reserved, is_safe_url
    for addr in ("100.64.0.1", "100.100.100.100", "100.127.255.254", "fec0::1", "64:ff9b::808:808",
                 "::ffff:10.0.0.1", "2002:a00:1::", "127.0.0.1", "169.254.169.254", "10.1.2.3"):
        assert _is_private_or_reserved(addr), addr
    for addr in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"):
        assert not _is_private_or_reserved(addr), addr
    ok, _ = is_safe_url("https://x.example.org/r.pdf", resolver=lambda h: ["100.100.100.100"])
    assert not ok
    ok, _ = is_safe_url("https://x.example.org/r.pdf", resolver=lambda h: ["93.184.216.34"])
    assert ok


# --- VULN-17 unhandled exceptions from untrusted CSV / KEV content -------------------------
def test_csv_oversized_field_is_a_parse_error():
    from manual_input.schema import ManualInputParseError
    from manual_input.csv_parser import parse_csv
    try:
        parse_csv("type,value\nip," + "1" * 200000 + "\n")
    except ManualInputParseError:
        pass
    else:
        raise AssertionError("expected ManualInputParseError")


def test_kev_blank_vendor_does_not_crash():
    import json
    from cve_hunt.builder import build_ir_from_cves
    from cve_hunt.kev import parse_kev_json_text
    kev = parse_kev_json_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2026-1111", "vendorProject": "  ", "product": "Widget"}]}))
    det = build_ir_from_cves(["CVE-2026-1111"], kev)      # old code: IndexError
    assert det.conditions.items


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print("PASS", name)
            except Exception as exc:  # noqa: BLE001
                failed += 1; print("FAIL", name, type(exc).__name__, exc)
    sys.exit(1 if failed else 0)
