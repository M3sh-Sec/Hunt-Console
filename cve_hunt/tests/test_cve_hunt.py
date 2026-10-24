from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest  # noqa: E402

from backends.ms_kql import MsKqlBackend  # noqa: E402
from cve_hunt import build_ir_from_cves, load_kev_json, parse_cve_ids  # noqa: E402

_KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-25645", "vendorProject": "Python", "product": "requests", "vulnerabilityName": "n",
     "dateAdded": "2026-10-20", "shortDescription": "s", "requiredAction": "a", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "not-a-cve", "vendorProject": "x", "product": "y"},
]}


def test_cve_id_validation():
    assert parse_cve_ids(["cve-2026-25645", "CVE-2026-25645", "CVE-2026-1234567890"]) == ["CVE-2026-25645", "CVE-2026-1234567890"]
    for bad in ["CVE-2026-1", 'CVE-2026-1234") or 1==1', "CVE-26-12345", "", "x"]:
        with pytest.raises(ValueError):
            parse_cve_ids([bad])
    with pytest.raises(ValueError):
        parse_cve_ids([])
    with pytest.raises(ValueError):
        parse_cve_ids([f"CVE-2026-{i:05d}" for i in range(501)])


def test_kev_loader_ignores_malformed_entries_and_rejects_wrong_files(tmp_path):
    good = tmp_path / "kev.json"; good.write_text(json.dumps(_KEV))
    kev = load_kev_json(good)
    assert list(kev) == ["CVE-2026-25645"]
    bad = tmp_path / "bad.json"; bad.write_text(json.dumps({"x": 1}))
    with pytest.raises(ValueError):
        load_kev_json(bad)


def test_exposure_query_renders_and_validates(tmp_path):
    f = tmp_path / "kev.json"; f.write_text(json.dumps(_KEV))
    det = build_ir_from_cves(["CVE-2026-25645", "CVE-2026-59890"], load_kev_json(f))
    assert det.validate() == [] and det.reviewed is False
    assert "kev:CVE-2026-25645" in det.tags and "kev-ransomware:CVE-2026-25645" in det.tags
    out = {q.table_or_index: q for q in MsKqlBackend().render(det)}
    q = out["DeviceTvmSoftwareVulnerabilities"]
    assert q.validated and 'CveId in ("CVE-2026-25645", "CVE-2026-59890")' in q.query_text
    assert "TimeGenerated" not in q.query_text            # snapshot table has no such column
    assert "CVE-2026-59890" in det.description and "not listed" in det.description


def test_report_with_cves_produces_exposure_condition():
    from report_parser.ingest import ingest_report
    text = b"Actors exploited CVE-2026-25645 and CVE-2026-59890 against exposed hosts, beaconing to 8.8.4.4."
    det, _w, _m = ingest_report(data=text, filename="r.txt", title="t")
    fields = {c.field for c in det.conditions.items if hasattr(c, "field")}
    assert "vuln.cve_id" in fields
    tables = {q.table_or_index for q in MsKqlBackend().render(det)}
    assert "DeviceTvmSoftwareVulnerabilities" in tables


def test_long_cve_ids_are_extracted():
    from report_parser.ioc_extraction import extract_iocs
    got = [i.value for i in extract_iocs("see CVE-2026-1234567 and CVE-2026-12345678") if i.ioc_type == "cve"]
    assert got == ["CVE-2026-1234567", "CVE-2026-12345678"]
