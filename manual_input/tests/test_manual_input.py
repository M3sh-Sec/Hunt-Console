"""
manual_input/tests/test_manual_input.py

Run with: pytest manual_input/tests/ -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from manual_input.csv_parser import parse_csv  # noqa: E402
from manual_input.json_parser import parse_json  # noqa: E402
from manual_input.stix_parser import parse_stix_bundle  # noqa: E402
from manual_input.ttp_parser import parse_ttp_list  # noqa: E402
from manual_input.builder import build_ir_from_manual_input, ingest_manual_input  # noqa: E402
from manual_input.schema import ManualInputParseError, ManualIndicator  # noqa: E402


# --- CSV ---

def test_parse_csv_basic():
    csv_text = "type,value,notes\nip,203.0.113.5,seen in logs\ndomain,evil.example.com,\n"
    indicators, warnings = parse_csv(csv_text)
    assert len(indicators) == 2
    assert indicators[0].indicator_type == "ip"
    assert indicators[0].value == "203.0.113.5"
    assert indicators[0].notes == "seen in logs"
    assert warnings == []


def test_parse_csv_missing_required_header_raises():
    with pytest.raises(ManualInputParseError):
        parse_csv("foo,bar\n1,2\n")


def test_parse_csv_empty_raises():
    with pytest.raises(ManualInputParseError):
        parse_csv("")


def test_parse_csv_skips_bad_rows_with_warning():
    csv_text = "type,value\nip,\n,203.0.113.5\nip,203.0.113.9\n"
    indicators, warnings = parse_csv(csv_text)
    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.9"
    assert len(warnings) == 2


# --- JSON ---

def test_parse_json_basic():
    json_text = '[{"type": "sha256", "value": "' + "a" * 64 + '"}, {"type": "ip", "value": "1.2.3.4"}]'
    indicators, warnings = parse_json(json_text)
    assert len(indicators) == 2
    assert warnings == []


def test_parse_json_not_a_list_raises():
    with pytest.raises(ManualInputParseError):
        parse_json('{"type": "ip", "value": "1.2.3.4"}')


def test_parse_json_invalid_json_raises():
    with pytest.raises(ManualInputParseError):
        parse_json("not json at all {{{")


def test_parse_json_skips_bad_entries():
    json_text = '[{"type": "ip", "value": "1.2.3.4"}, "not an object", {"type": "", "value": "x"}]'
    indicators, warnings = parse_json(json_text)
    assert len(indicators) == 1
    assert len(warnings) == 2


# --- STIX ---

def _sample_bundle():
    return """
    {
      "type": "bundle",
      "id": "bundle--test",
      "objects": [
        {
          "type": "indicator",
          "id": "indicator--1",
          "pattern": "[ipv4-addr:value = '203.0.113.5']",
          "pattern_type": "stix"
        },
        {
          "type": "indicator",
          "id": "indicator--2",
          "pattern": "[domain-name:value = 'evil.example.com' AND file:hashes.'SHA-256' = '""" + "a" * 64 + """']",
          "pattern_type": "stix"
        },
        {
          "type": "indicator",
          "id": "indicator--3",
          "pattern": "[file:name MATCHES '^bad.*\\\\.exe$']",
          "pattern_type": "stix"
        }
      ]
    }
    """


def test_parse_stix_bundle_extracts_simple_indicator():
    indicators, warnings = parse_stix_bundle(_sample_bundle())
    ip_inds = [i for i in indicators if i.indicator_type == "ip"]
    assert len(ip_inds) == 1
    assert ip_inds[0].value == "203.0.113.5"


def test_parse_stix_bundle_extracts_and_joined_pattern_with_warning():
    indicators, warnings = parse_stix_bundle(_sample_bundle())
    domain_inds = [i for i in indicators if i.indicator_type == "domain"]
    sha256_inds = [i for i in indicators if i.indicator_type == "sha256"]
    assert len(domain_inds) == 1 and domain_inds[0].value == "evil.example.com"
    assert len(sha256_inds) == 1
    assert any("combines" in w and "AND" in w for w in warnings)


def test_parse_stix_bundle_flags_unsupported_operator():
    indicators, warnings = parse_stix_bundle(_sample_bundle())
    assert any("MATCHES" in w for w in warnings)


def test_parse_stix_bundle_rejects_non_bundle():
    with pytest.raises(ManualInputParseError):
        parse_stix_bundle('{"type": "indicator", "pattern": "[ipv4-addr:value = \'1.2.3.4\']"}')


# --- TTP ---

def test_parse_ttp_list_valid_ids():
    valid, warnings = parse_ttp_list(["T1071.001", "t1059"])
    assert valid == ["T1071.001", "T1059"]


def test_parse_ttp_list_rejects_malformed_id():
    valid, warnings = parse_ttp_list(["T1071.001", "not-a-technique", "T99"])
    assert valid == ["T1071.001"]
    assert len(warnings) == 2


def test_parse_ttp_list_flags_unknown_but_well_formed_id():
    valid, warnings = parse_ttp_list(["T9999.999"])  # well-formed, not in local lookup
    assert valid == ["T9999.999"]
    assert any("not found in the local ATT&CK reference" in w for w in warnings)


def test_parse_ttp_list_deduplicates():
    valid, _ = parse_ttp_list(["T1071.001", "T1071.001", "t1071.001"])
    assert valid == ["T1071.001"]


# --- Builder / IR integration ---

def test_build_ir_from_manual_input_basic():
    indicators = [
        ManualIndicator(indicator_type="ip", value="203.0.113.5"),
        ManualIndicator(indicator_type="sha256", value="a" * 64),
        ManualIndicator(indicator_type="something_unknown", value="mystery"),
    ]
    detection = build_ir_from_manual_input(indicators, name="Test hunt", ttps=["T1071.001"])
    assert detection.validate() == []
    assert detection.reviewed is False
    fields = {c.field for c in detection.conditions.items}
    assert fields == {"network.dst_ip", "file.hash_sha256", "generic.raw_indicator"}
    assert "T1071.001" in detection.mitre_techniques


def test_ingest_manual_input_csv_and_ttps_together():
    csv_text = "type,value\nip,203.0.113.5\ndomain,evil.example.com\n"
    detection, warnings = ingest_manual_input(
        name="Combined manual hunt", csv_text=csv_text, ttp_ids=["T1071.001", "bogus"],
    )
    assert detection.validate() == []
    fields = {c.field for c in detection.conditions.items}
    assert "network.dst_ip" in fields and "dns.query" in fields
    assert "T1071.001" in detection.mitre_techniques
    assert any("bogus" in w for w in warnings)


def test_ingest_manual_input_requires_at_least_one_source():
    with pytest.raises(ManualInputParseError):
        ingest_manual_input(name="Empty")


def test_ingest_manual_input_merges_csv_and_json():
    csv_text = "type,value\nip,203.0.113.5\n"
    json_text = '[{"type": "domain", "value": "evil.example.com"}]'
    detection, warnings = ingest_manual_input(name="Merged", csv_text=csv_text, json_text=json_text)
    fields = {c.field for c in detection.conditions.items}
    assert "network.dst_ip" in fields and "dns.query" in fields


def test_reviewed_flag_and_reviewer_only_set_together():
    unreviewed = build_ir_from_manual_input(
        [ManualIndicator(indicator_type="ip", value="1.2.3.4")], name="x", reviewed=False, analyst="alice",
    )
    reviewed = build_ir_from_manual_input(
        [ManualIndicator(indicator_type="ip", value="1.2.3.4")], name="x", reviewed=True, analyst="alice",
    )
    assert unreviewed.reviewed is False and unreviewed.reviewer is None
    assert reviewed.reviewed is True and reviewed.reviewer == "alice"


def test_end_to_end_manual_input_into_kql_backend():
    from backends.ms_kql import MsKqlBackend
    detection, _ = ingest_manual_input(
        name="Manual hunt", json_text='[{"type": "ip", "value": "203.0.113.5"}]', ttp_ids=["T1071.001"],
    )
    backend = MsKqlBackend()
    results = backend.render(detection)
    assert len(results) == 1
    assert results[0].validated is True
    assert "203.0.113.5" in results[0].query_text
