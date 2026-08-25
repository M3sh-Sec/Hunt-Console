"""
backends/tests/test_ms_kql.py

Run with: pytest backends/tests/ -v
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ir.schema import (  # noqa: E402
    IRCondition, IRConditionGroup, IRDetection, Logic, Operator, Provenance,
    SourceType, TimeWindow,
)
from backends.ms_kql import MsKqlBackend  # noqa: E402
from backends.base import sanitize_value  # noqa: E402


def _multi_table_detection() -> IRDetection:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    return IRDetection(
        name="Test multi-table detection",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="203.0.113.55"),
            IRCondition(field="file.hash_sha256", operator=Operator.EQUALS, value="a" * 64),
            IRCondition(field="generic.raw_indicator", operator=Operator.EQUALS, value="mystery"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
        mitre_techniques=["T1071.001"],
        provenance=Provenance(source_type=SourceType.MANUAL, source_id="test"),
        tags=["severity:high"],
    )


def test_render_produces_one_query_per_referenced_table():
    backend = MsKqlBackend()
    detection = _multi_table_detection()
    results = backend.render(detection)

    tables = {r.table_or_index for r in results}
    assert tables == {"DeviceNetworkEvents", "DeviceFileEvents"}
    assert len(results) == 2


def test_network_query_omits_file_hash_condition_with_caveat():
    backend = MsKqlBackend()
    detection = _multi_table_detection()
    results = {r.table_or_index: r for r in backend.render(detection)}

    net_query = results["DeviceNetworkEvents"]
    assert "RemoteIP" in net_query.query_text
    assert "SHA256" not in net_query.query_text
    assert any("file.hash_sha256" in c for c in net_query.caveats)
    assert any("generic.raw_indicator" in c for c in net_query.caveats)


def test_file_query_omits_network_condition_with_caveat():
    backend = MsKqlBackend()
    detection = _multi_table_detection()
    results = {r.table_or_index: r for r in backend.render(detection)}

    file_query = results["DeviceFileEvents"]
    assert "SHA256" in file_query.query_text
    assert "RemoteIP" not in file_query.query_text
    assert any("network.dst_ip" in c for c in file_query.caveats)


def test_time_window_included_in_rendered_query():
    backend = MsKqlBackend()
    detection = _multi_table_detection()
    results = backend.render(detection)
    for r in results:
        assert "TimeGenerated between" in r.query_text
        assert "2026-08-20T11:00:00Z" in r.query_text
        assert "2026-08-20T13:00:00Z" in r.query_text


def test_rendered_queries_pass_validation():
    backend = MsKqlBackend()
    detection = _multi_table_detection()
    for r in backend.render(detection):
        assert r.validated is True, r.validation_errors
        assert r.validation_errors == []


def test_sanitize_value_strips_injection_characters():
    malicious = 'evil"; DeviceNetworkEvents | union secrets | project *'
    cleaned = sanitize_value(malicious)
    assert '"' not in cleaned
    assert ";" not in cleaned
    assert "|" not in cleaned


def test_injected_ioc_value_cannot_break_out_of_query_string_literal():
    backend = MsKqlBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="Injection attempt",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS,
                        value='1.2.3.4" or 1==1 | union DeviceFileEvents | take 1000000 //'),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    assert len(results) == 1
    query_text = results[0].query_text
    # The security property: exactly our own opening/closing quote survive
    # (the attacker's embedded quote is stripped), and no pipe character
    # survives inside the where-clause to start a new query stage.
    assert query_text.count('"') == 2
    assert "| union" not in query_text
    assert "|" not in query_text.split("where (")[1]
    assert results[0].validated is True


def test_all_unmapped_detection_returns_flagged_empty_result():
    backend = MsKqlBackend()
    detection = IRDetection(
        name="Nothing mappable",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="generic.raw_indicator", operator=Operator.EQUALS, value="x"),
        ]),
    )
    results = backend.render(detection)
    assert len(results) == 1
    assert results[0].table_or_index == "(none)"
    assert results[0].query_text == ""
    assert results[0].caveats  # must explain why


def test_not_group_negates_correctly_when_single_table():
    backend = MsKqlBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="Exclude known-good IP",
        conditions=IRConditionGroup(logic=Logic.NOT, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="10.0.0.1"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    assert len(results) == 1
    assert "not (" in results[0].query_text
