"""
backends/tests/test_splunk_spl.py

Run with: pytest backends/tests/ -v
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ir.schema import (  # noqa: E402
    IRCondition, IRConditionGroup, IRDetection, Logic, Operator, TimeWindow,
)
from backends.splunk_spl import SplunkSplBackend, _escape_like_wildcards  # noqa: E402


def _multi_index_detection() -> IRDetection:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    return IRDetection(
        name="Test multi-index detection",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="203.0.113.55"),
            IRCondition(field="file.hash_sha256", operator=Operator.EQUALS, value="a" * 64),
            IRCondition(field="generic.raw_indicator", operator=Operator.EQUALS, value="mystery"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
        mitre_techniques=["T1071.001"],
        tags=["severity:high"],
    )


def test_render_produces_one_query_per_referenced_index():
    backend = SplunkSplBackend()
    results = backend.render(_multi_index_detection())
    keys = {r.table_or_index for r in results}
    assert keys == {"network:stream:tcp", "endpoint:XmlWinEventLog:Sysmon"}
    assert len(results) == 2


def test_network_query_omits_file_condition_with_caveat():
    backend = SplunkSplBackend()
    results = {r.table_or_index: r for r in backend.render(_multi_index_detection())}
    net = results["network:stream:tcp"]
    assert "dest_ip" in net.query_text
    assert "file_hash_sha256" not in net.query_text
    assert any("file.hash_sha256" in c for c in net.caveats)


def test_time_range_present_as_earliest_latest():
    backend = SplunkSplBackend()
    for r in backend.render(_multi_index_detection()):
        assert 'earliest="08/20/2026:11:00:00"' in r.query_text
        assert 'latest="08/20/2026:13:00:00"' in r.query_text


def test_rendered_queries_pass_validation():
    backend = SplunkSplBackend()
    for r in backend.render(_multi_index_detection()):
        assert r.validated is True, r.validation_errors


def test_escape_like_wildcards():
    assert _escape_like_wildcards("50%_off") == "50\\%\\_off"
    assert _escape_like_wildcards(r"back\slash") == r"back\\slash"


def test_contains_operator_uses_like_with_escaped_wildcards():
    backend = SplunkSplBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="contains test",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="process.cmdline", operator=Operator.CONTAINS, value="powershell -enc"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    result = backend.render(detection)[0]
    assert 'like(process, "%powershell -enc%")' in result.query_text


def test_injected_value_cannot_break_out_of_eval_string_literal():
    backend = SplunkSplBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="Injection attempt",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS,
                        value='1.2.3.4" | delete | search dest_ip="'),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    result = backend.render(detection)[0]
    query_text = result.query_text
    where_clause = query_text.split("| where ")[1]
    # exactly our own opening/closing quote survive inside the where clause
    # (the many other quotes in the query belong to index/sourcetype/earliest/latest,
    # which are not attacker-controlled)
    assert where_clause.count('"') == 2
    assert "| delete" not in query_text
    assert result.validated is True


def test_all_unmapped_detection_returns_flagged_empty_result():
    backend = SplunkSplBackend()
    detection = IRDetection(
        name="Nothing mappable",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="generic.raw_indicator", operator=Operator.EQUALS, value="x"),
        ]),
    )
    results = backend.render(detection)
    assert len(results) == 1
    assert results[0].table_or_index == "(none)"
    assert results[0].caveats
