"""
backends/tests/test_sigma.py

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
from backends.sigma import SigmaBackend  # noqa: E402

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def _multi_category_detection() -> IRDetection:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    return IRDetection(
        name="Test multi-category Sigma detection",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="203.0.113.55"),
            IRCondition(field="file.hash_sha256", operator=Operator.EQUALS, value="a" * 64),
            IRCondition(field="generic.raw_indicator", operator=Operator.EQUALS, value="mystery"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
        mitre_techniques=["T1071.001"],
        tags=["severity:high"],
    )


def test_render_produces_one_rule_per_referenced_category():
    backend = SigmaBackend()
    results = backend.render(_multi_category_detection())
    categories = {r.table_or_index for r in results}
    assert categories == {"network_connection", "file_event"}


def test_rendered_rules_are_valid_yaml_and_structurally_correct():
    if not HAVE_YAML:
        pytest.skip("PyYAML not available")
    backend = SigmaBackend()
    for r in backend.render(_multi_category_detection()):
        parsed = yaml.safe_load(r.query_text)
        assert parsed["logsource"]["category"] == r.table_or_index
        assert "condition" in parsed["detection"]
        assert "attack.t1071.001" in parsed["tags"]


def test_multi_value_or_within_same_field_uses_list():
    backend = SigmaBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="Multi-IP",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="1.1.1.1"),
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="2.2.2.2"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    assert len(results) == 1
    if HAVE_YAML:
        parsed = yaml.safe_load(results[0].query_text)
        selection = parsed["detection"]["selection1"]
        assert set(selection["DestinationIp"]) == {"1.1.1.1", "2.2.2.2"}
        assert parsed["detection"]["condition"] == "selection1"


def test_top_level_and_uses_all_of_selection():
    backend = SigmaBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="AND logic",
        conditions=IRConditionGroup(logic=Logic.AND, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="1.1.1.1"),
            IRCondition(field="network.dst_port", operator=Operator.EQUALS, value=443),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    assert len(results) == 1
    if HAVE_YAML:
        parsed = yaml.safe_load(results[0].query_text)
        assert parsed["detection"]["condition"] == "all of selection*"


def test_top_level_or_uses_1_of_selection():
    backend = SigmaBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="OR logic across fields",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="1.1.1.1"),
            IRCondition(field="network.dst_port", operator=Operator.EQUALS, value=443),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    if HAVE_YAML:
        parsed = yaml.safe_load(results[0].query_text)
        assert parsed["detection"]["condition"] == "1 of selection*"


def test_not_group_renders_not_condition():
    backend = SigmaBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="Exclude known-good",
        conditions=IRConditionGroup(logic=Logic.NOT, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="10.0.0.1"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    assert len(results) == 1
    if HAVE_YAML:
        parsed = yaml.safe_load(results[0].query_text)
        assert parsed["detection"]["condition"] == "not selection1"


def test_contains_operator_uses_pipe_modifier():
    backend = SigmaBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    detection = IRDetection(
        name="Contains test",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="process.cmdline", operator=Operator.CONTAINS, value="powershell -enc"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    results = backend.render(detection)
    assert "CommandLine|contains" in results[0].query_text


def test_injected_value_cannot_break_yaml_structure():
    if not HAVE_YAML:
        pytest.skip("PyYAML not available")
    backend = SigmaBackend()
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    evil_value = 'x"\ntags: ["pwned"]\ninjected_key: "value'
    detection = IRDetection(
        name="Injection attempt",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value=evil_value),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
    )
    result = backend.render(detection)[0]
    parsed = yaml.safe_load(result.query_text)
    assert set(parsed.keys()) == {
        "title", "id", "status", "description", "references", "tags",
        "logsource", "detection", "level", "falsepositives",
    }
    assert "injected_key" not in parsed
    assert parsed["tags"] == []


def test_all_unmapped_detection_returns_flagged_empty_result():
    backend = SigmaBackend()
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
