"""
explanation/tests/test_generator.py

Run with: pytest explanation/tests/ -v
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
from backends.ms_kql import MsKqlBackend  # noqa: E402
from explanation.generator import build_explanation  # noqa: E402
from explanation.mitre_lookup import lookup_technique  # noqa: E402


def _detection():
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    return IRDetection(
        name="C2 beacon investigation",
        conditions=IRConditionGroup(logic=Logic.OR, items=[
            IRCondition(field="network.dst_ip", operator=Operator.EQUALS, value="203.0.113.55"),
        ]),
        time_window=TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1)),
        mitre_techniques=["T1071.001", "T9999.999"],  # second one is deliberately unknown
        tags=["severity:high"],
    )


def test_lookup_known_technique():
    info = lookup_technique("T1071.001")
    assert info is not None
    assert "Web Protocols" in info.name
    assert info.tactic == "Command and Control"


def test_lookup_unknown_technique_returns_none():
    assert lookup_technique("T0000.000") is None


def test_build_explanation_basic_fields():
    backend = MsKqlBackend()
    detection = _detection()
    rendered = backend.render(detection)[0]
    explanation = build_explanation(detection, rendered)

    assert explanation.platform == "ms_sentinel_defender"
    assert explanation.table_or_index == "DeviceNetworkEvents"
    assert "DeviceNetworkEvents" in explanation.summary
    assert explanation.expected_output  # non-empty
    assert explanation.data_source_requirements
    assert explanation.false_positive_guidance


def test_build_explanation_includes_known_and_unknown_mitre_context():
    backend = MsKqlBackend()
    detection = _detection()
    rendered = backend.render(detection)[0]
    explanation = build_explanation(detection, rendered)

    ids = {m.technique_id for m in explanation.mitre_context}
    assert "T1071.001" in ids
    assert "T9999.999" in ids

    known = next(m for m in explanation.mitre_context if m.technique_id == "T1071.001")
    unknown = next(m for m in explanation.mitre_context if m.technique_id == "T9999.999")
    assert known.tactic == "Command and Control"
    assert unknown.tactic == "unknown"
    assert "not found" in unknown.short_description


def test_severity_tag_drives_triage_hint():
    backend = MsKqlBackend()
    detection = _detection()  # tagged severity:high
    rendered = backend.render(detection)[0]
    explanation = build_explanation(detection, rendered)
    assert "prioritize" in explanation.severity_triage_hint.lower()


def test_to_dict_is_json_serializable():
    import json

    backend = MsKqlBackend()
    detection = _detection()
    rendered = backend.render(detection)[0]
    explanation = build_explanation(detection, rendered)
    serialized = json.dumps(explanation.to_dict())
    assert "T1071.001" in serialized


def test_to_markdown_renders_without_error():
    backend = MsKqlBackend()
    detection = _detection()
    rendered = backend.render(detection)[0]
    explanation = build_explanation(detection, rendered)
    md = explanation.to_markdown()
    assert "Summary" in md
    assert "DeviceNetworkEvents" in md
