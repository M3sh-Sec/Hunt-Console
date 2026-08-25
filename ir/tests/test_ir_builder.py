"""
ir/tests/test_ir_builder.py

Run with: pytest ir/tests/ -v
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from connectors.base import NormalizedAlert, NormalizedEntity  # noqa: E402
from ir import (  # noqa: E402
    build_ir_from_alert,
    build_ir_from_correlated_alerts,
    map_entity_field,
    Operator,
    Logic,
    FIELD_TAXONOMY,
)


def _sample_alert(platform: str = "sentinel") -> NormalizedAlert:
    return NormalizedAlert(
        source_platform=platform,
        source_alert_id="alert-001",
        title="Suspicious outbound connection",
        severity="high",
        created_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc),
        mitre_techniques=["T1071.001"],
        entities=[
            NormalizedEntity(entity_type="ip", value="203.0.113.55", raw_field_name="RemoteIP"),
            NormalizedEntity(entity_type="sha256", value="a" * 64, raw_field_name="FileHash"),
            NormalizedEntity(entity_type="totally_unknown_type", value="mystery-value",
                              raw_field_name="Custom"),
        ],
    )


def test_map_entity_field_known_type():
    ent = NormalizedEntity(entity_type="ip", value="1.2.3.4", raw_field_name="x")
    field_name, mapped = map_entity_field(ent)
    assert field_name == "network.dst_ip"
    assert mapped is True
    assert field_name in FIELD_TAXONOMY


def test_map_entity_field_unknown_type_falls_back_safely():
    ent = NormalizedEntity(entity_type="something_new", value="x", raw_field_name="y")
    field_name, mapped = map_entity_field(ent)
    assert field_name == "generic.raw_indicator"
    assert mapped is False


def test_build_ir_from_alert_produces_valid_detection():
    alert = _sample_alert()
    detection = build_ir_from_alert(alert)

    errors = detection.validate()
    assert errors == [], f"unexpected validation errors: {errors}"

    assert detection.conditions.logic == Logic.OR
    assert len(detection.conditions.items) == 3  # ip, hash, unmapped
    assert "T1071.001" in detection.mitre_techniques
    assert detection.reviewed is False  # must default to unreviewed
    assert detection.time_window is not None
    assert detection.time_window.start < alert.created_at < detection.time_window.end


def test_build_ir_from_alert_maps_known_entities_correctly():
    alert = _sample_alert()
    detection = build_ir_from_alert(alert)

    fields = {c.field for c in detection.conditions.items}
    assert "network.dst_ip" in fields
    assert "file.hash_sha256" in fields
    assert "generic.raw_indicator" in fields  # the unknown entity type


def test_build_ir_from_alert_with_no_entities_still_produces_valid_ir():
    alert = _sample_alert()
    alert.entities = []
    detection = build_ir_from_alert(alert)

    assert detection.validate() == []
    assert len(detection.conditions.items) == 1
    assert detection.conditions.items[0].operator == Operator.EXISTS


def test_auto_review_flag_respected():
    alert = _sample_alert()
    unreviewed = build_ir_from_alert(alert, auto_review=False)
    reviewed = build_ir_from_alert(alert, auto_review=True)
    assert unreviewed.reviewed is False
    assert reviewed.reviewed is True


def test_correlated_alerts_merge_entities_and_techniques():
    alert1 = _sample_alert(platform="sentinel")
    alert2 = _sample_alert(platform="crowdstrike_falcon")
    alert2.source_alert_id = "detect-002"
    alert2.mitre_techniques = ["T1059.001"]

    merged = build_ir_from_correlated_alerts([alert1, alert2])

    assert merged.validate() == []
    assert "T1071.001" in merged.mitre_techniques
    assert "T1059.001" in merged.mitre_techniques
    assert len(merged.conditions.items) == 6  # 3 entities x 2 alerts
    assert "source:sentinel" in merged.tags
    assert "source:crowdstrike_falcon" in merged.tags


def test_correlated_alerts_requires_at_least_one_alert():
    with pytest.raises(ValueError):
        build_ir_from_correlated_alerts([])


def test_to_dict_round_trip_is_json_serializable():
    import json

    alert = _sample_alert()
    detection = build_ir_from_alert(alert)
    d = detection.to_dict()

    # must not raise — this is what the GUI IR preview screen would send to the frontend
    serialized = json.dumps(d)
    assert "network.dst_ip" in serialized
    assert d["schema_version"] == "1.0"
    assert d["reviewed"] is False
