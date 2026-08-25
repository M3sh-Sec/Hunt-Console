"""
explanation/tests/test_attck_bundle.py

Run with: pytest explanation/tests/ -v

Includes a synthetic (small, hand-built) STIX 2.1 bundle covering the cases
that matter: a parent technique, a sub-technique linked via a
subtechnique-of relationship, a revoked technique (must be filtered out),
and multiple kill-chain phases (must pick the first as primary tactic).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from explanation.attck_bundle import (  # noqa: E402
    load_attck_bundle_from_json, load_attck_bundle_from_file, AttckBundleLoadError,
)
from explanation import mitre_lookup  # noqa: E402


def _synthetic_bundle() -> dict:
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--parent-1",
                "name": "Application Layer Protocol",
                "description": "Adversaries communicate using OSI application layer protocols.\n\nMore detail follows that should not appear in the short description.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}],
                "x_mitre_is_subtechnique": False,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--sub-1",
                "name": "Web Protocols",
                "description": "Adversaries communicate using web protocols to blend in with normal traffic.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1071.001"}],
                "x_mitre_is_subtechnique": True,
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--sub-1",
                "target_ref": "attack-pattern--parent-1",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--revoked-1",
                "name": "Some Old Technique",
                "description": "This should never appear.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9001"}],
                "revoked": True,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deprecated-1",
                "name": "Some Deprecated Technique",
                "description": "This should also never appear.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9002"}],
                "x_mitre_deprecated": True,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--multiphase-1",
                "name": "Multi Phase Technique",
                "description": "Has two kill chain phases; the first should win as primary tactic.",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                ],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9003"}],
            },
        ],
    }


def test_load_bundle_extracts_parent_and_subtechnique():
    lookup, warnings = load_attck_bundle_from_json(_synthetic_bundle())
    assert "T1071" in lookup
    assert "T1071.001" in lookup
    assert lookup["T1071"].name == "Application Layer Protocol"
    assert lookup["T1071.001"].name == "Application Layer Protocol: Web Protocols"
    assert lookup["T1071.001"].tactic == "Command And Control"


def test_load_bundle_filters_revoked_and_deprecated():
    lookup, warnings = load_attck_bundle_from_json(_synthetic_bundle())
    assert "T9001" not in lookup
    assert "T9002" not in lookup


def test_load_bundle_picks_first_kill_chain_phase_as_primary_tactic():
    lookup, warnings = load_attck_bundle_from_json(_synthetic_bundle())
    assert lookup["T9003"].tactic == "Defense Evasion"


def test_load_bundle_truncates_long_description_to_first_paragraph():
    lookup, warnings = load_attck_bundle_from_json(_synthetic_bundle())
    desc = lookup["T1071"].short_description
    assert "More detail follows" not in desc
    assert desc.startswith("Adversaries communicate")


def test_load_bundle_rejects_non_bundle():
    with pytest.raises(AttckBundleLoadError):
        load_attck_bundle_from_json({"type": "not-a-bundle"})


def test_load_bundle_from_file(tmp_path):
    bundle_path = tmp_path / "test-bundle.json"
    bundle_path.write_text(json.dumps(_synthetic_bundle()))
    lookup, warnings = load_attck_bundle_from_file(bundle_path)
    assert "T1071.001" in lookup


def test_load_bundle_from_missing_file_raises(tmp_path):
    with pytest.raises(AttckBundleLoadError):
        load_attck_bundle_from_file(tmp_path / "does-not-exist.json")


def test_active_lookup_swap_and_reset(tmp_path):
    mitre_lookup.reset_to_builtin_fallback()
    assert mitre_lookup.lookup_technique("T1071") is None  # not in the small built-in subset

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_synthetic_bundle()))

    count, warnings = mitre_lookup.load_and_activate_bundle(bundle_path)
    assert count == 3, count
    assert mitre_lookup.lookup_technique("T1071").name == "Application Layer Protocol"
    assert "STIX bundle" in mitre_lookup.get_active_source_description()

    mitre_lookup.reset_to_builtin_fallback()
    assert mitre_lookup.lookup_technique("T1071") is None
    assert mitre_lookup.lookup_technique("T1071.001") is not None


def test_attck_matcher_sees_swapped_bundle_live(tmp_path):
    """
    Regression test for the stale-reference bug: report_parser.attck_matcher
    used to `from explanation.mitre_lookup import TECHNIQUE_LOOKUP` directly,
    which would NOT reflect a later load_and_activate_bundle() call. It now
    reads via get_active_technique_lookup() each call, so this must pass.
    """
    from report_parser.attck_matcher import match_techniques

    mitre_lookup.reset_to_builtin_fallback()
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_synthetic_bundle()))
    mitre_lookup.load_and_activate_bundle(bundle_path)

    try:
        matches = match_techniques("The actor used T9003 for defense evasion.")
        assert any(m.technique_id == "T9003" and m.technique_name == "Multi Phase Technique" for m in matches)
    finally:
        mitre_lookup.reset_to_builtin_fallback()
