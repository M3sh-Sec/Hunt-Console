"""
explanation/attck_bundle.py

Parses a locally-stored MITRE ATT&CK Enterprise STIX 2.1 bundle (download
from https://github.com/mitre-attack/attack-stix-data — e.g.
enterprise-attack.json — and refresh periodically; never fetched live on
each request) into the same TechniqueInfo shape used throughout this
codebase. This is the real data source the placeholder subset in
mitre_lookup.py was always meant to be swapped for.

Parsing notes:
  - Only `attack-pattern` objects are technique definitions in STIX ATT&CK.
    Revoked and deprecated techniques are skipped.
  - Sub-techniques (x_mitre_is_subtechnique=true) are linked to their
    parent via a `relationship` object with relationship_type=
    "subtechnique-of"; the resulting name is formatted as "Parent: Sub" to
    match the style already used throughout this codebase (e.g.
    "Application Layer Protocol: Web Protocols").
  - A technique can belong to multiple tactics (kill_chain_phases); the
    first listed phase is used as the primary tactic.
  - The bundle file is treated as untrusted-ish external input — size
    capped and parsing wrapped so a malformed/truncated bundle fails
    clearly rather than partially, silently corrupting the lookup.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mitre_lookup import TechniqueInfo

MAX_BUNDLE_FILE_LEN = 200 * 1024 * 1024  # 200 MiB


class AttckBundleLoadError(Exception):
    """Raised when a STIX bundle can't be safely or meaningfully loaded."""


def _extract_external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _extract_primary_tactic(obj: dict[str, Any]) -> str:
    phases = obj.get("kill_chain_phases", [])
    for phase in phases:
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name"):
            return phase["phase_name"].replace("-", " ").title()
    return "unknown"


def _short_description(description: str, max_len: int = 240) -> str:
    if not description:
        return ""
    first_para = description.strip().split("\n\n")[0].strip()
    if len(first_para) <= max_len:
        return first_para
    truncated = first_para[:max_len].rsplit(" ", 1)[0]
    return truncated + "…"


def load_attck_bundle_from_json(bundle: dict[str, Any]) -> tuple[dict[str, TechniqueInfo], list[str]]:
    """Returns (lookup, warnings). Individual malformed objects are skipped with a warning, not fatal."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise AttckBundleLoadError("input does not look like a STIX 2.x bundle (missing type='bundle')")

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise AttckBundleLoadError("bundle has no 'objects' array")

    warnings: list[str] = []

    attack_patterns: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_patterns[obj.get("id", "")] = obj

    subtechnique_parent: dict[str, str] = {}
    for obj in objects:
        if (
            isinstance(obj, dict)
            and obj.get("type") == "relationship"
            and obj.get("relationship_type") == "subtechnique-of"
        ):
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")
            if source_ref and target_ref:
                subtechnique_parent[source_ref] = target_ref

    lookup: dict[str, TechniqueInfo] = {}

    for stix_id, obj in attack_patterns.items():
        ext_id = _extract_external_id(obj)
        if not ext_id:
            warnings.append(f"attack-pattern {stix_id} has no mitre-attack external_id — skipped")
            continue

        name = obj.get("name", "")
        if not name:
            warnings.append(f"{ext_id}: no name field — skipped")
            continue

        if obj.get("x_mitre_is_subtechnique") and stix_id in subtechnique_parent:
            parent_obj = attack_patterns.get(subtechnique_parent[stix_id])
            full_name = f"{parent_obj['name']}: {name}" if parent_obj and parent_obj.get("name") else name
        else:
            full_name = name

        lookup[ext_id.upper()] = TechniqueInfo(
            technique_id=ext_id.upper(),
            name=full_name,
            tactic=_extract_primary_tactic(obj),
            short_description=_short_description(obj.get("description", "")),
        )

    return lookup, warnings


def load_attck_bundle_from_file(path) -> tuple[dict[str, TechniqueInfo], list[str]]:
    file_path = Path(path)
    if not file_path.exists():
        raise AttckBundleLoadError(f"bundle file not found: {file_path}")

    size = file_path.stat().st_size
    if size > MAX_BUNDLE_FILE_LEN:
        raise AttckBundleLoadError(f"bundle file exceeds max size ({MAX_BUNDLE_FILE_LEN} bytes): {size} bytes")

    try:
        with file_path.open("r", encoding="utf-8") as f:
            bundle = json.load(f)
    except json.JSONDecodeError as exc:
        raise AttckBundleLoadError(f"invalid JSON in bundle file: {exc}") from exc

    return load_attck_bundle_from_json(bundle)
