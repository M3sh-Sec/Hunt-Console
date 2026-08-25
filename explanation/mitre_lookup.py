"""
explanation/mitre_lookup.py

Local ATT&CK technique reference used to populate MitreContext in generated
explanations without a live network call. Two data sources:

  1. A small BUILT-IN FALLBACK subset (a handful of common techniques),
     used automatically so the tool works out of the box with zero setup.
  2. A REAL local ATT&CK Enterprise STIX 2.1 bundle, loaded via
     load_and_activate_bundle() from explanation/attck_bundle.py — this is
     what production deployments should use. Download the bundle from
     https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)
     and refresh it periodically; never fetch it live on each request.

Callers should use lookup_technique() or get_active_technique_lookup()
rather than importing a dict by name directly — the active lookup can be
swapped at runtime via load_and_activate_bundle(), and code that captured
a direct reference to an old dict object would not see the swap.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TechniqueInfo:
    technique_id: str
    name: str
    tactic: str
    short_description: str


_BUILTIN_FALLBACK_LOOKUP: dict[str, TechniqueInfo] = {
    "T1071.001": TechniqueInfo(
        "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
        "Adversaries communicate using web protocols (HTTP/HTTPS) to blend C2 traffic with normal web traffic.",
    ),
    "T1059.001": TechniqueInfo(
        "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
        "Adversaries abuse PowerShell for execution, often to run malicious scripts or commands.",
    ),
    "T1105": TechniqueInfo(
        "T1105", "Ingress Tool Transfer", "Command and Control",
        "Adversaries transfer tools or files from an external system onto a compromised host.",
    ),
    "T1486": TechniqueInfo(
        "T1486", "Data Encrypted for Impact", "Impact",
        "Adversaries encrypt data on target systems to interrupt availability, typical of ransomware.",
    ),
    "T1027": TechniqueInfo(
        "T1027", "Obfuscated Files or Information", "Defense Evasion",
        "Adversaries obfuscate content to make it harder to discover or analyze.",
    ),
    "T1566.001": TechniqueInfo(
        "T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
        "Adversaries send emails with malicious attachments to gain initial access.",
    ),
}

# Module-level mutable state: the currently active lookup. Starts as the
# built-in fallback; load_and_activate_bundle() replaces the dict this
# points to. Callers must go through get_active_technique_lookup() or
# lookup_technique() (not `from .mitre_lookup import TECHNIQUE_LOOKUP`) to
# see updates after a swap, since a direct dict import captures a reference
# to whatever dict object was active at import time.
_active_lookup: dict[str, TechniqueInfo] = dict(_BUILTIN_FALLBACK_LOOKUP)
_active_source_description: str = "built-in fallback subset"


def get_active_technique_lookup() -> dict[str, TechniqueInfo]:
    """Returns the currently active lookup dict (live — reflects the most recent bundle load, if any)."""
    return _active_lookup


def get_active_source_description() -> str:
    return _active_source_description


def lookup_technique(technique_id: str) -> TechniqueInfo | None:
    """Returns TechniqueInfo for a known technique ID, or None if not in the currently active lookup."""
    return _active_lookup.get(technique_id.strip().upper())


def load_and_activate_bundle(path) -> tuple[int, list[str]]:
    """
    Loads a real ATT&CK STIX bundle from `path` and makes it the active
    lookup for all subsequent lookup_technique() / get_active_technique_lookup()
    calls. Returns (technique_count, warnings). On failure, the previously
    active lookup is left unchanged (the swap is all-or-nothing) and the
    underlying AttckBundleLoadError propagates.
    """
    from .attck_bundle import load_attck_bundle_from_file, AttckBundleLoadError

    new_lookup, warnings = load_attck_bundle_from_file(path)
    if not new_lookup:
        raise AttckBundleLoadError(
            f"bundle at {path} parsed successfully but contained zero usable techniques — refusing to activate"
        )

    global _active_lookup, _active_source_description
    _active_lookup = new_lookup
    _active_source_description = f"STIX bundle: {path}"
    return len(new_lookup), warnings


def reset_to_builtin_fallback() -> None:
    """Reverts the active lookup to the small built-in subset. Mainly useful for tests."""
    global _active_lookup, _active_source_description
    _active_lookup = dict(_BUILTIN_FALLBACK_LOOKUP)
    _active_source_description = "built-in fallback subset"
