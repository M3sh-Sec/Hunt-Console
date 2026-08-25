"""
manual_input/ttp_parser.py

Validates and normalizes a list of manually-entered MITRE ATT&CK technique
IDs (e.g. "T1071.001"). Cross-checks against the local ATT&CK lookup
(explanation.mitre_lookup) so unknown/mistyped IDs are flagged rather than
silently passed through to the explanation generator later.
"""

from __future__ import annotations

import re

from explanation.mitre_lookup import lookup_technique

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def parse_ttp_list(raw: list[str]) -> tuple[list[str], list[str]]:
    """
    Returns (valid_technique_ids, warnings). Malformed IDs (wrong shape) are
    dropped with a warning. Well-formed IDs not found in the local ATT&CK
    lookup are still KEPT (the local lookup is a placeholder subset, not the
    full ATT&CK bundle — see explanation/mitre_lookup.py) but flagged.
    """
    valid: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for entry in raw:
        candidate = str(entry).strip().upper()
        if not candidate:
            continue
        if not _TECHNIQUE_ID_RE.match(candidate):
            warnings.append(f"'{entry}' does not look like a valid ATT&CK technique ID (expected e.g. T1071.001) "
                            f"— skipped")
            continue
        if candidate in seen:
            continue
        seen.add(candidate)

        if lookup_technique(candidate) is None:
            warnings.append(f"'{candidate}' is well-formed but not found in the local ATT&CK reference "
                            f"— kept, but verify against the full MITRE ATT&CK bundle")

        valid.append(candidate)

    return valid, warnings
