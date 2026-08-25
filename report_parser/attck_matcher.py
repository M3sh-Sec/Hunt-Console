"""
report_parser/attck_matcher.py

Matches free-text report content against the local ATT&CK technique
reference (explanation/mitre_lookup.py) by technique name, rather than
trusting an LLM's technique-ID guess verbatim (per the product spec: "match
extracted TTP language against the local ATT&CK STIX bundle... rather than
trusting an LLM's technique ID guess verbatim"). Direct mentions of a
technique ID (e.g. "T1071.001") in the text are also picked up, at higher
confidence than a name-based match.

This is intentionally simple substring/keyword matching against the (small,
placeholder) local lookup — see explanation/mitre_lookup.py's docstring
about swapping in a full local ATT&CK STIX bundle for production use. The
matching strategy here (technique ID regex + case-insensitive technique
name substring) carries over unchanged once that bundle is swapped in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from explanation import mitre_lookup

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class MatchedTechnique:
    technique_id: str
    technique_name: str
    confidence: float
    match_basis: str          # "explicit_id" | "name_mention"
    source_snippet: str


def _snippet(text: str, start: int, end: int, radius: int = 60) -> str:
    s = max(0, start - radius)
    e = min(len(text), end + radius)
    return text[s:e].strip().replace("\n", " ")


def match_techniques(text: str) -> list[MatchedTechnique]:
    results: list[MatchedTechnique] = []
    seen_ids: set[str] = set()
    active_lookup = mitre_lookup.get_active_technique_lookup()

    for m in _TECHNIQUE_ID_RE.finditer(text):
        tid = m.group(0).upper()
        if tid in seen_ids:
            continue
        info = active_lookup.get(tid)
        name = info.name if info else "(technique ID not in local ATT&CK reference)"
        results.append(MatchedTechnique(
            technique_id=tid, technique_name=name, confidence=0.95,
            match_basis="explicit_id", source_snippet=_snippet(text, m.start(), m.end()),
        ))
        seen_ids.add(tid)

    lowered = text.lower()
    for tid, info in active_lookup.items():
        if tid in seen_ids:
            continue
        name_lower = info.name.split(":")[-1].strip().lower()
        if len(name_lower) < 6:
            continue
        idx = lowered.find(name_lower)
        if idx != -1:
            results.append(MatchedTechnique(
                technique_id=tid, technique_name=info.name, confidence=0.5,
                match_basis="name_mention", source_snippet=_snippet(text, idx, idx + len(name_lower)),
            ))
            seen_ids.add(tid)

    return results
