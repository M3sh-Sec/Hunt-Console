"""
manual_input/stix_parser.py

Parses a STIX 2.x bundle and extracts indicators from `indicator` objects'
`pattern` field. STIX patterns are a full expression language; this parser
handles the common case — one or more atomic equality comparisons joined by
AND/OR — via a bounded regex extraction, not a full STIX pattern grammar
parser. Patterns using other operators (LIKE, MATCHES, ranges, timestamps,
nested observation expressions) are not extracted and are reported as a
warning rather than silently ignored or mis-parsed.

Each atomic comparison becomes its own ManualIndicator — AND/OR structure
in the original pattern is NOT preserved (all extracted indicators from a
bundle are treated as independent candidates for a broad "any of these"
hunt, consistent with how the alert and PCAP builders already work). If a
pattern requires multiple conditions to hold simultaneously to mean
anything (e.g. a specific file name AND a specific hash together), that
nuance is flagged in the returned warning so an analyst reviewing the IR
preview can catch it rather than the AND being silently dropped.
"""

from __future__ import annotations

import json
import re

from .schema import MAX_INDICATORS_PER_BATCH, MAX_INDICATOR_VALUE_LEN, ManualIndicator, ManualInputParseError

_STIX_PATH_TO_TYPE = {
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ip",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "file:name": "filename",
    "file:hashes.md5": "md5",
    "file:hashes.'md5'": "md5",
    "file:hashes.sha-1": "sha1",
    "file:hashes.'sha-1'": "sha1",
    "file:hashes.sha-256": "sha256",
    "file:hashes.'sha-256'": "sha256",
    "windows-registry-key:key": "registrykey",
    "mutex:name": "mutex",
}

_COMPARISON_RE = re.compile(r"([A-Za-z0-9:\-\.'_]+)\s*=\s*'([^']*)'")


def _map_stix_path(path: str):
    return _STIX_PATH_TO_TYPE.get(path.strip().lower())


def parse_stix_bundle(text: str) -> tuple[list[ManualIndicator], list[str]]:
    """Returns (indicators, warnings)."""
    if not text.strip():
        raise ManualInputParseError("STIX bundle input is empty")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManualInputParseError(f"invalid JSON in STIX bundle: {exc}") from exc

    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise ManualInputParseError("input does not look like a STIX 2.x bundle (missing type='bundle')")

    objects = data.get("objects")
    if not isinstance(objects, list):
        raise ManualInputParseError("STIX bundle has no 'objects' array")

    indicators: list[ManualIndicator] = []
    warnings: list[str] = []

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern")
        stix_id = obj.get("id", "unknown")
        if not pattern or not isinstance(pattern, str):
            continue

        upper_pattern = pattern.upper()
        if " LIKE " in upper_pattern or " MATCHES " in upper_pattern or "FOLLOWEDBY" in upper_pattern:
            warnings.append(f"{stix_id}: pattern uses an operator this parser doesn't extract "
                            f"(LIKE/MATCHES/FOLLOWEDBY) — review manually: {pattern[:200]}")
            continue

        matches = _COMPARISON_RE.findall(pattern)
        if not matches:
            warnings.append(f"{stix_id}: no extractable equality comparisons found in pattern: {pattern[:200]}")
            continue

        if len(matches) > 1 and " AND " in upper_pattern:
            warnings.append(
                f"{stix_id}: pattern combines {len(matches)} conditions with AND — each was extracted as an "
                f"independent indicator, but the original pattern may only be meaningful when ALL conditions "
                f"hold together. Review before treating these as separate standalone IOCs."
            )

        for path, value in matches:
            if len(indicators) >= MAX_INDICATORS_PER_BATCH:
                warnings.append(f"stopped at {MAX_INDICATORS_PER_BATCH} indicators (batch size cap reached)")
                break

            mapped_type = _map_stix_path(path)
            if mapped_type is None:
                warnings.append(f"{stix_id}: unmapped STIX object path '{path}' — indicator skipped")
                continue
            if len(value) > MAX_INDICATOR_VALUE_LEN:
                warnings.append(f"{stix_id}: value for '{path}' exceeds max length — skipped")
                continue

            indicators.append(ManualIndicator(
                indicator_type=mapped_type,
                value=value,
                notes=f"from STIX indicator {stix_id}",
            ))

    return indicators, warnings
