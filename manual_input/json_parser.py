"""
manual_input/json_parser.py

Parses a JSON array of manually-entered IOCs:
  [{"type": "ip", "value": "1.2.3.4", "notes": "seen in report X"}, ...]

Structural problems (not a JSON array, not a list of objects) raise
ManualInputParseError. Individual malformed entries are skipped with a
warning, same policy as the CSV parser.
"""

from __future__ import annotations

import json

from .schema import MAX_INDICATORS_PER_BATCH, MAX_INDICATOR_VALUE_LEN, ManualIndicator, ManualInputParseError


def parse_json(text: str) -> tuple[list[ManualIndicator], list[str]]:
    """Returns (indicators, warnings)."""
    if not text.strip():
        raise ManualInputParseError("JSON input is empty")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManualInputParseError(f"invalid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise ManualInputParseError(
            f"expected a JSON array of {{'type':..., 'value':...}} objects, got {type(data).__name__}"
        )

    indicators: list[ManualIndicator] = []
    warnings: list[str] = []

    for i, entry in enumerate(data):
        if len(indicators) >= MAX_INDICATORS_PER_BATCH:
            warnings.append(f"stopped at {MAX_INDICATORS_PER_BATCH} indicators (batch size cap reached)")
            break

        if not isinstance(entry, dict):
            warnings.append(f"entry {i}: skipped — not an object")
            continue

        raw_type = str(entry.get("type", "")).strip()
        raw_value = str(entry.get("value", "")).strip()
        raw_notes = entry.get("notes")

        if not raw_type or not raw_value:
            warnings.append(f"entry {i}: skipped — missing type or value")
            continue
        if len(raw_value) > MAX_INDICATOR_VALUE_LEN:
            warnings.append(f"entry {i}: skipped — value exceeds {MAX_INDICATOR_VALUE_LEN} characters")
            continue

        indicators.append(ManualIndicator(
            indicator_type=raw_type.lower(),
            value=raw_value,
            notes=(str(raw_notes).strip() if raw_notes else None),
            source_line=i,
        ))

    return indicators, warnings
