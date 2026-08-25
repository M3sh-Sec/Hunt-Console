"""
manual_input/csv_parser.py

Parses a CSV of manually-entered IOCs. Expected headers (case-insensitive):
  type, value, notes (notes optional)

Malformed individual ROWS are skipped with a warning rather than aborting
the whole batch — one typo'd row shouldn't block importing the other 500 —
but structural problems (missing required headers, empty file, oversized
batch) raise ManualInputParseError immediately.
"""

from __future__ import annotations

import csv
import io

from .schema import MAX_INDICATORS_PER_BATCH, MAX_INDICATOR_VALUE_LEN, ManualIndicator, ManualInputParseError

_REQUIRED_HEADERS = {"type", "value"}


def parse_csv(text: str) -> tuple[list[ManualIndicator], list[str]]:
    """Returns (indicators, warnings)."""
    if not text.strip():
        raise ManualInputParseError("CSV input is empty")

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ManualInputParseError("CSV has no header row")

    normalized_headers = {h.strip().lower() for h in reader.fieldnames}
    missing = _REQUIRED_HEADERS - normalized_headers
    if missing:
        raise ManualInputParseError(
            f"CSV missing required header(s): {sorted(missing)} (found: {sorted(normalized_headers)})"
        )

    header_map = {h.strip().lower(): h for h in reader.fieldnames}

    indicators: list[ManualIndicator] = []
    warnings: list[str] = []

    for line_num, row in enumerate(reader, start=2):  # header is line 1
        if len(indicators) >= MAX_INDICATORS_PER_BATCH:
            warnings.append(f"stopped at {MAX_INDICATORS_PER_BATCH} indicators (batch size cap reached)")
            break

        raw_type = (row.get(header_map["type"]) or "").strip()
        raw_value = (row.get(header_map["value"]) or "").strip()
        raw_notes = row.get(header_map.get("notes", ""), None)

        if not raw_type or not raw_value:
            warnings.append(f"row {line_num}: skipped — missing type or value")
            continue
        if len(raw_value) > MAX_INDICATOR_VALUE_LEN:
            warnings.append(f"row {line_num}: skipped — value exceeds {MAX_INDICATOR_VALUE_LEN} characters")
            continue

        indicators.append(ManualIndicator(
            indicator_type=raw_type.lower(),
            value=raw_value,
            notes=(raw_notes.strip() if raw_notes else None),
            source_line=line_num,
        ))

    return indicators, warnings
