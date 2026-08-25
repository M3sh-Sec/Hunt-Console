"""
manual_input/builder.py

Converts parsed ManualIndicator objects (+ optional TTP list) into an
IRDetection, using the same generic field taxonomy and mapping table as
every other input source. Also provides `ingest_manual_input()`, the single
entry point that dispatches to the right format parser (CSV/JSON/STIX) and
builds IR in one call — this is what the CLI/GUI should call.
"""

from __future__ import annotations

import logging
from typing import Optional

from ir.builder import ENTITY_TYPE_TO_IR_FIELD
from ir.schema import (
    IRCondition, IRConditionGroup, IRDetection, Logic, Operator,
    Provenance, SourceType,
)

from .csv_parser import parse_csv
from .json_parser import parse_json
from .stix_parser import parse_stix_bundle
from .ttp_parser import parse_ttp_list
from .schema import ManualIndicator, ManualInputParseError

logger = logging.getLogger("manual_input.builder")

MANUAL_ENTRY_CONFIDENCE = 1.0  # an analyst explicitly typed this — treat as asserted, not inferred


def _map_indicator_field(indicator: ManualIndicator) -> tuple[str, bool]:
    key = indicator.indicator_type.strip().lower()
    ir_field = ENTITY_TYPE_TO_IR_FIELD.get(key)
    if ir_field is None:
        logger.info("no field mapping for manual indicator_type '%s' (value=%r) — using generic.raw_indicator",
                    indicator.indicator_type, indicator.value)
        return "generic.raw_indicator", False
    return ir_field, True


def build_ir_from_manual_input(
    indicators: list[ManualIndicator],
    *,
    name: str,
    description: str = "",
    ttps: Optional[list[str]] = None,
    reviewed: bool = False,
    analyst: Optional[str] = None,
) -> IRDetection:
    """
    reviewed=True should ONLY be set when a human has actually looked at
    this specific batch (e.g. the GUI's IR preview "accept all" action) —
    the default is False even though manual entry is high-confidence,
    because "typed by an analyst" and "reviewed in the IR preview screen"
    are two different gates and this tool should not conflate them.
    """
    condition_items: list[IRCondition | IRConditionGroup] = []
    unmapped_count = 0

    for ind in indicators:
        ir_field, mapped_cleanly = _map_indicator_field(ind)
        if not mapped_cleanly:
            unmapped_count += 1

        condition_items.append(IRCondition(
            field=ir_field,
            operator=Operator.EQUALS,
            value=ind.value,
            notes=ind.notes or f"manually entered, original type='{ind.indicator_type}'",
            provenance=Provenance(
                source_type=SourceType.MANUAL,
                source_id=f"manual-entry:{analyst or 'unspecified'}",
                source_detail=f"row/entry {ind.source_line}" if ind.source_line is not None else None,
                confidence=MANUAL_ENTRY_CONFIDENCE,
            ),
        ))

    if not condition_items:
        condition_items.append(IRCondition(
            field="generic.raw_indicator", operator=Operator.EXISTS, value=None,
            notes="no valid indicators were provided in this manual input batch",
        ))

    detection = IRDetection(
        name=name,
        description=description or (
            f"Manually entered: {len(indicators)} indicator(s)"
            + (f", {unmapped_count} unmapped to a known field" if unmapped_count else "") + "."
        ),
        conditions=IRConditionGroup(logic=Logic.OR, items=condition_items),
        mitre_techniques=list(ttps or []),
        provenance=Provenance(
            source_type=SourceType.MANUAL,
            source_id=f"manual-entry:{analyst or 'unspecified'}",
            confidence=MANUAL_ENTRY_CONFIDENCE,
        ),
        reviewed=reviewed,
        reviewer=analyst if reviewed else None,
        tags=["source:manual"],
    )

    errors = detection.validate()
    if errors:
        logger.warning("manually-built IRDetection %s has validation issues: %s", detection.id, errors)

    return detection


def ingest_manual_input(
    *,
    name: str,
    description: str = "",
    csv_text: Optional[str] = None,
    json_text: Optional[str] = None,
    stix_text: Optional[str] = None,
    ttp_ids: Optional[list[str]] = None,
    reviewed: bool = False,
    analyst: Optional[str] = None,
) -> tuple[IRDetection, list[str]]:
    """
    Single entry point for manual input: pass one or more of csv_text/
    json_text/stix_text (any combination — results are merged) and/or
    ttp_ids, get back (IRDetection, warnings). Raises ManualInputParseError
    if none of the inputs are provided, or if a provided input is
    structurally invalid.
    """
    if not any([csv_text, json_text, stix_text, ttp_ids]):
        raise ManualInputParseError(
            "no input provided — supply at least one of csv_text/json_text/stix_text/ttp_ids"
        )

    all_indicators: list[ManualIndicator] = []
    all_warnings: list[str] = []

    if csv_text:
        inds, warnings = parse_csv(csv_text)
        all_indicators.extend(inds)
        all_warnings.extend(warnings)
    if json_text:
        inds, warnings = parse_json(json_text)
        all_indicators.extend(inds)
        all_warnings.extend(warnings)
    if stix_text:
        inds, warnings = parse_stix_bundle(stix_text)
        all_indicators.extend(inds)
        all_warnings.extend(warnings)

    valid_ttps: list[str] = []
    if ttp_ids:
        valid_ttps, ttp_warnings = parse_ttp_list(ttp_ids)
        all_warnings.extend(ttp_warnings)

    detection = build_ir_from_manual_input(
        all_indicators, name=name, description=description, ttps=valid_ttps,
        reviewed=reviewed, analyst=analyst,
    )
    return detection, all_warnings
