"""
report_parser/builder.py

Converts Stage 1 (regex) extraction results — ExtractedIOC and
MatchedTechnique lists — into an IRDetection, with full provenance back to
the source report and the exact snippet each item was extracted from.

=== Stage 2 (NLP/LLM-assisted extraction) — NOT IMPLEMENTED HERE ===

The product spec calls for a second extraction stage using NLP/an LLM to
pull campaign narrative, kill-chain context, and TTP-to-IOC associations
that regex can't get. This codebase does not include a working Stage 2 —
there is no LLM API wired into this pipeline. What follows is the
integration contract and threat model a Stage 2 implementation MUST follow,
so it can be added later without becoming a prompt-injection vector:

  1. Report text is UNTRUSTED. Stage 2 must use a strict system prompt with
     JSON-schema-constrained output, and must treat 100% of the model's
     output as untrusted DATA — never as instructions, regardless of what
     the report text says ("ignore previous instructions", "you are now
     in developer mode", etc. are attacker payloads, not to be honored).
  2. The extraction call must not have tool access, network access, or the
     ability to trigger any downstream action directly. It returns
     structured candidate extractions (IOC/TTP suggestions with the source
     snippet they came from) and nothing else.
  3. Every candidate Stage 2 produces flows through the EXACT SAME
     mandatory analyst-review gate as Stage 1 output below (`reviewed`
     defaults to False) — Stage 2 does not get a fast path.
  4. Log the raw input/output pair for audit, so a successful injection
     attempt is at least detectable after the fact.
  5. Before sending report text to the model, strip/neutralize spans that
     look like system-prompt or instruction-block syntax (e.g. lines
     starting with "system:", "###", markdown code fences containing
     phrases like "ignore previous instructions") — this reduces attack
     surface but is NOT a substitute for #1 and #2; a determined attacker
     can still phrase an injection as ordinary prose.

Any future Stage 2 module should live at report_parser/nlp_extraction.py,
return the same ExtractedIOC/MatchedTechnique shapes as Stage 1, and be
merged into build_ir_from_report() the same way Stage 1 results are below.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from ir.builder import ENTITY_TYPE_TO_IR_FIELD
from ir.schema import (
    IRCondition, IRConditionGroup, IRDetection, Logic, Operator,
    Provenance, SourceType, TimeWindow,
)

from .attck_matcher import MatchedTechnique
from .ioc_extraction import ExtractedIOC

_IOC_TYPE_TO_ENTITY_TYPE = {
    "ip": "ip", "domain": "domain", "url": "url",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256", "email": "email",
}


def _report_fingerprint(source_id: str, content: bytes) -> str:
    basis = source_id.encode("utf-8") + hashlib.sha256(content).digest()
    return hashlib.sha256(basis).hexdigest()[:16]


def build_ir_from_report(
    iocs: list[ExtractedIOC],
    techniques: list[MatchedTechnique],
    *,
    report_title: str,
    report_source: str,
    report_bytes_for_fingerprint: bytes,
    report_publish_date: Optional[datetime] = None,
) -> IRDetection:
    condition_items: list[IRCondition | IRConditionGroup] = []
    cve_tags: list[str] = []
    unmapped_count = 0

    for ioc in iocs:
        if ioc.ioc_type == "cve":
            cve_tags.append(f"cve:{ioc.value}")
            continue

        entity_type = _IOC_TYPE_TO_ENTITY_TYPE.get(ioc.ioc_type)
        ir_field = ENTITY_TYPE_TO_IR_FIELD.get(entity_type) if entity_type else None
        if ir_field is None:
            ir_field = "generic.raw_indicator"
            unmapped_count += 1

        condition_items.append(IRCondition(
            field=ir_field,
            operator=Operator.EQUALS,
            value=ioc.value,
            notes=f"extracted from report '{report_title}': \"{ioc.source_snippet}\"",
            provenance=Provenance(
                source_type=SourceType.REPORT,
                source_id=_report_fingerprint(report_source, report_bytes_for_fingerprint),
                source_detail=ioc.source_snippet,
                confidence=ioc.confidence,
            ),
        ))

    if not condition_items:
        condition_items.append(IRCondition(
            field="generic.raw_indicator", operator=Operator.EXISTS, value=None,
            notes="no extractable IOCs found in this report",
        ))

    mitre_techniques = sorted({t.technique_id for t in techniques})

    now = datetime.now(timezone.utc)
    if report_publish_date:
        time_window = TimeWindow.around(report_publish_date, timedelta(days=7), timedelta(days=1))
    else:
        time_window = TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1))

    detection = IRDetection(
        name=f"Hunt from threat report: {report_title}",
        description=(
            f"Auto-extracted from report '{report_title}' ({report_source}): "
            f"{len(condition_items)} IOC condition(s)"
            + (f", {unmapped_count} unmapped to a known field" if unmapped_count else "")
            + f", {len(mitre_techniques)} ATT&CK technique(s) matched."
        ),
        conditions=IRConditionGroup(logic=Logic.OR, items=condition_items),
        time_window=time_window,
        mitre_techniques=mitre_techniques,
        provenance=Provenance(
            source_type=SourceType.REPORT,
            source_id=_report_fingerprint(report_source, report_bytes_for_fingerprint),
            source_detail=report_source,
            confidence=0.8,
        ),
        reviewed=False,   # report-derived indicators always require analyst review — no exceptions
        tags=["auto-generated", "source:report", f"report:{report_title}"] + cve_tags,
    )

    errors = detection.validate()
    if errors:
        detection.tags.append("has-validation-warnings")

    return detection
