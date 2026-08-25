"""
ir/builder.py

Converts source-specific normalized objects into IRDetection. This module
currently implements the alert -> IR path (build_ir_from_alert), which
consumes NormalizedAlert objects from any connectors/*.py implementation —
the whole point of the connector layer's normalization is that this builder
never needs vendor-specific branching.

Other sources (PCAP parser, report parser, manual GUI entry) each get their
own `build_ir_from_*` function in this module, all converging on the same
IRDetection/IRConditionGroup shape, so the query-generation backends only
ever need to understand one format regardless of where a detection came from.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

from connectors.base import NormalizedAlert, NormalizedEntity

from .schema import (
    FIELD_TAXONOMY,
    IRCondition,
    IRConditionGroup,
    IRDetection,
    Logic,
    Operator,
    Provenance,
    SourceType,
    TimeWindow,
)

logger = logging.getLogger("ir.builder")

# Maps a connector's NormalizedEntity.entity_type (vendor/connector-side
# vocabulary, e.g. "ip", "sha256", "hostname") to the generic IR field
# taxonomy (backend-side vocabulary, e.g. "network.dst_ip"). Extend this as
# new connectors introduce new entity_type strings — every new mapping
# should have a corresponding entry in FIELD_TAXONOMY.
ENTITY_TYPE_TO_IR_FIELD: dict[str, str] = {
    "ip": "network.dst_ip",
    "ipv4": "network.dst_ip",
    "ipv6": "network.dst_ip",
    "domain": "dns.query",
    "domainname": "dns.query",
    "url": "url.full",
    "host": "host.name",
    "hostname": "host.name",
    "user": "identity.user",
    "account": "identity.user",
    "process_cmdline": "process.cmdline",
    "cmdline": "process.cmdline",
    "file_hash": "file.hash_sha256",   # default assumption; refine below if type-specific
    "file_hash_md5": "file.hash_md5",
    "file_hash_sha1": "file.hash_sha1",
    "file_hash_sha256": "file.hash_sha256",
    "md5": "file.hash_md5",
    "sha1": "file.hash_sha1",
    "sha256": "file.hash_sha256",
    "filename": "file.name",
    "filepath": "file.path",
    "sni": "tls.sni",
    "ja3": "tls.ja3",
    "email": "email.sender",
    "mutex": "mutex.name",
    "registrykey": "registry.key",
}

DEFAULT_ALERT_WINDOW_BEFORE = timedelta(hours=1)
DEFAULT_ALERT_WINDOW_AFTER = timedelta(hours=1)


def map_entity_field(entity: NormalizedEntity) -> tuple[str, bool]:
    """
    Returns (ir_field, was_mapped_cleanly). Unmapped entity types fall back
    to generic.raw_indicator rather than being silently dropped or guessed
    into the wrong field — the caller/GUI should surface was_mapped_cleanly
    False for analyst review.
    """
    key = entity.entity_type.strip().lower()
    ir_field = ENTITY_TYPE_TO_IR_FIELD.get(key)
    if ir_field is None:
        logger.info("no field mapping for entity_type '%s' (value=%r) — using generic.raw_indicator",
                    entity.entity_type, entity.value)
        return "generic.raw_indicator", False
    return ir_field, True


def build_ir_from_alert(
    alert: NormalizedAlert,
    *,
    window_before: timedelta = DEFAULT_ALERT_WINDOW_BEFORE,
    window_after: timedelta = DEFAULT_ALERT_WINDOW_AFTER,
    auto_review: bool = False,
) -> IRDetection:
    """
    Builds one IRDetection representing "find related activity around this
    alert." Each entity on the alert becomes an OR'd condition (any of these
    IOCs/entities appearing is worth investigating); if you want AND-joined
    multi-entity correlation instead, build that as a separate, more specific
    IRDetection downstream rather than changing this default.

    auto_review=True marks the resulting IRDetection as already reviewed —
    only set this for trusted automated pipelines (e.g. a scheduled poll
    against a high-confidence internal feed). GUI/manual flows should leave
    this False so the IR preview screen's review step is not bypassed.
    """
    condition_items: list[IRCondition | IRConditionGroup] = []
    unmapped_count = 0

    for entity in alert.entities:
        ir_field, mapped_cleanly = map_entity_field(entity)
        if not mapped_cleanly:
            unmapped_count += 1

        condition_items.append(IRCondition(
            field=ir_field,
            operator=Operator.EQUALS,
            value=entity.value,
            notes=f"from {alert.source_platform} alert {alert.source_alert_id}, "
                  f"original entity_type='{entity.entity_type}'",
            provenance=Provenance(
                source_type=SourceType.ALERT,
                source_id=alert.fingerprint(),
                source_platform=alert.source_platform,
                source_detail=f"entity field: {entity.raw_field_name}",
                confidence=entity.confidence,
            ),
        ))

    if not condition_items:
        # No entities extracted — still produce a valid IR object (e.g. a
        # title/technique-only hunt) rather than raising, so the GUI can show
        # "0 entities found, review manually" instead of a hard failure.
        condition_items.append(IRCondition(
            field="generic.raw_indicator",
            operator=Operator.EXISTS,
            value=None,
            notes="alert had no extractable entities; placeholder condition for analyst review",
        ))

    detection = IRDetection(
        name=f"Investigate: {alert.title}",
        description=(
            f"Auto-generated from {alert.source_platform} alert "
            f"'{alert.source_alert_id}' (severity={alert.severity}). "
            f"{len(alert.entities)} entities extracted"
            + (f", {unmapped_count} unmapped to generic.raw_indicator" if unmapped_count else "")
            + "."
        ),
        conditions=IRConditionGroup(logic=Logic.OR, items=condition_items),
        time_window=TimeWindow.around(alert.created_at, window_before, window_after),
        mitre_techniques=list(alert.mitre_techniques),
        provenance=Provenance(
            source_type=SourceType.ALERT,
            source_id=alert.fingerprint(),
            source_platform=alert.source_platform,
            source_detail=alert.portal_url,
            confidence=1.0,
        ),
        reviewed=auto_review,
        tags=["auto-generated", f"source:{alert.source_platform}", f"severity:{alert.severity}"],
    )

    errors = detection.validate()
    if errors:
        # Don't silently swallow validation problems — surface them so the
        # GUI/CLI caller can decide whether to block or flag for review.
        logger.warning("IRDetection %s built with validation issues: %s", detection.id, errors)

    return detection


def build_ir_from_correlated_alerts(alerts: list[NormalizedAlert], **kwargs) -> IRDetection:
    """
    Merges multiple alerts (typically ones sharing an entity across
    platforms, per the cross-platform correlation pass) into a single
    IRDetection with a union of entities/conditions and the union of
    their time windows, so a single investigation query covers all of them.
    """
    if not alerts:
        raise ValueError("no alerts provided for correlation")

    individual = [build_ir_from_alert(a, **kwargs) for a in alerts]

    merged_items: list[IRCondition | IRConditionGroup] = []
    for det in individual:
        merged_items.extend(det.conditions.items)

    starts = [d.time_window.start for d in individual if d.time_window]
    ends = [d.time_window.end for d in individual if d.time_window]

    merged = IRDetection(
        name=f"Correlated investigation across {len(alerts)} platform(s)",
        description="Merged from alerts sharing one or more entities: " +
                     ", ".join(f"{a.source_platform}:{a.source_alert_id}" for a in alerts),
        conditions=IRConditionGroup(logic=Logic.OR, items=merged_items),
        time_window=TimeWindow(start=min(starts), end=max(ends)) if starts and ends else None,
        mitre_techniques=sorted({t for d in individual for t in d.mitre_techniques}),
        provenance=Provenance(
            source_type=SourceType.ALERT,
            source_id="+".join(a.fingerprint() for a in alerts),
            source_platform="multiple",
            confidence=min((d.provenance.confidence for d in individual), default=1.0),
        ),
        tags=["auto-generated", "correlated", *{f"source:{a.source_platform}" for a in alerts}],
    )
    return merged
