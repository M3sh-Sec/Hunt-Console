"""
ir/schema.py

The platform-agnostic Intermediate Representation (IR). Every input source —
PCAP parser, report parser, manual IOC/TTP entry, and every connector in
connectors/ — produces one or more IRDetection objects. Every query backend
(kql_builder, spl_builder, etc.) consumes IRDetection objects and never
touches a source-specific payload directly.

Design notes:
  - Conditions are a small logic tree (IRConditionGroup of IRCondition /
    nested IRConditionGroup) rather than a flat list, so "A AND (B OR C)"
    style logic survives the round trip to every backend, including Sigma.
  - `field` values use a GENERIC field taxonomy (see FIELD_TAXONOMY below),
    not any platform's native column name. Each backend's own field-mapping
    table (backends/<platform>/fields.py) translates generic -> native at
    render time. This is what lets one IR power KQL, SPL, EQL, etc. without
    N separate extraction pipelines.
  - Every IRDetection carries `provenance` so a generated query/explanation
    can always answer "where did this come from" (alert ID, report snippet,
    PCAP frame, analyst-entered).
  - schema_version is bumped on any breaking change to this shape, since
    IR objects may be persisted (e.g. in the GUI's IR preview / review step)
    and re-loaded later.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------
# Generic field taxonomy — the vocabulary every backend's field-mapping
# table translates FROM. Keep this flat and platform-neutral; do not name
# entries after any specific vendor's column (no "SrcIpAddr", no "src_ip").
# --------------------------------------------------------------------------

FIELD_TAXONOMY = {
    "network.src_ip", "network.dst_ip", "network.src_port", "network.dst_port",
    "network.protocol", "network.direction",
    "dns.query", "dns.response_ip",
    "http.url", "http.host", "http.user_agent", "http.method",
    "tls.sni", "tls.ja3", "tls.ja3s", "tls.cert_thumbprint",
    "file.hash_md5", "file.hash_sha1", "file.hash_sha256", "file.name", "file.path",
    "process.cmdline", "process.name", "process.parent_name", "process.pid",
    "identity.user", "identity.upn", "identity.sid",
    "host.name", "host.id", "host.ip",
    "email.sender", "email.recipient", "email.subject",
    "registry.key", "registry.value",
    "mutex.name",
    "url.full", "url.domain",
    "generic.raw_indicator",  # fallback bucket for entity types we can't yet map cleanly
}


class Operator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"                # value is a list
    NOT_IN = "not_in"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    EXISTS = "exists"


class Logic(str, Enum):
    AND = "and"
    OR = "or"
    NOT = "not"


class SourceType(str, Enum):
    ALERT = "alert"
    PCAP = "pcap"
    REPORT = "report"
    MANUAL = "manual"


@dataclass
class Provenance:
    """Traceability: where did this piece of IR come from, and how confident are we in it."""
    source_type: SourceType
    source_id: str                     # alert fingerprint, report hash, pcap filename, "manual-entry"
    source_platform: Optional[str] = None   # e.g. "sentinel", "crowdstrike_falcon", None for manual/report
    source_detail: Optional[str] = None     # e.g. source sentence for report-extracted items
    confidence: float = 1.0
    extracted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IRCondition:
    """A single leaf condition, e.g. network.dst_ip in [1.2.3.4, 5.6.7.8]."""
    field: str                         # must be a member of FIELD_TAXONOMY (validated on build)
    operator: Operator
    value: Any                         # str, number, or list depending on operator
    provenance: Optional[Provenance] = None
    notes: Optional[str] = None        # human-readable annotation, e.g. "IOC from CrowdStrike detection"

    def validate(self) -> list[str]:
        errors = []
        if self.field not in FIELD_TAXONOMY:
            errors.append(f"unknown IR field '{self.field}' — not in FIELD_TAXONOMY")
        if self.operator in (Operator.IN, Operator.NOT_IN) and not isinstance(self.value, (list, tuple, set)):
            errors.append(f"operator {self.operator} requires a list value, got {type(self.value)}")
        if self.value is None and self.operator != Operator.EXISTS:
            errors.append(f"condition on field '{self.field}' has no value")
        return errors


@dataclass
class IRConditionGroup:
    """A logic node: AND/OR/NOT over a mix of leaf conditions and nested groups."""
    logic: Logic
    items: list["IRCondition | IRConditionGroup"] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors = []
        if self.logic == Logic.NOT and len(self.items) != 1:
            errors.append("NOT group must have exactly one child item")
        if not self.items:
            errors.append("condition group has no items")
        for item in self.items:
            errors.extend(item.validate())
        return errors


@dataclass
class TimeWindow:
    start: datetime
    end: datetime

    @classmethod
    def around(cls, ts: datetime, before: timedelta, after: timedelta) -> "TimeWindow":
        return cls(start=ts - before, end=ts + after)


@dataclass
class IRDetection:
    """
    One complete, backend-agnostic detection/hunt definition. This is the
    unit that flows: parser/connector -> IR preview (GUI review) -> backend
    query generation -> explanation generation.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = SCHEMA_VERSION
    name: str = "Untitled detection"
    description: str = ""
    conditions: IRConditionGroup = field(default_factory=lambda: IRConditionGroup(logic=Logic.AND, items=[]))
    time_window: Optional[TimeWindow] = None
    mitre_techniques: list[str] = field(default_factory=list)
    provenance: Provenance = field(default_factory=lambda: Provenance(
        source_type=SourceType.MANUAL, source_id="unspecified"
    ))
    reviewed: bool = False           # GUI review gate — nothing flows to query gen unreviewed by default
    reviewer: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors = self.conditions.validate()
        if not self.name:
            errors.append("detection has no name")
        if self.schema_version != SCHEMA_VERSION:
            errors.append(f"schema_version mismatch: {self.schema_version} != {SCHEMA_VERSION}")
        return errors

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable representation for the GUI IR preview / storage."""
        def _cond(node):
            if isinstance(node, IRConditionGroup):
                return {"logic": node.logic.value, "items": [_cond(i) for i in node.items]}
            return {
                "field": node.field,
                "operator": node.operator.value,
                "value": list(node.value) if isinstance(node.value, (set, tuple)) else node.value,
                "notes": node.notes,
                "provenance": _prov(node.provenance) if node.provenance else None,
            }

        def _prov(p: Provenance):
            return {
                "source_type": p.source_type.value,
                "source_id": p.source_id,
                "source_platform": p.source_platform,
                "source_detail": p.source_detail,
                "confidence": p.confidence,
                "extracted_at": p.extracted_at.isoformat(),
            }

        return {
            "id": self.id,
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "conditions": _cond(self.conditions),
            "time_window": {
                "start": self.time_window.start.isoformat(),
                "end": self.time_window.end.isoformat(),
            } if self.time_window else None,
            "mitre_techniques": self.mitre_techniques,
            "provenance": _prov(self.provenance),
            "reviewed": self.reviewed,
            "reviewer": self.reviewer,
            "tags": self.tags,
        }
