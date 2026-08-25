"""
connectors/base.py

Common interface that every SIEM/XDR/SOAR connector must implement.

DESIGN RULES (do not violate these when adding a new connector):
  1. READ-ONLY BY CONTRACT. This base class defines no method that can modify,
     remediate, contain, isolate, close, or delete anything on the source
     platform. Do not add one. If a future feature genuinely needs a write
     action, it must live in a separate, explicitly-named module (e.g.
     `connectors/actions/`) that is NOT imported by the investigation
     pipeline, and must go through its own review.
  2. Every concrete connector normalizes vendor-specific alert payloads into
     NormalizedAlert / NormalizedEntity before anything downstream (IR
     builder, query generator) ever sees the data.
  3. Every value pulled from a vendor payload is treated as untrusted. Do not
     assume it's safe just because it came from a security product's API.
  4. Every authenticate() / get_alerts() / run_query() call is audit-logged
     via `audit_log()` before returning to the caller.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("connectors.audit")


# --------------------------------------------------------------------------
# Normalized data model — every connector maps its native schema into these.
# --------------------------------------------------------------------------

@dataclass
class NormalizedEntity:
    """A single indicator/entity extracted from an alert (untrusted data)."""
    entity_type: str          # "ip" | "domain" | "url" | "file_hash" | "user" | "host" | "process" | ...
    value: str
    raw_field_name: str       # original vendor field name, for traceability
    confidence: float = 1.0   # 1.0 = platform-asserted, lower for inferred values


@dataclass
class NormalizedAlert:
    """Vendor-agnostic alert representation. This is what feeds the IR."""
    source_platform: str              # "sentinel" | "crowdstrike_falcon" | "splunk_es" | ...
    source_alert_id: str
    title: str
    severity: str                     # normalized to: informational|low|medium|high|critical
    created_at: datetime
    mitre_techniques: list[str] = field(default_factory=list)   # e.g. ["T1071.001"]
    entities: list[NormalizedEntity] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)           # original payload, for audit only
    portal_url: Optional[str] = None  # deep link back to the alert in its native console

    def fingerprint(self) -> str:
        """Stable identifier for correlation/dedup across platforms."""
        basis = f"{self.source_platform}:{self.source_alert_id}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


class ConnectorError(Exception):
    """Base exception for all connector failures."""


class ConnectorAuthError(ConnectorError):
    """Raised when authentication/token acquisition fails."""


class ConnectorRateLimitError(ConnectorError):
    """Raised when a platform's rate limit is hit and retries are exhausted."""


class ConnectorQueryScopeError(ConnectorError):
    """Raised when a requested query targets a table/index not on the connector's allow-list."""


# --------------------------------------------------------------------------
# Audit logging — every connector call goes through this, one schema for all
# --------------------------------------------------------------------------

def audit_log(*, platform: str, action: str, identity: str,
              detail: str = "", query: Optional[str] = None,
              status: str = "success") -> None:
    """
    Emit a structured audit record. Never log full raw payloads/PCAP-derived
    secrets here — only metadata needed for SOC accountability.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "action": action,          # "authenticate" | "get_alerts" | "run_query" | ...
        "identity": identity,      # service principal / app id / user, not a secret
        "status": status,
        "detail": detail,
    }
    if query is not None:
        record["query_hash"] = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
    logger.info(json.dumps(record))


def retry_with_backoff(fn, *, max_attempts: int = 5, base_delay: float = 1.0,
                        retry_on: tuple[type[Exception], ...] = (ConnectorRateLimitError,)):
    """
    Small shared retry helper. Each connector should wrap its own
    platform-specific rate-limit exception into ConnectorRateLimitError
    (or pass its own retry_on) so backoff behavior is consistent.
    """
    import random

    attempt = 0
    while True:
        try:
            return fn()
        except retry_on as exc:
            attempt += 1
            if attempt >= max_attempts:
                raise
            delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
            logger.warning("retrying after rate limit (attempt %d/%d) in %.1fs: %s",
                            attempt, max_attempts, delay, exc)
            time.sleep(delay)


# --------------------------------------------------------------------------
# Abstract connector interface
# --------------------------------------------------------------------------

class BaseConnector(abc.ABC):
    """
    Every platform connector (Sentinel, Defender, CrowdStrike, Splunk ES/SOAR,
    QRadar, Elastic, Chronicle, XSOAR, ...) implements this interface.

    NOTE: There is intentionally no isolate_host(), quarantine_file(),
    close_case(), suppress_alert(), or any other write/remediation method
    on this class, and none should ever be added.
    """

    platform_name: str = "base"

    @abc.abstractmethod
    def authenticate(self) -> None:
        """Acquire/refresh credentials. Must not persist secrets to disk."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_alerts(self, filters: dict[str, Any]) -> list[NormalizedAlert]:
        """Pull alerts matching filters (time range, severity, status, etc.)."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_alert_detail(self, alert_id: str) -> NormalizedAlert:
        """Fetch full detail for a single alert."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_alert_entities(self, alert_id: str) -> list[NormalizedEntity]:
        """Fetch/extract entities associated with a single alert."""
        raise NotImplementedError

    @abc.abstractmethod
    def run_query(self, query: str, dialect: str) -> dict[str, Any]:
        """
        Execute a READ-ONLY hunting query against this platform's own search
        API (e.g. Advanced Hunting, Log Analytics, Humio/LogScale search).
        Implementations must:
          - only ever call read/search endpoints, never action endpoints
          - validate the target table/index against an allow-list
          - audit_log() the call before returning
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a case/incident that groups one or more alerts, if the platform has that concept."""
        raise NotImplementedError
