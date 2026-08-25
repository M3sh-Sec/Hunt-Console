"""
connectors/crowdstrike_falcon.py

CrowdStrike Falcon connector.

Required API client scopes (CrowdStrike API Client, Falcon console > Support > API Clients).
Grant READ ONLY on the following — never grant the corresponding WRITE scopes:
  - Detections:            READ
  - Alerts:                READ
  - Hosts:                 READ            (needed only to resolve device_id -> hostname)
  - Event streams / Search: READ            (for run_query against LogScale/Humio)
Do NOT grant: Hosts:WRITE, Response Policies:WRITE, Real Time Response, or
Sample Uploads — this connector has no use for them and never calls them.

Auth: OAuth2 client-credentials against the CrowdStrike API. Base URL varies
by cloud (us-1, us-2, eu-1, us-gov-1) — set via CROWDSTRIKE_BASE_URL.

Env vars expected:
  CROWDSTRIKE_CLIENT_ID
  CROWDSTRIKE_CLIENT_SECRET
  CROWDSTRIKE_BASE_URL        e.g. https://api.crowdstrike.com
  CROWDSTRIKE_HUMIO_BASE_URL  e.g. https://api.us-2.crowdstrike.com  (Falcon Next-Gen SIEM / LogScale)
  CROWDSTRIKE_HUMIO_REPO      LogScale repository/view to search against

Note on run_query dialect: CrowdStrike's native hunting query language for
Falcon Next-Gen SIEM / Event Search is LogScale (Humio) Query Language,
referred to here as dialect="lql" (LogScale Query Language). This connector
does not accept arbitrary FQL filter strings as "queries" for run_query —
FQL is used only internally for the /detects filter parameter.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import (
    BaseConnector,
    NormalizedAlert,
    NormalizedEntity,
    ConnectorAuthError,
    ConnectorRateLimitError,
    ConnectorQueryScopeError,
    audit_log,
    retry_with_backoff,
)

# LogScale repositories/views this connector may search — defense in depth,
# independent of what the query builder generates.
ALLOWED_REPOS = {"detections", "xdr", "falcon-events"}

_SEVERITY_MAP = {
    1: "informational", 2: "low", 3: "low", 4: "medium",
    5: "medium", 6: "high", 7: "high", 8: "critical", 9: "critical", 10: "critical",
}


class CrowdStrikeFalconConnector(BaseConnector):
    platform_name = "crowdstrike_falcon"

    def __init__(self) -> None:
        self._token: str | None = None
        self._token_expiry: datetime | None = None
        self._client_id = os.environ["CROWDSTRIKE_CLIENT_ID"]
        self._client_secret = os.environ["CROWDSTRIKE_CLIENT_SECRET"]
        self._base_url = os.environ["CROWDSTRIKE_BASE_URL"].rstrip("/")
        self._humio_base_url = os.environ.get("CROWDSTRIKE_HUMIO_BASE_URL", self._base_url).rstrip("/")
        self._humio_repo = os.environ.get("CROWDSTRIKE_HUMIO_REPO", "detections")

    # ------------------------------------------------------------------
    def authenticate(self) -> None:
        if self._token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return

        import requests

        def _do_call():
            resp = requests.post(
                f"{self._base_url}/oauth2/token",
                data={"client_id": self._client_id, "client_secret": self._client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            if resp.status_code == 429:
                raise ConnectorRateLimitError("CrowdStrike OAuth2 token endpoint rate limited")
            resp.raise_for_status()
            return resp.json()

        try:
            data = retry_with_backoff(_do_call)
        except Exception as exc:
            audit_log(platform=self.platform_name, action="authenticate",
                      identity=self._client_id, status="failure", detail=str(exc))
            raise ConnectorAuthError(str(exc)) from exc

        self._token = data["access_token"]
        self._token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=int(data.get("expires_in", 1800)) - 30
        )
        audit_log(platform=self.platform_name, action="authenticate",
                  identity=self._client_id, status="success")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    # ------------------------------------------------------------------
    def get_alerts(self, filters: dict[str, Any]) -> list[NormalizedAlert]:
        """
        Pulls Falcon detections (read-only). `filters` may include:
        lookback_hours (int), min_severity (int 1-10), limit (int).
        """
        self.authenticate()
        import requests

        lookback = int(filters.get("lookback_hours", 24))
        limit = int(filters.get("limit", 50))
        since = (datetime.now(timezone.utc) - timedelta(hours=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # FQL filter — values here come from our own config/filters dict, not
        # from alert content, so injection risk is low, but we still avoid
        # naive string concatenation of anything user-supplied beyond ints/dates.
        fql = f"first_behavior:>'{since}'"

        def _do_call():
            resp = requests.get(
                f"{self._base_url}/detects/queries/detects/v1",
                headers=self._headers(),
                params={"filter": fql, "limit": limit, "sort": "first_behavior.desc"},
                timeout=30,
            )
            if resp.status_code == 429:
                raise ConnectorRateLimitError("CrowdStrike detects query API rate limited")
            resp.raise_for_status()
            return resp.json()

        try:
            id_resp = retry_with_backoff(_do_call)
        except Exception as exc:
            audit_log(platform=self.platform_name, action="get_alerts",
                      identity=self._client_id, status="failure", detail=str(exc))
            raise

        detect_ids = id_resp.get("resources", [])
        if not detect_ids:
            audit_log(platform=self.platform_name, action="get_alerts",
                      identity=self._client_id, status="success", detail="0 results")
            return []

        details = self._get_detect_details(detect_ids)
        audit_log(platform=self.platform_name, action="get_alerts",
                  identity=self._client_id, status="success",
                  detail=f"{len(details)} results")
        return [self._detection_to_alert(d) for d in details]

    def _get_detect_details(self, detect_ids: list[str]) -> list[dict[str, Any]]:
        import requests

        def _do_call():
            resp = requests.post(
                f"{self._base_url}/detects/entities/summaries/GET/v1",
                headers={**self._headers(), "Content-Type": "application/json"},
                json={"ids": detect_ids},
                timeout=30,
            )
            if resp.status_code == 429:
                raise ConnectorRateLimitError("CrowdStrike detect summaries API rate limited")
            resp.raise_for_status()
            return resp.json()

        data = retry_with_backoff(_do_call)
        return data.get("resources", [])

    def get_alert_detail(self, alert_id: str) -> NormalizedAlert:
        self.authenticate()
        details = self._get_detect_details([alert_id])
        if not details:
            raise ConnectorQueryScopeError(f"detection {alert_id} not found")
        return self._detection_to_alert(details[0])

    def get_alert_entities(self, alert_id: str) -> list[NormalizedEntity]:
        return self.get_alert_detail(alert_id).entities

    # ------------------------------------------------------------------
    def run_query(self, query: str, dialect: str = "lql") -> dict[str, Any]:
        """
        Executes a READ-ONLY LogScale (Humio) query against Falcon Next-Gen
        SIEM / Event Search. This calls only the search endpoint — never a
        response-action or host-containment endpoint.
        """
        if dialect not in ("lql", "humio", "logscale"):
            raise ConnectorQueryScopeError(
                f"crowdstrike_falcon connector expects an LQL/LogScale query, got dialect={dialect}"
            )
        if self._humio_repo not in ALLOWED_REPOS:
            raise ConnectorQueryScopeError(
                f"repo '{self._humio_repo}' not in allow-list {ALLOWED_REPOS}"
            )

        self.authenticate()
        import requests

        url = f"{self._humio_base_url}/humio/api/v1/repositories/{self._humio_repo}/query"
        body = {
            "queryString": query,
            "start": "24hours",
            "end": "now",
        }

        def _do_call():
            resp = requests.post(url, headers={**self._headers(), "Content-Type": "application/json"},
                                  json=body, timeout=60)
            if resp.status_code == 429:
                raise ConnectorRateLimitError("CrowdStrike LogScale search API rate limited")
            resp.raise_for_status()
            return resp.json()

        try:
            data = retry_with_backoff(_do_call)
        except Exception as exc:
            audit_log(platform=self.platform_name, action="run_query",
                      identity=self._client_id, query=query, status="failure", detail=str(exc))
            raise

        audit_log(platform=self.platform_name, action="run_query",
                  identity=self._client_id, query=query, status="success")

        events = data.get("events", data if isinstance(data, list) else [])
        return {"columns": list(events[0].keys()) if events else [], "rows": events}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetches a Falcon Incident (groups related detections) — read-only GET."""
        self.authenticate()
        import requests

        def _do_call():
            resp = requests.post(
                f"{self._base_url}/incidents/entities/incidents/GET/v1",
                headers={**self._headers(), "Content-Type": "application/json"},
                json={"ids": [incident_id]},
                timeout=30,
            )
            if resp.status_code == 429:
                raise ConnectorRateLimitError("CrowdStrike incidents API rate limited")
            resp.raise_for_status()
            return resp.json()

        data = retry_with_backoff(_do_call)
        audit_log(platform=self.platform_name, action="get_incident",
                  identity=self._client_id, detail=incident_id, status="success")
        resources = data.get("resources", [])
        return resources[0] if resources else {}

    # ------------------------------------------------------------------
    def _detection_to_alert(self, d: dict[str, Any]) -> NormalizedAlert:
        entities: list[NormalizedEntity] = []
        for b in d.get("behaviors", []):
            if b.get("ioc_value"):
                entities.append(NormalizedEntity(
                    entity_type=str(b.get("ioc_type", "unknown")).lower(),
                    value=str(b["ioc_value"]),
                    raw_field_name="behaviors[].ioc_value",
                ))
            if b.get("md5"):
                entities.append(NormalizedEntity(entity_type="file_hash_md5",
                                                   value=b["md5"], raw_field_name="behaviors[].md5"))
            if b.get("sha256"):
                entities.append(NormalizedEntity(entity_type="file_hash_sha256",
                                                   value=b["sha256"], raw_field_name="behaviors[].sha256"))
            if b.get("cmdline"):
                entities.append(NormalizedEntity(entity_type="process_cmdline",
                                                   value=b["cmdline"], raw_field_name="behaviors[].cmdline",
                                                   confidence=0.8))

        device = d.get("device", {})
        if device.get("hostname"):
            entities.append(NormalizedEntity(entity_type="host", value=device["hostname"],
                                               raw_field_name="device.hostname"))

        techniques = sorted({
            b["technique_id"] for b in d.get("behaviors", []) if b.get("technique_id")
        })

        max_severity = max((b.get("severity", 0) for b in d.get("behaviors", [])), default=0)

        return NormalizedAlert(
            source_platform=self.platform_name,
            source_alert_id=str(d.get("detection_id", "")),
            title=d.get("behaviors", [{}])[0].get("display_name", "CrowdStrike Detection"),
            severity=_SEVERITY_MAP.get(max_severity, "medium"),
            created_at=_parse_ts(d.get("first_behavior")),
            mitre_techniques=list(techniques),
            entities=entities,
            raw=d,
            portal_url=d.get("detection_id") and
                       f"https://falcon.crowdstrike.com/activity-v2/detections/{d['detection_id']}",
        )


def _parse_ts(value: Any) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
