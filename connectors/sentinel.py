"""
connectors/sentinel.py

Microsoft Sentinel connector.

Required Azure AD app registration permissions (least privilege — do not grant more):
  - Log Analytics:  "Log Analytics Reader" role on the workspace (data-plane read only)
  - Sentinel:       "Microsoft Sentinel Reader" role on the resource group/workspace
                     (NOT "Sentinel Responder" or "Sentinel Contributor" — those grant
                     write/remediation and must never be used by this codebase)
  - Graph/API scope: none needed beyond the above for pure read/hunt use

Auth: client-credentials flow via MSAL against Azure AD. Secrets are read from
environment variables only; never hardcode, never write to disk.

Env vars expected:
  AZURE_TENANT_ID
  AZURE_CLIENT_ID
  AZURE_CLIENT_SECRET        (prefer a certificate + AZURE_CLIENT_CERT_PATH in production)
  SENTINEL_WORKSPACE_ID      (Log Analytics workspace GUID, for run_query)
  SENTINEL_SUBSCRIPTION_ID
  SENTINEL_RESOURCE_GROUP
  SENTINEL_WORKSPACE_NAME
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

# Tables this connector is permitted to query via run_query(), independent of
# what the query builder generates upstream — defense in depth.
ALLOWED_TABLES = {
    "DeviceNetworkEvents", "DeviceProcessEvents", "DeviceFileEvents",
    "DeviceLogonEvents", "DeviceRegistryEvents", "SigninLogs",
    "AADNonInteractiveUserSignInLogs", "CommonSecurityLog",
    "SecurityAlert", "SecurityIncident", "OfficeActivity",
}

_SEVERITY_MAP = {
    "Informational": "informational",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}


class SentinelConnector(BaseConnector):
    platform_name = "sentinel"

    def __init__(self) -> None:
        self._token: str | None = None
        self._token_expiry: datetime | None = None
        self._tenant_id = os.environ["AZURE_TENANT_ID"]
        self._client_id = os.environ["AZURE_CLIENT_ID"]
        self._client_secret = os.environ["AZURE_CLIENT_SECRET"]
        self._workspace_id = os.environ["SENTINEL_WORKSPACE_ID"]
        self._subscription_id = os.environ["SENTINEL_SUBSCRIPTION_ID"]
        self._resource_group = os.environ["SENTINEL_RESOURCE_GROUP"]
        self._workspace_name = os.environ["SENTINEL_WORKSPACE_NAME"]

    # ------------------------------------------------------------------
    def authenticate(self) -> None:
        import msal

        if self._token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return  # cached token still valid, in-memory only

        app = msal.ConfidentialClientApplication(
            client_id=self._client_id,
            client_credential=self._client_secret,
            authority=f"https://login.microsoftonline.com/{self._tenant_id}",
        )
        result = app.acquire_token_for_client(
            scopes=["https://api.loganalytics.io/.default"]
        )
        if "access_token" not in result:
            audit_log(platform=self.platform_name, action="authenticate",
                      identity=self._client_id, status="failure",
                      detail=result.get("error_description", "unknown error"))
            raise ConnectorAuthError(result.get("error_description", "MSAL auth failed"))

        self._token = result["access_token"]
        # refresh a little early
        self._token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=result.get("expires_in", 3600) - 60
        )
        audit_log(platform=self.platform_name, action="authenticate",
                  identity=self._client_id, status="success")

    # ------------------------------------------------------------------
    def get_alerts(self, filters: dict[str, Any]) -> list[NormalizedAlert]:
        """
        Pulls SecurityAlert rows via Log Analytics (read-only). `filters` may
        include: lookback_hours (int), min_severity (str), limit (int).
        """
        self.authenticate()
        lookback = int(filters.get("lookback_hours", 24))
        limit = int(filters.get("limit", 50))

        kql = f"""
        SecurityAlert
        | where TimeGenerated > ago({lookback}h)
        | sort by TimeGenerated desc
        | take {limit}
        """
        result = self.run_query(kql, dialect="kql")
        alerts = [self._row_to_alert(row) for row in result.get("rows", [])]
        return alerts

    def get_alert_detail(self, alert_id: str) -> NormalizedAlert:
        self.authenticate()
        # SystemAlertId is not attacker-controlled input here, but we still
        # never string-format untrusted values directly — use a parameterized
        # KQL literal escape for defense in depth.
        safe_id = _escape_kql_string(alert_id)
        kql = f"""
        SecurityAlert
        | where SystemAlertId == "{safe_id}"
        | take 1
        """
        result = self.run_query(kql, dialect="kql")
        rows = result.get("rows", [])
        if not rows:
            raise ConnectorQueryScopeError(f"alert {alert_id} not found")
        return self._row_to_alert(rows[0])

    def get_alert_entities(self, alert_id: str) -> list[NormalizedEntity]:
        alert = self.get_alert_detail(alert_id)
        return alert.entities

    # ------------------------------------------------------------------
    def run_query(self, query: str, dialect: str = "kql") -> dict[str, Any]:
        """
        Executes a READ-ONLY KQL query against the Log Analytics data-plane
        query API. This never calls a management-plane write endpoint.
        """
        if dialect != "kql":
            raise ConnectorQueryScopeError(f"sentinel connector only supports kql, got {dialect}")

        _enforce_table_allowlist(query)

        self.authenticate()

        import requests

        url = f"https://api.loganalytics.io/v1/workspaces/{self._workspace_id}/query"
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

        def _do_call():
            resp = requests.post(url, headers=headers, json={"query": query}, timeout=30)
            if resp.status_code == 429:
                raise ConnectorRateLimitError("Log Analytics API rate limited (429)")
            resp.raise_for_status()
            return resp.json()

        try:
            data = retry_with_backoff(_do_call)
        except Exception as exc:
            audit_log(platform=self.platform_name, action="run_query",
                      identity=self._client_id, query=query, status="failure",
                      detail=str(exc))
            raise

        audit_log(platform=self.platform_name, action="run_query",
                  identity=self._client_id, query=query, status="success")

        table = data.get("tables", [{}])[0]
        columns = [c["name"] for c in table.get("columns", [])]
        rows = [dict(zip(columns, r)) for r in table.get("rows", [])]
        return {"columns": columns, "rows": rows}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """
        Fetches a Sentinel Incident via the Azure management-plane REST API
        (read-only GET — never PATCH/PUT/DELETE from this method).
        """
        self.authenticate()
        import requests

        url = (
            f"https://management.azure.com/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{self._resource_group}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self._workspace_name}/providers/Microsoft.SecurityInsights"
            f"/incidents/{incident_id}?api-version=2023-11-01"
        )
        headers = {"Authorization": f"Bearer {self._token}"}

        def _do_call():
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 429:
                raise ConnectorRateLimitError("Sentinel incidents API rate limited (429)")
            resp.raise_for_status()
            return resp.json()

        data = retry_with_backoff(_do_call)
        audit_log(platform=self.platform_name, action="get_incident",
                  identity=self._client_id, detail=incident_id, status="success")
        return data

    # ------------------------------------------------------------------
    def _row_to_alert(self, row: dict[str, Any]) -> NormalizedAlert:
        import json as _json

        entities_raw = row.get("Entities", "[]")
        try:
            entities_parsed = _json.loads(entities_raw) if isinstance(entities_raw, str) else entities_raw
        except (ValueError, TypeError):
            entities_parsed = []

        entities: list[NormalizedEntity] = []
        for ent in entities_parsed or []:
            ent_type = str(ent.get("Type", "unknown")).lower()
            value = ent.get("Address") or ent.get("DomainName") or ent.get("Name") or ent.get("FileHash") or ""
            if value:
                entities.append(NormalizedEntity(entity_type=ent_type, value=str(value),
                                                   raw_field_name="Entities"))

        techniques_raw = row.get("Tactics", "") or ""
        techniques = [t.strip() for t in str(techniques_raw).split(",") if t.strip()]

        return NormalizedAlert(
            source_platform=self.platform_name,
            source_alert_id=str(row.get("SystemAlertId", "")),
            title=str(row.get("AlertName", "unknown")),
            severity=_SEVERITY_MAP.get(row.get("AlertSeverity"), "medium"),
            created_at=_parse_ts(row.get("TimeGenerated")),
            mitre_techniques=techniques,
            entities=entities,
            raw=row,
            portal_url=None,
        )


# --------------------------------------------------------------------
def _escape_kql_string(value: str) -> str:
    """Minimal allow-list escaping for values interpolated into KQL string literals."""
    return value.replace('"', "").replace("\\", "").replace("\n", "")


def _enforce_table_allowlist(query: str) -> None:
    """
    Defense-in-depth check: confirm the query only references tables this
    connector is configured to allow, independent of upstream query-builder
    trust. Not a substitute for proper KQL parsing, but blocks obvious
    out-of-scope table access (e.g. a generated query accidentally or
    maliciously targeting an unexpected table).
    """
    referenced = {tok.strip() for tok in query.replace("\n", " ").split("|")[0].split() if tok[:1].isupper()}
    if referenced and not referenced & ALLOWED_TABLES:
        raise ConnectorQueryScopeError(
            f"query does not reference an allow-listed table: {ALLOWED_TABLES}"
        )


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
