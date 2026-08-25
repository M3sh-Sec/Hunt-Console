"""
explanation/generator.py

Builds a QueryExplanation for a single RenderedQuery, templated directly
from the IRDetection and the rendered query's own metadata (table, caveats,
validation status). This intentionally does NOT call an LLM to describe the
query after the fact — every field here is derived from data the backend
already computed, so the explanation can never drift from what the query
actually does.
"""

from __future__ import annotations

from backends.base import RenderedQuery
from ir.schema import IRDetection

from .mitre_lookup import lookup_technique
from .schema import MitreContext, QueryExplanation

# Per-table/index knowledge used to fill in expected-output / data-source /
# false-positive guidance, keyed by platform so each backend can carry its
# own entries without colliding on table/index name collisions across
# platforms (e.g. Splunk's "network:stream:tcp" vs KQL's "DeviceNetworkEvents").
_MS_KQL_KNOWLEDGE: dict[str, dict[str, object]] = {
    "DeviceNetworkEvents": {
        "expected_output": (
            "Each row is one network connection event. A match means a monitored "
            "device made or received a connection matching the specified indicator(s)."
        ),
        "data_source_requirements": [
            "Requires Microsoft Defender for Endpoint with device network event "
            "collection enabled on the target devices.",
        ],
        "false_positive_guidance": [
            "Shared/CDN-hosted IPs or domains can trigger matches unrelated to the "
            "intended threat — check RemoteUrl context, not just RemoteIP, before escalating.",
            "Internal scanning tools or vulnerability scanners may generate connections "
            "that superficially resemble reconnaissance traffic.",
        ],
    },
    "DeviceFileEvents": {
        "expected_output": (
            "Each row is one file-system event (create/modify/rename). A match means "
            "a file with a matching hash or name was observed on a monitored device."
        ),
        "data_source_requirements": [
            "Requires Microsoft Defender for Endpoint with file event collection enabled.",
        ],
        "false_positive_guidance": [
            "Generic or commonly-reused filenames (e.g. 'update.exe') can produce "
            "unrelated matches — hash-based conditions are more reliable than filename-based ones.",
        ],
    },
    "DeviceProcessEvents": {
        "expected_output": (
            "Each row is one process-creation event. A match means a monitored device "
            "launched a process matching the specified command-line or name pattern."
        ),
        "data_source_requirements": [
            "Requires Microsoft Defender for Endpoint with process event collection enabled.",
        ],
        "false_positive_guidance": [
            "Command-line fragments can appear in legitimate admin/automation scripts — "
            "review the full command line and parent process before treating as malicious.",
        ],
    },
    "SigninLogs": {
        "expected_output": (
            "Each row is one Azure AD sign-in event. A match means a sign-in occurred "
            "involving the specified user/identity."
        ),
        "data_source_requirements": [
            "Requires Azure AD sign-in logs ingested into the Sentinel workspace "
            "(diagnostic setting on the Azure AD tenant).",
        ],
        "false_positive_guidance": [
            "Legitimate travel, VPN use, or shared corporate devices can produce sign-ins "
            "that look anomalous by location/device alone.",
        ],
    },
    "DeviceLogonEvents": {
        "expected_output": (
            "Each row is one device logon event. A match means the specified account "
            "logged onto a monitored device."
        ),
        "data_source_requirements": [
            "Requires Microsoft Defender for Endpoint with logon event collection enabled.",
        ],
        "false_positive_guidance": [
            "Service accounts and scheduled tasks can produce frequent legitimate logons "
            "that match broad account-based conditions.",
        ],
    },
    "DeviceRegistryEvents": {
        "expected_output": (
            "Each row is one registry modification event. A match means the specified "
            "registry key/value was created, modified, or deleted on a monitored device."
        ),
        "data_source_requirements": [
            "Requires Microsoft Defender for Endpoint with registry event collection enabled "
            "(not enabled by default for all key paths — verify coverage).",
        ],
        "false_positive_guidance": [
            "Many legitimate applications and Windows components modify common registry "
            "run-keys during normal operation.",
        ],
    },
}

_SPLUNK_SPL_KNOWLEDGE: dict[str, dict[str, object]] = {
    "network:stream:tcp": {
        "expected_output": (
            "Each row is one TCP connection record captured by Splunk Stream. A match "
            "means a monitored host made or received a connection matching the indicator(s)."
        ),
        "data_source_requirements": [
            "Requires the Splunk Stream app/forwarder deployed and the network index onboarded; "
            "field names assume default Stream CIM-style extraction — verify against your environment.",
        ],
        "false_positive_guidance": [
            "Shared/CDN-hosted IPs can trigger matches unrelated to the intended threat.",
            "Internal vulnerability scanners can produce connections that resemble scanning/recon.",
        ],
    },
    "network:stream:dns": {
        "expected_output": "Each row is one DNS query/response record. A match means a monitored "
                            "host queried or received a response involving the specified domain/IP.",
        "data_source_requirements": ["Requires Splunk Stream DNS capture onboarded."],
        "false_positive_guidance": [
            "Domain generation algorithm false-positives aside, legitimate CDNs and cloud "
            "services can share infrastructure with malicious domains.",
        ],
    },
    "network:stream:http": {
        "expected_output": "Each row is one HTTP transaction record. A match means a monitored "
                            "host made an HTTP request matching the specified URL/host/user-agent.",
        "data_source_requirements": ["Requires Splunk Stream HTTP capture onboarded."],
        "false_positive_guidance": [
            "Proxies and shared egress IPs can make attribution to a single host ambiguous.",
        ],
    },
    "network:stream:tls": {
        "expected_output": "Each row is one TLS session record. A match means a monitored host "
                            "negotiated TLS with a certificate/SNI matching the indicator.",
        "data_source_requirements": ["Requires Splunk Stream TLS capture onboarded."],
        "false_positive_guidance": [
            "Shared hosting/CDN certificates can produce matches unrelated to the intended threat.",
        ],
    },
    "endpoint:XmlWinEventLog:Sysmon": {
        "expected_output": "Each row is one Sysmon event (process/file/registry depending on the "
                            "specific field matched). A match means matching activity was observed "
                            "on a monitored endpoint.",
        "data_source_requirements": [
            "Requires Sysmon deployed with an appropriate configuration and a Windows TA forwarding "
            "XmlWinEventLog:Sysmon into the endpoint index.",
        ],
        "false_positive_guidance": [
            "Command-line fragments and file names can appear in legitimate admin/automation activity — "
            "review full context before escalating.",
        ],
    },
    "auth:WinEventLog:Security": {
        "expected_output": "Each row is one Windows Security event log entry. A match means the "
                            "specified account appeared in a logon/auth-related event.",
        "data_source_requirements": ["Requires Windows Security event log forwarding onboarded."],
        "false_positive_guidance": [
            "Service accounts and scheduled tasks can produce frequent legitimate matches.",
        ],
    },
}

_SIGMA_KNOWLEDGE: dict[str, dict[str, object]] = {
    "network_connection": {
        "expected_output": "This is a platform-agnostic Sigma rule, not a directly runnable query. "
                            "Convert it with a Sigma converter (e.g. pySigma / `sigma convert`) targeting "
                            "your actual SIEM before running it. Once converted and run, a match means a "
                            "monitored host made or received a network connection matching the indicator(s).",
        "data_source_requirements": [
            "Requires network connection telemetry ingested by your SIEM under whatever product/service "
            "the target pySigma pipeline maps 'network_connection' to.",
        ],
        "false_positive_guidance": [
            "Shared/CDN-hosted IPs can trigger matches unrelated to the intended threat.",
        ],
    },
    "dns_query": {
        "expected_output": "Platform-agnostic Sigma rule — convert before running. A match means a "
                            "monitored host issued a DNS query matching the indicator.",
        "data_source_requirements": ["Requires DNS query telemetry ingested by your SIEM."],
        "false_positive_guidance": [
            "Legitimate CDNs and cloud services can share infrastructure with malicious domains.",
        ],
    },
    "proxy": {
        "expected_output": "Platform-agnostic Sigma rule — convert before running. A match means a "
                            "monitored host made an HTTP(S) request matching the indicator.",
        "data_source_requirements": ["Requires proxy/web-request telemetry ingested by your SIEM."],
        "false_positive_guidance": ["Shared egress IPs/proxies can make attribution ambiguous."],
    },
    "file_event": {
        "expected_output": "Platform-agnostic Sigma rule — convert before running. A match means a "
                            "file matching the indicator was observed on a monitored endpoint.",
        "data_source_requirements": ["Requires file event (Sysmon EventID 11 or equivalent) telemetry."],
        "false_positive_guidance": ["Hash-based matches are far more reliable than filename-based ones."],
    },
    "process_creation": {
        "expected_output": "Platform-agnostic Sigma rule — convert before running. A match means a "
                            "process matching the indicator was launched on a monitored endpoint.",
        "data_source_requirements": ["Requires process creation (Sysmon EventID 1 or equivalent) telemetry."],
        "false_positive_guidance": ["Command-line fragments can appear in legitimate admin scripts."],
    },
    "registry_event": {
        "expected_output": "Platform-agnostic Sigma rule — convert before running. A match means the "
                            "specified registry key/value activity was observed on a monitored endpoint.",
        "data_source_requirements": ["Requires registry event (Sysmon EventID 13 or equivalent) telemetry."],
        "false_positive_guidance": ["Many legitimate applications modify common registry run-keys."],
    },
}

_KNOWLEDGE_BY_PLATFORM: dict[str, dict[str, dict[str, object]]] = {
    "ms_sentinel_defender": _MS_KQL_KNOWLEDGE,
    "splunk": _SPLUNK_SPL_KNOWLEDGE,
    "sigma": _SIGMA_KNOWLEDGE,
}

_SEVERITY_TRIAGE_HINTS = {
    "critical": "If this returns results, treat as high priority: isolate scope of impact and "
                "escalate immediately per your incident response process. Do not action "
                "automatically from this tool.",
    "high": "If this returns results, prioritize triage within the current shift. Pivot to "
            "related tables (process/file events on the same DeviceId) to establish scope.",
    "medium": "If this returns results, review during normal triage queue. Correlate with "
              "other alerts on the same entity before escalating.",
    "low": "If this returns results, note for pattern-of-life review; escalate only if "
           "correlated with other higher-confidence signals.",
    "informational": "Results are context, not necessarily malicious activity on their own.",
}


def build_explanation(detection: IRDetection, rendered: RenderedQuery) -> QueryExplanation:
    platform_knowledge = _KNOWLEDGE_BY_PLATFORM.get(rendered.platform, {})
    knowledge = platform_knowledge.get(rendered.table_or_index, {})

    mitre_context = []
    for tid in detection.mitre_techniques:
        info = lookup_technique(tid)
        if info:
            mitre_context.append(MitreContext(
                technique_id=info.technique_id,
                technique_name=info.name,
                tactic=info.tactic,
                short_description=info.short_description,
            ))
        else:
            mitre_context.append(MitreContext(
                technique_id=tid, technique_name="(not in local ATT&CK lookup)",
                tactic="unknown",
                short_description="Technique ID not found in the local reference — "
                                   "verify against the full MITRE ATT&CK STIX bundle.",
            ))

    severity_tag = next((t.split(":", 1)[1] for t in detection.tags if t.startswith("severity:")), "medium")
    triage_hint = _SEVERITY_TRIAGE_HINTS.get(severity_tag, _SEVERITY_TRIAGE_HINTS["medium"])

    summary = (
        f"Searches {rendered.table_or_index} for activity matching indicator(s) from "
        f"\"{detection.name}\""
        + (f" over the window {detection.time_window.start.isoformat()} to "
           f"{detection.time_window.end.isoformat()}" if detection.time_window else "")
        + "."
    )

    return QueryExplanation(
        platform=rendered.platform,
        dialect=rendered.dialect,
        table_or_index=rendered.table_or_index,
        summary=summary,
        expected_output=knowledge.get(
            "expected_output",
            f"Each row is a matching event from {rendered.table_or_index}; a returned row "
            f"means the indicator was observed.",
        ),
        mitre_context=mitre_context,
        false_positive_guidance=list(knowledge.get("false_positive_guidance", [])),
        data_source_requirements=list(knowledge.get("data_source_requirements", [])),
        severity_triage_hint=triage_hint,
        caveats=list(rendered.caveats) + (
            [f"validation warning: {e}" for e in rendered.validation_errors]
            if rendered.validation_errors else []
        ),
    )
