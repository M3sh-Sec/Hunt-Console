"""
backends/field_maps/splunk_spl_fields.py

Maps the generic IR field taxonomy to Splunk index/sourcetype/field triples.
Field names follow Splunk Common Information Model (CIM) conventions where
a CIM-compliant add-on would normally provide them (dest_ip, src_ip, user,
process, file_hash, etc.).

IMPORTANT — unlike Sentinel/Defender's fixed table schema, Splunk index and
sourcetype names are entirely deployment-specific (they depend on what data
is actually onboarded and how it's normalized). The values below are
reasonable, commonly-seen defaults (Splunk Stream app for network data,
Sysmon via a Windows TA for endpoint data) but MUST be reviewed/adjusted
per environment before use — see README section "Splunk field mapping
customization." Treat this file as a starting template, not ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SplFieldMapping:
    index: str
    sourcetype: str
    field: str
    value_type: str = "string"   # "string" | "number"

    @property
    def key(self) -> str:
        return f"{self.index}:{self.sourcetype}"


FIELD_MAP: dict[str, SplFieldMapping] = {
    "network.src_ip": SplFieldMapping("network", "stream:tcp", "src_ip"),
    "network.dst_ip": SplFieldMapping("network", "stream:tcp", "dest_ip"),
    "network.src_port": SplFieldMapping("network", "stream:tcp", "src_port", "number"),
    "network.dst_port": SplFieldMapping("network", "stream:tcp", "dest_port", "number"),
    "network.protocol": SplFieldMapping("network", "stream:tcp", "transport"),

    "dns.query": SplFieldMapping("network", "stream:dns", "query"),
    "dns.response_ip": SplFieldMapping("network", "stream:dns", "answer"),

    "http.url": SplFieldMapping("network", "stream:http", "url"),
    "http.host": SplFieldMapping("network", "stream:http", "url"),
    "http.user_agent": SplFieldMapping("network", "stream:http", "http_user_agent"),
    "url.full": SplFieldMapping("network", "stream:http", "url"),
    "url.domain": SplFieldMapping("network", "stream:http", "url"),

    "tls.sni": SplFieldMapping("network", "stream:tls", "ssl_subject"),

    "file.hash_md5": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "file_hash_md5"),
    "file.hash_sha1": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "file_hash_sha1"),
    "file.hash_sha256": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "file_hash_sha256"),
    "file.name": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "file_name"),
    "file.path": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "file_path"),

    "process.cmdline": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "process"),
    "process.name": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "process_name"),
    "process.parent_name": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "parent_process_name"),
    "process.pid": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "process_id", "number"),

    "identity.user": SplFieldMapping("auth", "WinEventLog:Security", "user"),
    "identity.upn": SplFieldMapping("auth", "WinEventLog:Security", "user"),
    "identity.sid": SplFieldMapping("auth", "WinEventLog:Security", "user_id"),

    "host.name": SplFieldMapping("network", "stream:tcp", "dest"),
    "host.id": SplFieldMapping("network", "stream:tcp", "dvc"),

    "registry.key": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "registry_key_name"),
    "registry.value": SplFieldMapping("endpoint", "XmlWinEventLog:Sysmon", "registry_value_name"),
    # mutex.name, email.*, ja3 intentionally omitted for v1 — same rationale
    # as the KQL field map: no default onboarded source assumed, so these
    # correctly fall through to "unmapped field" handling.
}

# Known-valid fields per (index, sourcetype) key, used by SplunkSplBackend.
# validate() as a defense-in-depth check independent of FIELD_MAP.
INDEX_SOURCETYPE_SCHEMAS: dict[str, set[str]] = {
    "network:stream:tcp": {"src_ip", "dest_ip", "src_port", "dest_port", "transport", "dest", "dvc"},
    "network:stream:dns": {"query", "answer"},
    "network:stream:http": {"url", "http_user_agent"},
    "network:stream:tls": {"ssl_subject"},
    "endpoint:XmlWinEventLog:Sysmon": {
        "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "file_name", "file_path",
        "process", "process_name", "parent_process_name", "process_id",
        "registry_key_name", "registry_value_name",
    },
    "auth:WinEventLog:Security": {"user", "user_id"},
}
