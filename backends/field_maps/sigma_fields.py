"""
backends/field_maps/sigma_fields.py

Maps the generic IR field taxonomy to Sigma's logsource category + field
naming conventions. Sigma itself is meant to be converted to a specific
SIEM's syntax by a converter (pySigma) using a target-specific field-mapping
pipeline — the field names used here are Sigma's own common/generic
taxonomy (as seen across the public SigmaHQ rule corpus), not any single
backend's native columns. A real pySigma pipeline would still be needed to
convert these rules to a specific product; this backend's job is producing
a correct, valid Sigma rule, not a final product-native query.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SigmaFieldMapping:
    category: str
    field: str
    value_type: str = "string"


FIELD_MAP: dict[str, SigmaFieldMapping] = {
    "network.src_ip": SigmaFieldMapping("network_connection", "SourceIp"),
    "network.dst_ip": SigmaFieldMapping("network_connection", "DestinationIp"),
    "network.src_port": SigmaFieldMapping("network_connection", "SourcePort", "number"),
    "network.dst_port": SigmaFieldMapping("network_connection", "DestinationPort", "number"),
    "network.protocol": SigmaFieldMapping("network_connection", "Protocol"),

    "dns.query": SigmaFieldMapping("dns_query", "query"),
    "dns.response_ip": SigmaFieldMapping("dns_query", "answer"),

    "http.url": SigmaFieldMapping("proxy", "cs-uri-query"),
    "http.host": SigmaFieldMapping("proxy", "c-uri"),
    "url.full": SigmaFieldMapping("proxy", "cs-uri-query"),
    "tls.sni": SigmaFieldMapping("network_connection", "DestinationHostname"),

    "file.hash_md5": SigmaFieldMapping("file_event", "Hashes"),
    "file.hash_sha1": SigmaFieldMapping("file_event", "Hashes"),
    "file.hash_sha256": SigmaFieldMapping("file_event", "Hashes"),
    "file.name": SigmaFieldMapping("file_event", "TargetFilename"),
    "file.path": SigmaFieldMapping("file_event", "TargetFilename"),

    "process.cmdline": SigmaFieldMapping("process_creation", "CommandLine"),
    "process.name": SigmaFieldMapping("process_creation", "Image"),
    "process.parent_name": SigmaFieldMapping("process_creation", "ParentImage"),
    "process.pid": SigmaFieldMapping("process_creation", "ProcessId", "number"),

    "identity.user": SigmaFieldMapping("process_creation", "User"),
    "identity.upn": SigmaFieldMapping("process_creation", "User"),

    "host.name": SigmaFieldMapping("network_connection", "Computer"),

    "registry.key": SigmaFieldMapping("registry_event", "TargetObject"),
    "registry.value": SigmaFieldMapping("registry_event", "Details"),
}

CATEGORY_SCHEMAS: dict[str, set[str]] = {
    "network_connection": {"SourceIp", "DestinationIp", "SourcePort", "DestinationPort",
                            "Protocol", "DestinationHostname", "Computer"},
    "dns_query": {"query", "answer"},
    "proxy": {"cs-uri-query", "c-uri"},
    "file_event": {"Hashes", "TargetFilename"},
    "process_creation": {"CommandLine", "Image", "ParentImage", "ProcessId", "User"},
    "registry_event": {"TargetObject", "Details"},
}
