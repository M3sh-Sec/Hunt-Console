"""
backends/field_maps/ms_kql_fields.py

Maps the generic IR field taxonomy (ir.schema.FIELD_TAXONOMY) to Microsoft
Sentinel / Defender Advanced Hunting table + column names, and declares the
known-valid column set per table used for post-render validation.

This is the ONLY place KQL-specific column names should appear outside of
backends/ms_kql.py's operator templates. Keeping it isolated here is what
lets a future SPL/EQL backend exist without touching this file.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KqlFieldMapping:
    table: str
    column: str
    value_type: str = "string"   # "string" | "number" | "datetime"


# generic IR field -> KQL table + column
FIELD_MAP: dict[str, KqlFieldMapping] = {
    "network.src_ip": KqlFieldMapping("DeviceNetworkEvents", "LocalIP"),
    "network.dst_ip": KqlFieldMapping("DeviceNetworkEvents", "RemoteIP"),
    "network.src_port": KqlFieldMapping("DeviceNetworkEvents", "LocalPort", "number"),
    "network.dst_port": KqlFieldMapping("DeviceNetworkEvents", "RemotePort", "number"),
    "network.protocol": KqlFieldMapping("DeviceNetworkEvents", "Protocol"),

    "dns.query": KqlFieldMapping("DeviceNetworkEvents", "RemoteUrl"),
    "dns.response_ip": KqlFieldMapping("DeviceNetworkEvents", "RemoteIP"),

    "http.url": KqlFieldMapping("DeviceNetworkEvents", "RemoteUrl"),
    "http.host": KqlFieldMapping("DeviceNetworkEvents", "RemoteUrl"),
    "url.full": KqlFieldMapping("DeviceNetworkEvents", "RemoteUrl"),
    "url.domain": KqlFieldMapping("DeviceNetworkEvents", "RemoteUrl"),

    "tls.sni": KqlFieldMapping("DeviceNetworkEvents", "RemoteUrl"),

    "file.hash_md5": KqlFieldMapping("DeviceFileEvents", "MD5"),
    "file.hash_sha1": KqlFieldMapping("DeviceFileEvents", "SHA1"),
    "file.hash_sha256": KqlFieldMapping("DeviceFileEvents", "SHA256"),
    "file.name": KqlFieldMapping("DeviceFileEvents", "FileName"),
    "file.path": KqlFieldMapping("DeviceFileEvents", "FolderPath"),

    "process.cmdline": KqlFieldMapping("DeviceProcessEvents", "ProcessCommandLine"),
    "process.name": KqlFieldMapping("DeviceProcessEvents", "FileName"),
    "process.parent_name": KqlFieldMapping("DeviceProcessEvents", "InitiatingProcessFileName"),
    "process.pid": KqlFieldMapping("DeviceProcessEvents", "ProcessId", "number"),

    "identity.user": KqlFieldMapping("SigninLogs", "UserPrincipalName"),
    "identity.upn": KqlFieldMapping("SigninLogs", "UserPrincipalName"),
    "identity.sid": KqlFieldMapping("DeviceLogonEvents", "AccountSid"),

    "host.name": KqlFieldMapping("DeviceNetworkEvents", "DeviceName"),
    "host.id": KqlFieldMapping("DeviceNetworkEvents", "DeviceId"),

    "registry.key": KqlFieldMapping("DeviceRegistryEvents", "RegistryKey"),
    "registry.value": KqlFieldMapping("DeviceRegistryEvents", "RegistryValueName"),
    # mutex.name, email.*, ja3 intentionally omitted for v1 — not present in
    # standard Defender tables without additional data connectors. Leaving
    # them unmapped means they correctly fall through to "unmapped field"
    # handling rather than being guessed at.
}

# Known-valid columns per table, used by KQLBackend.validate() as a defense-
# in-depth check independent of FIELD_MAP correctness. Not exhaustive —
# covers the columns this backend actually emits, plus TimeGenerated which
# every table has and every rendered query filters on.
TABLE_SCHEMAS: dict[str, set[str]] = {
    "DeviceNetworkEvents": {
        "TimeGenerated", "DeviceId", "DeviceName", "LocalIP", "RemoteIP",
        "LocalPort", "RemotePort", "Protocol", "RemoteUrl",
    },
    "DeviceFileEvents": {
        "TimeGenerated", "DeviceId", "DeviceName", "MD5", "SHA1", "SHA256",
        "FileName", "FolderPath",
    },
    "DeviceProcessEvents": {
        "TimeGenerated", "DeviceId", "DeviceName", "ProcessCommandLine",
        "FileName", "InitiatingProcessFileName", "ProcessId",
    },
    "SigninLogs": {
        "TimeGenerated", "UserPrincipalName", "AppDisplayName", "IPAddress",
    },
    "DeviceLogonEvents": {
        "TimeGenerated", "DeviceId", "DeviceName", "AccountSid", "AccountName",
    },
    "DeviceRegistryEvents": {
        "TimeGenerated", "DeviceId", "DeviceName", "RegistryKey", "RegistryValueName",
    },
}
