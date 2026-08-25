"""
parser/pcap_to_ir.py

Converts ExtractedEvent objects (from packet_decoder.py, via the sandboxed
parser in sandbox.py) into an IRDetection, using the same IR schema every
other input source (alerts, reports, manual entry) converges on.

Unlike an alert, a PCAP has no inherent "this is the suspicious thing"
signal — every distinct value observed is a candidate indicator, not a
confirmed one. Confidence is set lower than the alert path's default (1.0)
to reflect that, and `reviewed` always defaults to False regardless of
caller intent, since PCAP-derived indicators should always go through
analyst review before being used to generate a hunting query.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from ir.schema import (
    IRCondition,
    IRConditionGroup,
    IRDetection,
    Logic,
    Operator,
    Provenance,
    SourceType,
    TimeWindow,
)
from .packet_decoder import ExtractedEvent
from .sandbox import PcapParseResult

PCAP_DERIVED_CONFIDENCE = 0.6  # lower than alert-sourced (1.0) — unconfirmed until analyst review


def _pcap_fingerprint(filename: str, data: bytes) -> str:
    basis = filename.encode("utf-8") + hashlib.sha256(data).digest()
    return hashlib.sha256(basis).hexdigest()[:16]


def build_ir_from_pcap(
    parse_result: PcapParseResult,
    *,
    source_filename: str,
    source_bytes_for_fingerprint: bytes,
    capture_start: datetime | None = None,
    capture_end: datetime | None = None,
) -> IRDetection:
    """
    Aggregates all distinct indicator values observed in a parsed PCAP into
    a single IRDetection. Distinct values only (not one condition per
    packet) — a busy capture can easily contain thousands of packets to the
    same handful of IPs, and a condition-per-packet IR would be both
    useless and a performance problem downstream.
    """
    seen_dst_ips: dict[str, int] = {}      # value -> occurrence count
    seen_domains: dict[str, int] = {}
    seen_sni: dict[str, int] = {}
    seen_http_hosts: dict[str, int] = {}

    for event in parse_result.events:
        if event.event_type == "connection" and event.dst_ip:
            seen_dst_ips[event.dst_ip] = seen_dst_ips.get(event.dst_ip, 0) + 1
        elif event.event_type == "dns_query" and not event.value.get("is_response"):
            query = event.value.get("query")
            if query:
                seen_domains[query] = seen_domains.get(query, 0) + 1
        elif event.event_type == "tls_sni":
            sni = event.value.get("sni")
            if sni:
                seen_sni[sni] = seen_sni.get(sni, 0) + 1
        elif event.event_type == "http_request":
            host = event.value.get("host")
            if host:
                seen_http_hosts[host] = seen_http_hosts.get(host, 0) + 1

    condition_items: list[IRCondition | IRConditionGroup] = []

    def _add_conditions(field: str, values: dict[str, int], label: str) -> None:
        for value, count in values.items():
            condition_items.append(IRCondition(
                field=field,
                operator=Operator.EQUALS,
                value=value,
                notes=f"observed {count}x in {label} from {source_filename}",
                provenance=Provenance(
                    source_type=SourceType.PCAP,
                    source_id=_pcap_fingerprint(source_filename, source_bytes_for_fingerprint),
                    source_detail=f"{label}: {value} (count={count})",
                    confidence=PCAP_DERIVED_CONFIDENCE,
                ),
            ))

    _add_conditions("network.dst_ip", seen_dst_ips, "connection destination IPs")
    _add_conditions("dns.query", seen_domains, "DNS queries")
    _add_conditions("tls.sni", seen_sni, "TLS SNI values")
    _add_conditions("http.host", seen_http_hosts, "HTTP Host headers")

    if not condition_items:
        condition_items.append(IRCondition(
            field="generic.raw_indicator",
            operator=Operator.EXISTS,
            value=None,
            notes="no extractable indicators found in this capture "
                  "(no DNS/TLS-SNI/HTTP/connection events decoded)",
        ))

    if capture_start and capture_end:
        time_window = TimeWindow(start=capture_start, end=capture_end)
    elif capture_start:
        time_window = TimeWindow.around(capture_start, timedelta(hours=1), timedelta(hours=1))
    else:
        now = datetime.now(timezone.utc)
        time_window = TimeWindow.around(now, timedelta(hours=1), timedelta(hours=1))

    warning_note = ""
    if parse_result.packets_skipped_malformed:
        warning_note = (
            f" {parse_result.packets_skipped_malformed} malformed packet(s) were skipped during parsing."
        )
    if parse_result.truncated_by_packet_cap:
        warning_note += " Parsing was stopped early due to the packet-count safety cap."

    detection = IRDetection(
        name=f"Investigate indicators from PCAP: {source_filename}",
        description=(
            f"Auto-extracted from {parse_result.packets_processed} decoded packets in "
            f"'{source_filename}': {len(seen_dst_ips)} distinct destination IP(s), "
            f"{len(seen_domains)} DNS quer(y/ies), {len(seen_sni)} TLS SNI value(s), "
            f"{len(seen_http_hosts)} HTTP host(s)." + warning_note
        ),
        conditions=IRConditionGroup(logic=Logic.OR, items=condition_items),
        time_window=time_window,
        provenance=Provenance(
            source_type=SourceType.PCAP,
            source_id=_pcap_fingerprint(source_filename, source_bytes_for_fingerprint),
            source_detail=source_filename,
            confidence=PCAP_DERIVED_CONFIDENCE,
        ),
        reviewed=False,   # PCAP-derived indicators always require analyst review before use
        tags=["auto-generated", "source:pcap", f"file:{source_filename}"],
    )

    errors = detection.validate()
    if errors:
        detection.tags.append("has-validation-warnings")

    return detection
