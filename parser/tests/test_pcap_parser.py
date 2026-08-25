"""
parser/tests/test_pcap_parser.py

Run with: pytest parser/tests/ -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from parser.pcap_format import iter_packets, PcapFormatError  # noqa: E402
from parser.packet_decoder import decode_packet  # noqa: E402
from parser.sandbox import (  # noqa: E402
    parse_pcap_sandboxed, validate_file_before_parse, PcapValidationError,
)
from parser.pcap_to_ir import build_ir_from_pcap  # noqa: E402
from ir.schema import Operator  # noqa: E402

from .pcap_fixtures import (
    build_dns_query_packet, build_tls_client_hello_packet, build_http_get_packet,
    build_truncated_malformed_packet, write_pcap_file,
)


def test_validate_rejects_non_pcap_bytes():
    with pytest.raises(PcapValidationError):
        validate_file_before_parse(b"this is definitely not a pcap file")


def test_validate_accepts_valid_magic():
    data = write_pcap_file([build_dns_query_packet("10.0.0.5", "8.8.8.8", "example.com")])
    validate_file_before_parse(data)  # must not raise


def test_iter_packets_reads_expected_count():
    packets = [
        build_dns_query_packet("10.0.0.5", "8.8.8.8", "evil.example.com"),
        build_tls_client_hello_packet("10.0.0.5", "203.0.113.9", "c2.badsite.example"),
        build_http_get_packet("10.0.0.5", "198.51.100.7", "phish.example.net"),
    ]
    data = write_pcap_file(packets)
    records = list(iter_packets(data))
    assert len(records) == 3


def test_decode_dns_query_packet():
    pkt = build_dns_query_packet("10.0.0.5", "8.8.8.8", "evil.example.com")
    events = decode_packet(pkt)
    dns_events = [e for e in events if e.event_type == "dns_query"]
    assert len(dns_events) == 1
    assert dns_events[0].value["query"] == "evil.example.com"


def test_decode_tls_sni_packet():
    pkt = build_tls_client_hello_packet("10.0.0.5", "203.0.113.9", "c2.badsite.example")
    events = decode_packet(pkt)
    sni_events = [e for e in events if e.event_type == "tls_sni"]
    assert len(sni_events) == 1
    assert sni_events[0].value["sni"] == "c2.badsite.example"


def test_decode_http_request_packet():
    pkt = build_http_get_packet("10.0.0.5", "198.51.100.7", "phish.example.net", "/login")
    events = decode_packet(pkt)
    http_events = [e for e in events if e.event_type == "http_request"]
    assert len(http_events) == 1
    assert http_events[0].value["host"] == "phish.example.net"
    assert http_events[0].value["path"] == "/login"


def test_decode_malformed_packet_does_not_raise():
    pkt = build_truncated_malformed_packet()
    events = decode_packet(pkt)  # must not raise
    assert isinstance(events, list)


def test_sandboxed_parse_handles_mixed_valid_and_malformed_packets():
    packets = [
        build_dns_query_packet("10.0.0.5", "8.8.8.8", "evil.example.com"),
        build_truncated_malformed_packet(),
        build_tls_client_hello_packet("10.0.0.5", "203.0.113.9", "c2.badsite.example"),
        build_http_get_packet("10.0.0.5", "198.51.100.7", "phish.example.net"),
    ]
    data = write_pcap_file(packets)
    result = parse_pcap_sandboxed(data, timeout_seconds=15)

    assert result.packets_processed == 4  # malformed packet still "processed" (decoded to 0-1 events), not a crash
    event_types = {e.event_type for e in result.events}
    assert "dns_query" in event_types
    assert "tls_sni" in event_types
    assert "http_request" in event_types


def test_sandboxed_parse_rejects_invalid_file():
    with pytest.raises(PcapValidationError):
        parse_pcap_sandboxed(b"not a pcap at all", timeout_seconds=5)


def test_build_ir_from_pcap_extracts_all_indicator_types():
    packets = [
        build_dns_query_packet("10.0.0.5", "8.8.8.8", "evil.example.com"),
        build_tls_client_hello_packet("10.0.0.5", "203.0.113.9", "c2.badsite.example"),
        build_http_get_packet("10.0.0.5", "198.51.100.7", "phish.example.net"),
    ]
    data = write_pcap_file(packets)
    result = parse_pcap_sandboxed(data, timeout_seconds=15)

    detection = build_ir_from_pcap(result, source_filename="test.pcap", source_bytes_for_fingerprint=data)

    assert detection.validate() == []
    assert detection.reviewed is False  # PCAP-derived must always require review
    fields = {c.field for c in detection.conditions.items}
    assert "network.dst_ip" in fields
    assert "dns.query" in fields
    assert "tls.sni" in fields
    assert "http.host" in fields

    values = {c.value for c in detection.conditions.items}
    assert "evil.example.com" in values
    assert "c2.badsite.example" in values
    assert "phish.example.net" in values


def test_build_ir_from_pcap_with_no_indicators_produces_valid_placeholder():
    empty_data = write_pcap_file([])
    result = parse_pcap_sandboxed(empty_data, timeout_seconds=15)
    detection = build_ir_from_pcap(result, source_filename="empty.pcap", source_bytes_for_fingerprint=empty_data)

    assert detection.validate() == []
    assert len(detection.conditions.items) == 1
    assert detection.conditions.items[0].operator == Operator.EXISTS


def test_build_ir_from_pcap_deduplicates_repeated_indicators():
    packets = [build_dns_query_packet("10.0.0.5", "8.8.8.8", "evil.example.com") for _ in range(5)]
    data = write_pcap_file(packets)
    result = parse_pcap_sandboxed(data, timeout_seconds=15)
    detection = build_ir_from_pcap(result, source_filename="repeat.pcap", source_bytes_for_fingerprint=data)

    dns_conditions = [c for c in detection.conditions.items if c.field == "dns.query"]
    assert len(dns_conditions) == 1  # deduplicated, not 5 separate conditions
    assert "5x" in dns_conditions[0].notes
