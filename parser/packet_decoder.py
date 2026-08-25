"""
parser/packet_decoder.py

Decodes a single raw packet (as captured, starting at the Ethernet frame)
into zero or more ExtractedEvent objects. Every function here treats the
input as fully untrusted: all offsets are bounds-checked against the actual
buffer length before use, and malformed/truncated packets return None (or
fewer events) rather than raising or reading out of bounds. A single
malformed packet must never be able to crash or hang the overall parse.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD

_IPPROTO_TCP = 6
_IPPROTO_UDP = 17

_TLS_HANDSHAKE_CONTENT_TYPE = 0x16
_TLS_CLIENT_HELLO_TYPE = 0x01
_TLS_EXTENSION_SERVER_NAME = 0x0000


@dataclass
class ExtractedEvent:
    event_type: str                 # "dns_query" | "tls_sni" | "http_request" | "connection"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # "tcp" | "udp"
    value: dict = field(default_factory=dict)   # event-specific payload, e.g. {"query": "evil.example.com"}
    packet_index: int = -1
    truncated: bool = False


def _safe_slice(data: bytes, start: int, length: int) -> Optional[bytes]:
    """Returns data[start:start+length] only if fully within bounds, else None."""
    if start < 0 or length < 0 or start + length > len(data):
        return None
    return data[start:start + length]


def _format_ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _format_ipv6(raw: bytes) -> str:
    groups = struct.unpack(">8H", raw)
    return ":".join(f"{g:x}" for g in groups)


def decode_packet(raw: bytes, packet_index: int = -1) -> list[ExtractedEvent]:
    """
    Top-level entry point: decode one raw Ethernet frame and return every
    ExtractedEvent found in it. Never raises on malformed input — returns
    an empty list if the packet can't be meaningfully parsed.
    """
    events: list[ExtractedEvent] = []

    eth = _safe_slice(raw, 0, 14)
    if eth is None:
        return events  # too short to even be an Ethernet frame
    ethertype = struct.unpack(">H", eth[12:14])[0]

    if ethertype == _ETHERTYPE_IPV4:
        ip_info = _decode_ipv4(raw, 14)
    elif ethertype == _ETHERTYPE_IPV6:
        ip_info = _decode_ipv6(raw, 14)
    else:
        return events  # ARP, VLAN-tagged, or other — not handled in v1

    if ip_info is None:
        return events

    src_ip, dst_ip, proto, payload_offset = ip_info

    if proto == _IPPROTO_UDP:
        udp_info = _decode_udp(raw, payload_offset)
        if udp_info is None:
            return events
        src_port, dst_port, udp_payload = udp_info

        conn_event = ExtractedEvent(
            event_type="connection", src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol="udp",
            packet_index=packet_index,
        )
        events.append(conn_event)

        if dst_port == 53 or src_port == 53:
            dns_event = _decode_dns_query(udp_payload)
            if dns_event is not None:
                dns_event.src_ip, dns_event.dst_ip = src_ip, dst_ip
                dns_event.src_port, dns_event.dst_port = src_port, dst_port
                dns_event.protocol = "udp"
                dns_event.packet_index = packet_index
                events.append(dns_event)

    elif proto == _IPPROTO_TCP:
        tcp_info = _decode_tcp(raw, payload_offset)
        if tcp_info is None:
            return events
        src_port, dst_port, tcp_payload = tcp_info

        conn_event = ExtractedEvent(
            event_type="connection", src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol="tcp",
            packet_index=packet_index,
        )
        events.append(conn_event)

        if tcp_payload:
            sni_event = _decode_tls_client_hello_sni(tcp_payload)
            if sni_event is not None:
                sni_event.src_ip, sni_event.dst_ip = src_ip, dst_ip
                sni_event.src_port, sni_event.dst_port = src_port, dst_port
                sni_event.protocol = "tcp"
                sni_event.packet_index = packet_index
                events.append(sni_event)

            http_event = _decode_http_request(tcp_payload)
            if http_event is not None:
                http_event.src_ip, http_event.dst_ip = src_ip, dst_ip
                http_event.src_port, http_event.dst_port = src_port, dst_port
                http_event.protocol = "tcp"
                http_event.packet_index = packet_index
                events.append(http_event)

    return events


def _decode_ipv4(raw: bytes, offset: int) -> Optional[tuple[str, str, int, int]]:
    header = _safe_slice(raw, offset, 20)
    if header is None:
        return None
    version_ihl = header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None
    proto = header[9]
    src_ip = _format_ipv4(header[12:16])
    dst_ip = _format_ipv4(header[16:20])

    if ihl > 20:
        full_header = _safe_slice(raw, offset, ihl)
        if full_header is None:
            return None

    payload_offset = offset + ihl
    if payload_offset > len(raw):
        return None
    return src_ip, dst_ip, proto, payload_offset


def _decode_ipv6(raw: bytes, offset: int) -> Optional[tuple[str, str, int, int]]:
    header = _safe_slice(raw, offset, 40)
    if header is None:
        return None
    version = header[0] >> 4
    if version != 6:
        return None
    next_header = header[6]
    src_ip = _format_ipv6(header[8:24])
    dst_ip = _format_ipv6(header[24:40])
    payload_offset = offset + 40
    # Note: IPv6 extension headers are not walked in v1 — next_header is
    # assumed to already be the transport protocol. Packets using extension
    # headers will simply not match TCP/UDP below and be safely ignored.
    return src_ip, dst_ip, next_header, payload_offset


def _decode_udp(raw: bytes, offset: int) -> Optional[tuple[int, int, bytes]]:
    header = _safe_slice(raw, offset, 8)
    if header is None:
        return None
    src_port, dst_port, length, _checksum = struct.unpack(">HHHH", header)
    payload = raw[offset + 8: offset + max(length, 8)] if length >= 8 else raw[offset + 8:]
    return src_port, dst_port, payload


def _decode_tcp(raw: bytes, offset: int) -> Optional[tuple[int, int, bytes]]:
    header = _safe_slice(raw, offset, 20)
    if header is None:
        return None
    src_port, dst_port = struct.unpack(">HH", header[0:4])
    data_offset_byte = header[12]
    header_len = (data_offset_byte >> 4) * 4
    if header_len < 20:
        return None
    payload = raw[offset + header_len:]
    return src_port, dst_port, payload


def _read_dns_name(data: bytes, start: int) -> Optional[tuple[str, int]]:
    """
    Reads a (possibly compressed) DNS name starting at `start`. Returns
    (name, offset_after_name) or None if malformed. Compression-pointer
    following is capped to prevent an infinite loop on a maliciously
    crafted pointer cycle.
    """
    labels: list[str] = []
    pos = start
    jumps = 0
    max_jumps = 20  # a legitimate DNS name never needs anywhere near this many

    while True:
        if pos >= len(data):
            return None
        length_byte = data[pos]

        if length_byte == 0:
            pos += 1
            break

        if (length_byte & 0xC0) == 0xC0:  # compression pointer
            jumps += 1
            if jumps > max_jumps:
                return None
            if pos + 1 >= len(data):
                return None
            pointer = ((length_byte & 0x3F) << 8) | data[pos + 1]
            pos = pointer
            continue

        label_len = length_byte
        label = _safe_slice(data, pos + 1, label_len)
        if label is None:
            return None
        try:
            labels.append(label.decode("ascii", errors="replace"))
        except Exception:
            return None
        pos += 1 + label_len

        if len(labels) > 128:  # sanity cap on label count
            return None

    return ".".join(labels), pos


def _decode_dns_query(payload: bytes) -> Optional[ExtractedEvent]:
    header = _safe_slice(payload, 0, 12)
    if header is None:
        return None
    _id, flags, qdcount, _an, _ns, _ar = struct.unpack(">HHHHHH", header)
    is_response = bool(flags & 0x8000)
    if qdcount == 0:
        return None

    result = _read_dns_name(payload, 12)
    if result is None:
        return None
    name, _end = result
    if not name:
        return None

    return ExtractedEvent(
        event_type="dns_query",
        value={"query": name.rstrip("."), "is_response": is_response},
    )


def _decode_tls_client_hello_sni(payload: bytes) -> Optional[ExtractedEvent]:
    record_header = _safe_slice(payload, 0, 5)
    if record_header is None:
        return None
    content_type = record_header[0]
    if content_type != _TLS_HANDSHAKE_CONTENT_TYPE:
        return None
    record_len = struct.unpack(">H", record_header[3:5])[0]

    handshake = _safe_slice(payload, 5, min(record_len, len(payload) - 5))
    if handshake is None or len(handshake) < 4:
        return None
    if handshake[0] != _TLS_CLIENT_HELLO_TYPE:
        return None

    pos = 4  # skip handshake type(1) + length(3)
    pos += 2  # client version
    pos += 32  # random
    if pos >= len(handshake):
        return None

    session_id_len = handshake[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(handshake):
        return None

    cipher_suites_len = struct.unpack(">H", handshake[pos:pos + 2])[0]
    pos += 2 + cipher_suites_len
    if pos >= len(handshake):
        return None

    compression_len = handshake[pos]
    pos += 1 + compression_len
    if pos + 2 > len(handshake):
        return None

    extensions_len = struct.unpack(">H", handshake[pos:pos + 2])[0]
    pos += 2
    extensions_end = min(pos + extensions_len, len(handshake))

    while pos + 4 <= extensions_end:
        ext_type, ext_len = struct.unpack(">HH", handshake[pos:pos + 4])
        pos += 4
        ext_data = _safe_slice(handshake, pos, ext_len)
        if ext_data is None:
            return None

        if ext_type == _TLS_EXTENSION_SERVER_NAME:
            sni = _parse_server_name_extension(ext_data)
            if sni:
                return ExtractedEvent(event_type="tls_sni", value={"sni": sni})
        pos += ext_len

    return None


def _parse_server_name_extension(data: bytes) -> Optional[str]:
    if len(data) < 2:
        return None
    list_len = struct.unpack(">H", data[0:2])[0]
    pos = 2
    end = min(2 + list_len, len(data))
    while pos + 3 <= end:
        name_type = data[pos]
        name_len = struct.unpack(">H", data[pos + 1:pos + 3])[0]
        name = _safe_slice(data, pos + 3, name_len)
        pos += 3 + name_len
        if name_type == 0 and name is not None:
            try:
                return name.decode("ascii", errors="replace")
            except Exception:
                return None
    return None


_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")


def _decode_http_request(payload: bytes) -> Optional[ExtractedEvent]:
    if not payload.startswith(_HTTP_METHODS):
        return None
    try:
        text = payload[:4096].decode("ascii", errors="replace")
    except Exception:
        return None

    lines = text.split("\r\n")
    if not lines:
        return None
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]

    host = None
    for line in lines[1:]:
        if line == "":
            break
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    return ExtractedEvent(
        event_type="http_request",
        value={"method": method, "path": path, "host": host},
    )
