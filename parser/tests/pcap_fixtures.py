"""
parser/tests/pcap_fixtures.py

Hand-crafted classic-pcap byte builders, stdlib-only, used to generate
synthetic test captures without depending on scapy/tcpdump/real capture
files. Not part of the shipped application — test support code only.
"""

from __future__ import annotations

import struct

_ETHERTYPE_IPV4 = 0x0800


def _eth_header(ethertype: int = _ETHERTYPE_IPV4) -> bytes:
    dst_mac = b"\xaa" * 6
    src_mac = b"\xbb" * 6
    return dst_mac + src_mac + struct.pack(">H", ethertype)


def _ipv4_header(payload_len: int, proto: int, src_ip: str, dst_ip: str) -> bytes:
    version_ihl = 0x45
    total_len = 20 + payload_len
    src = bytes(int(o) for o in src_ip.split("."))
    dst = bytes(int(o) for o in dst_ip.split("."))
    return struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl, 0, total_len, 0, 0, 64, proto, 0, src, dst,
    )


def _udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + payload_len, 0)


def _tcp_header(src_port: int, dst_port: int) -> bytes:
    data_offset_flags = (5 << 12) | 0x018  # 20-byte header, PSH+ACK
    return struct.pack(">HHIIHHHH", src_port, dst_port, 0, 0, data_offset_flags, 0, 0, 0)


def _dns_query_payload(domain: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        struct.pack(">B", len(label)) + label.encode("ascii") for label in domain.split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def build_dns_query_packet(src_ip: str, dst_ip: str, domain: str) -> bytes:
    payload = _dns_query_payload(domain)
    udp = _udp_header(53421, 53, len(payload))
    ip = _ipv4_header(len(udp) + len(payload), 17, src_ip, dst_ip)
    return _eth_header() + ip + udp + payload


def _tls_client_hello_with_sni(sni: str) -> bytes:
    client_version = struct.pack(">H", 0x0303)
    random_bytes = b"\x00" * 32
    session_id = struct.pack(">B", 0)  # length 0
    cipher_suites = struct.pack(">H", 2) + b"\x00\x35"
    compression = struct.pack(">B", 1) + b"\x00"

    sni_bytes = sni.encode("ascii")
    server_name_entry = struct.pack(">B", 0) + struct.pack(">H", len(sni_bytes)) + sni_bytes
    server_name_list = struct.pack(">H", len(server_name_entry)) + server_name_entry
    sni_extension = struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list

    extensions = sni_extension
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    handshake_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_block
    handshake_len = struct.pack(">I", len(handshake_body))[1:]  # 3-byte length
    handshake = struct.pack(">B", 1) + handshake_len + handshake_body  # type=ClientHello

    record = struct.pack(">B", 0x16) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    return record


def build_tls_client_hello_packet(src_ip: str, dst_ip: str, sni: str) -> bytes:
    payload = _tls_client_hello_with_sni(sni)
    tcp = _tcp_header(51234, 443)
    ip = _ipv4_header(len(tcp) + len(payload), 6, src_ip, dst_ip)
    return _eth_header() + ip + tcp + payload


def build_http_get_packet(src_ip: str, dst_ip: str, host: str, path: str = "/") -> bytes:
    payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n".encode("ascii")
    tcp = _tcp_header(51235, 80)
    ip = _ipv4_header(len(tcp) + len(payload), 6, src_ip, dst_ip)
    return _eth_header() + ip + tcp + payload


def build_truncated_malformed_packet() -> bytes:
    """An Ethernet+IPv4 header claiming a payload that isn't actually present."""
    ip = _ipv4_header(9999, 6, "10.0.0.1", "10.0.0.2")  # claims a huge payload that doesn't follow
    return _eth_header() + ip  # no transport header/payload at all


def write_pcap_file(packets: list[bytes]) -> bytes:
    """Assembles a classic-pcap file (little-endian, microsecond precision) from raw packet bytes."""
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray()
    for i, pkt in enumerate(packets):
        record_header = struct.pack("<IIII", 1755000000 + i, 0, len(pkt), len(pkt))
        body += record_header + pkt
    return global_header + bytes(body)
