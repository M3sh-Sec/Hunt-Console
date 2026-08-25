"""
parser/pcap_format.py

Minimal, defensive reader for the classic libpcap file format (RFC-ish,
see https://wiki.wireshark.org/Development/LibpcapFileFormat). Deliberately
implemented with the Python standard library only (struct) rather than
scapy/pyshark: this tool's job is bulk-extracting a handful of fields
(addresses, ports, DNS names, TLS SNI, plain HTTP request lines) from
untrusted, possibly-malformed capture files, and a large general-purpose
packet-parsing library is a larger attack surface than this narrow need
actually requires. Every read here is explicitly bounds-checked against the
remaining buffer length — malformed/truncated length fields are a known
exploit vector for packet parsers, so this module never trusts a length
field without clamping it to what's actually available.

PCAPNG (the newer block-based format) is NOT supported by this module —
detected and rejected with a clear error rather than mis-parsed. Convert
PCAPNG to classic pcap with `editcap -F pcap` before ingestion, or extend
this module with a dedicated pcapng reader (out of scope for v1).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

# Classic pcap magic numbers (native and swapped byte order; microsecond
# and nanosecond timestamp variants).
_MAGIC_LE_US = 0xA1B2C3D4
_MAGIC_BE_US = 0xD4C3B2A1
_MAGIC_LE_NS = 0xA1B23C4D
_MAGIC_BE_NS = 0x4D3CB2A1

# PCAPNG's block-type magic — used only to detect and reject.
_PCAPNG_MAGIC = 0x0A0D0D0A

_GLOBAL_HEADER_LEN = 24
_RECORD_HEADER_LEN = 16

# Defensive caps — a legitimate single packet is never anywhere near this
# large; a length field claiming otherwise is either corruption or a
# deliberately crafted malicious file.
MAX_PACKET_LEN = 262144          # 256 KiB per packet
MAX_FILE_LEN = 500 * 1024 * 1024  # 500 MiB per file (enforce at caller too)


class PcapFormatError(Exception):
    """Raised for unrecoverable format problems (bad magic, truncated global header, unsupported format)."""


@dataclass
class RawPacketRecord:
    timestamp: float          # seconds since epoch, float
    captured_len: int         # bytes actually captured (may be < original_len if snaplen truncated)
    original_len: int         # on-the-wire length
    data: bytes                # captured bytes, length == captured_len (already clamped)
    truncated_by_snaplen: bool
    index: int                 # 0-based position in the file, for error reporting


def _detect_byte_order_and_precision(magic_bytes: bytes) -> tuple[str, str]:
    magic = struct.unpack("<I", magic_bytes)[0]
    if magic == _MAGIC_LE_US:
        return "<", "us"
    if magic == _MAGIC_LE_NS:
        return "<", "ns"
    magic_be = struct.unpack(">I", magic_bytes)[0]
    if magic_be == _MAGIC_LE_US:
        return ">", "us"
    if magic_be == _MAGIC_LE_NS:
        return ">", "ns"
    if magic == _PCAPNG_MAGIC or magic_be == _PCAPNG_MAGIC:
        raise PcapFormatError(
            "file appears to be PCAPNG format, which is not supported by this reader — "
            "convert to classic pcap first (e.g. `editcap -F pcap in.pcapng out.pcap`)"
        )
    raise PcapFormatError(f"unrecognized pcap magic number: {magic_bytes!r}")


def iter_packets(data: bytes) -> Iterator[RawPacketRecord]:
    """
    Yields RawPacketRecord objects from raw classic-pcap file bytes.

    Malformed individual packet records are handled by raising
    PcapFormatError for the file as a whole ONLY when the global header
    itself is unreadable; per-packet length anomalies are clamped/handled
    rather than raising, since one bad record should not necessarily be
    treated as fatal by the higher-level extractor (see pcap_reader.py's
    sandboxed wrapper for the file-level size/time budget that bounds
    worst-case behavior on a maliciously crafted file).
    """
    if len(data) < _GLOBAL_HEADER_LEN:
        raise PcapFormatError(f"file too short to contain a pcap global header ({len(data)} bytes)")

    endian, precision = _detect_byte_order_and_precision(data[0:4])
    # Global header: magic(4) version_major(2) version_minor(2) thiszone(4)
    # sigfigs(4) snaplen(4) network(4)
    _, _, _, _, _, snaplen, _ = struct.unpack(f"{endian}IHHiIII", data[0:_GLOBAL_HEADER_LEN])

    offset = _GLOBAL_HEADER_LEN
    index = 0
    total_len = len(data)

    while offset < total_len:
        remaining = total_len - offset
        if remaining < _RECORD_HEADER_LEN:
            # Trailing garbage shorter than one record header — stop cleanly
            # rather than raising; this is common in truncated captures.
            break

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", data[offset:offset + _RECORD_HEADER_LEN]
        )
        offset += _RECORD_HEADER_LEN

        # Defensive clamp: never trust incl_len beyond what's actually left
        # in the buffer or beyond our sanity cap, regardless of what the
        # file claims.
        safe_incl_len = min(incl_len, MAX_PACKET_LEN, total_len - offset)
        if incl_len > MAX_PACKET_LEN:
            # Still record it, but the caller will see captured_len clamped
            # short of incl_len — flagged via truncated_by_snaplen-style logic
            pass

        packet_data = data[offset:offset + safe_incl_len]
        offset += safe_incl_len

        timestamp = ts_sec + (ts_frac / 1_000_000_000.0 if precision == "ns" else ts_frac / 1_000_000.0)

        yield RawPacketRecord(
            timestamp=timestamp,
            captured_len=len(packet_data),
            original_len=orig_len,
            data=packet_data,
            truncated_by_snaplen=(incl_len < orig_len) or (safe_incl_len < incl_len),
            index=index,
        )
        index += 1
