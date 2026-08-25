"""
parser/sandbox.py

Runs PCAP parsing in an isolated child process with a wall-clock timeout and
a memory cap, and validates the file before parsing even starts. PCAP files
are untrusted input — malformed captures are a known way to trigger
excessive memory use or hangs in packet parsers — so parsing never happens
in the main process.
"""

from __future__ import annotations

import multiprocessing
from dataclasses import dataclass

from .pcap_format import MAX_FILE_LEN, PcapFormatError, iter_packets
from .packet_decoder import ExtractedEvent, decode_packet

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MEMORY_LIMIT_BYTES = 512 * 1024 * 1024  # 512 MiB
MAX_PACKETS_PER_FILE = 200_000   # sanity cap independent of file size, in case of tiny-packet floods

# Classic pcap magic bytes (all byte-order/precision variants) — checked
# before any parsing begins so an obviously-not-a-pcap file is rejected
# immediately rather than fed to the parser.
_VALID_MAGICS = {
    bytes.fromhex("a1b2c3d4"), bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"), bytes.fromhex("4d3cb2a1"),
}


class PcapValidationError(Exception):
    """Raised when a file fails pre-parse validation (size, magic bytes)."""


class PcapSandboxTimeoutError(Exception):
    """Raised when parsing exceeds the wall-clock timeout."""


@dataclass
class PcapParseResult:
    events: list[ExtractedEvent]
    packets_processed: int
    packets_skipped_malformed: int
    truncated_by_packet_cap: bool
    warnings: list[str]


def validate_file_before_parse(data: bytes, *, max_len: int = MAX_FILE_LEN) -> None:
    """Cheap, pre-parse checks. Raises PcapValidationError on any failure."""
    if len(data) < 4:
        raise PcapValidationError("file too short to be a pcap file")
    if len(data) > max_len:
        raise PcapValidationError(f"file exceeds maximum allowed size ({max_len} bytes)")
    magic = data[0:4]
    magic_swapped = bytes(reversed(magic))
    if magic not in _VALID_MAGICS and magic_swapped not in _VALID_MAGICS:
        raise PcapValidationError(
            f"file does not start with a recognized pcap magic number (got {magic.hex()}); "
            f"if this is a PCAPNG file, convert it to classic pcap first"
        )


def _parse_worker(data: bytes, memory_limit_bytes: int, result_queue: "multiprocessing.Queue") -> None:
    """
    Runs inside the child process. Sets a memory limit (POSIX only — on
    platforms without `resource` this cap is skipped, and the timeout in
    the parent process remains the primary backstop) then parses.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
    except (ImportError, ValueError, OSError):
        pass  # not available on this platform, or already tighter — proceed with timeout as backstop

    events: list[ExtractedEvent] = []
    packets_processed = 0
    packets_skipped = 0
    warnings: list[str] = []
    truncated_by_cap = False

    try:
        for record in iter_packets(data):
            if packets_processed >= MAX_PACKETS_PER_FILE:
                truncated_by_cap = True
                warnings.append(f"stopped after {MAX_PACKETS_PER_FILE} packets (packet-count cap reached)")
                break
            try:
                packet_events = decode_packet(record.data, packet_index=record.index)
                events.extend(packet_events)
                packets_processed += 1
            except Exception as exc:  # noqa: BLE001 — a single bad packet must not abort the whole parse
                packets_skipped += 1
                if packets_skipped <= 10:  # avoid unbounded warning list on a very corrupt file
                    warnings.append(f"packet {record.index} skipped: {exc}")
    except PcapFormatError as exc:
        result_queue.put(("error", str(exc)))
        return

    result_queue.put(("ok", {
        "events": events,
        "packets_processed": packets_processed,
        "packets_skipped_malformed": packets_skipped,
        "truncated_by_packet_cap": truncated_by_cap,
        "warnings": warnings,
    }))


def parse_pcap_sandboxed(
    data: bytes,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    memory_limit_bytes: int = DEFAULT_MEMORY_LIMIT_BYTES,
) -> PcapParseResult:
    """
    Validates and parses `data` (raw pcap file bytes) in an isolated
    subprocess with a timeout and memory cap. This is the only entry point
    application code should call — never call iter_packets/decode_packet
    directly on untrusted input outside this wrapper.
    """
    validate_file_before_parse(data)

    ctx = multiprocessing.get_context("spawn")  # spawn, not fork: avoids inheriting parent state/handles
    result_queue: multiprocessing.Queue = ctx.Queue()
    process = ctx.Process(target=_parse_worker, args=(data, memory_limit_bytes, result_queue))
    process.start()
    process.join(timeout=timeout_seconds)

    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        if process.is_alive():
            process.kill()
        raise PcapSandboxTimeoutError(f"pcap parsing exceeded {timeout_seconds}s timeout and was terminated")

    if process.exitcode not in (0, None) and result_queue.empty():
        # Most likely killed by the OOM/memory limit (SIGKILL/SIGSEGV from RLIMIT_AS)
        raise PcapValidationError(
            f"pcap parser subprocess exited abnormally (code {process.exitcode}), "
            f"likely due to the {memory_limit_bytes}-byte memory limit or a crafted malformed file"
        )

    if result_queue.empty():
        raise PcapValidationError("pcap parser subprocess produced no result")

    status, payload = result_queue.get()
    if status == "error":
        raise PcapFormatError(payload)

    return PcapParseResult(
        events=payload["events"],
        packets_processed=payload["packets_processed"],
        packets_skipped_malformed=payload["packets_skipped_malformed"],
        truncated_by_packet_cap=payload["truncated_by_packet_cap"],
        warnings=payload["warnings"],
    )
