"""
report_parser/url_fetcher.py

Validates and fetches a report from a URL, with SSRF protections: https
only, hostname resolved and every resulting address checked against
private/loopback/link-local/reserved ranges before any request is made,
size and content-type capped. This module cannot be meaningfully tested
against a live network in this environment, so `is_safe_url` (the pure
validation logic) is written to be independently testable via a mockable
resolver function, and is what should be exercised in CI.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlparse

MAX_REPORT_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB
ALLOWED_CONTENT_TYPES = {
    "text/html", "text/plain", "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
REQUEST_TIMEOUT_SECONDS = 15

ResolverFn = Callable[[str], list[str]]  # hostname -> list of IP address strings


class UnsafeUrlError(Exception):
    """Raised when a URL fails SSRF/scheme/host validation."""


def _default_resolver(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"could not resolve hostname '{hostname}': {exc}") from exc
    return sorted({info[4][0] for info in infos})


def _is_private_or_reserved(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable — treat as unsafe rather than let it through
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def is_safe_url(url: str, *, resolver: Optional[ResolverFn] = None) -> tuple[bool, str]:
    """
    Returns (is_safe, reason). `resolver` is injectable for testing without
    real DNS/network access — defaults to socket.getaddrinfo.
    """
    resolver = resolver or _default_resolver

    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False, f"only https:// URLs are allowed (got scheme='{parsed.scheme}')"
    if not parsed.hostname:
        return False, "URL has no hostname"
    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not allowed"

    hostname = parsed.hostname

    try:
        ipaddress.ip_address(hostname)
        return False, "URL host is a raw IP literal, not a domain name — not allowed"
    except ValueError:
        pass  # good — it's a domain name, proceed to resolve it

    try:
        addresses = resolver(hostname)
    except UnsafeUrlError as exc:
        return False, str(exc)

    if not addresses:
        return False, f"hostname '{hostname}' did not resolve to any address"

    for addr in addresses:
        if _is_private_or_reserved(addr):
            return False, f"hostname '{hostname}' resolves to a private/reserved address ({addr}) — blocked"

    return True, "ok"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UnsafeUrlError(f"refusing to follow redirect to '{newurl}' — re-submit the new URL explicitly")


def fetch_report_url(url: str, *, resolver: Optional[ResolverFn] = None) -> bytes:
    """
    Fetches `url` after passing is_safe_url(), with no automatic redirect
    following (a redirect to an internal address is a classic SSRF bypass —
    each redirect target must be independently validated, so any redirect
    is treated as a failure here rather than silently followed).
    """
    safe, reason = is_safe_url(url, resolver=resolver)
    if not safe:
        raise UnsafeUrlError(f"refusing to fetch '{url}': {reason}")

    req = urllib.request.Request(url, headers={"User-Agent": "threat-intel-ingest/1.0"})
    opener = urllib.request.build_opener(_NoRedirectHandler)
    with opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type and content_type not in ALLOWED_CONTENT_TYPES:
            raise UnsafeUrlError(f"unexpected content-type '{content_type}' — refusing to ingest")

        chunk = resp.read(MAX_REPORT_DOWNLOAD_BYTES + 1)
        if len(chunk) > MAX_REPORT_DOWNLOAD_BYTES:
            raise UnsafeUrlError(f"response exceeds max allowed size ({MAX_REPORT_DOWNLOAD_BYTES} bytes)")
        return chunk
