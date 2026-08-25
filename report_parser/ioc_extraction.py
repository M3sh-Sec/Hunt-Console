"""
report_parser/ioc_extraction.py

Deterministic, regex-based IOC extraction from free-text report content.
This is Stage 1 of the two-stage extraction pipeline described in the
product spec (fast, auditable, no hallucination risk). Stage 2
(NLP/LLM-assisted extraction of TTP narrative / campaign context) is
intentionally NOT implemented in this module — see the module docstring
in builder.py for why and what the integration contract would be.

Threat reports very commonly "defang" indicators to avoid them being
clickable/live (e.g. "185[.]220[.]101[.]1", "evil[.]com", "hxxp://",
"malware[.]exe"). This module un-defangs before matching so those are
still extracted, since a report author's intent (this IS an indicator,
just written safely) shouldn't cause it to be missed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_TEXT_LEN_FOR_EXTRACTION = 5_000_000  # 5 MB of text — regex on far larger input is a DoS risk


@dataclass
class ExtractedIOC:
    ioc_type: str            # "ip","domain","url","md5","sha1","sha256","cve","email"
    value: str
    source_snippet: str      # surrounding text, for traceability in the IR preview
    confidence: float = 0.8  # regex-matched, unconfirmed — lower than manual entry (1.0) or alert (1.0)


def _defang(text: str) -> str:
    replacements = [
        (r"\[\.\]", "."), (r"\(\.\)", "."), (r"\{\.\}", "."),
        (r"hxxps://", "https://"), (r"hxxp://", "http://"),
        (r"HXXPS://", "https://"), (r"HXXP://", "http://"),
        (r"\[:\]", ":"), (r"\[at\]", "@"), (r"\(at\)", "@"),
    ]
    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text, flags=re.IGNORECASE)
    return text


_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|io|co|ru|cn|top|xyz|club|online|site|link|icu|cc|tk|gq|ml|ga|cf)\b",
    re.IGNORECASE,
)


def _snippet(text: str, start: int, end: int, radius: int = 60) -> str:
    s = max(0, start - radius)
    e = min(len(text), end + radius)
    return text[s:e].strip().replace("\n", " ")


def extract_iocs(raw_text: str) -> list[ExtractedIOC]:
    if len(raw_text) > MAX_TEXT_LEN_FOR_EXTRACTION:
        raw_text = raw_text[:MAX_TEXT_LEN_FOR_EXTRACTION]

    text = _defang(raw_text)
    results: list[ExtractedIOC] = []

    for m in _IPV4_RE.finditer(text):
        results.append(ExtractedIOC("ip", m.group(0), _snippet(text, m.start(), m.end())))

    for m in _URL_RE.finditer(text):
        results.append(ExtractedIOC("url", m.group(0), _snippet(text, m.start(), m.end())))

    for m in _CVE_RE.finditer(text):
        results.append(ExtractedIOC("cve", m.group(0).upper(), _snippet(text, m.start(), m.end()), confidence=0.95))

    for m in _EMAIL_RE.finditer(text):
        results.append(ExtractedIOC("email", m.group(0), _snippet(text, m.start(), m.end())))

    seen_hash_spans: set[tuple[int, int]] = set()
    for regex, kind in ((_SHA256_RE, "sha256"), (_SHA1_RE, "sha1"), (_MD5_RE, "md5")):
        for m in regex.finditer(text):
            span = (m.start(), m.end())
            if span in seen_hash_spans:
                continue
            seen_hash_spans.add(span)
            results.append(
                ExtractedIOC(kind, m.group(0).lower(), _snippet(text, m.start(), m.end()), confidence=0.9)
            )

    url_spans = [(m.start(), m.end()) for m in _URL_RE.finditer(text)]

    def _inside_url(pos: int) -> bool:
        return any(s <= pos < e for s, e in url_spans)

    for m in _DOMAIN_RE.finditer(text):
        if _inside_url(m.start()):
            continue
        results.append(ExtractedIOC("domain", m.group(0).lower().rstrip("."), _snippet(text, m.start(), m.end())))

    return results
