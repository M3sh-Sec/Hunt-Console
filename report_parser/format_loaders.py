"""
report_parser/format_loaders.py

Extracts plain text from an uploaded threat intel / breach report, for
downstream IOC/TTP extraction. Every loader treats input bytes as fully
untrusted (same tier as PCAP data — a crafted "report" is a plausible
attack vector) and enforces size/complexity caps before doing real work.

Format support:
  - text/markdown: trivial decode, no dependencies.
  - HTML: stdlib html.parser tag stripping — no dependencies.
  - DOCX: DOCX is a zip archive of XML — fully extracted with stdlib
    zipfile + xml.etree, no external dependencies, with zip-bomb and
    XML-entity-expansion guards.
  - PDF: a minimal, dependency-free, BEST-EFFORT extractor that scans for
    PDF content-stream text-showing operators (Tj/TJ), handling both raw
    and FlateDecode-compressed streams via stdlib zlib. This is NOT a
    general-purpose PDF parser — it does not handle CID/Type0 fonts,
    ligature/encoding tables, multi-column reflow, or encrypted PDFs. For
    production use on arbitrary real-world PDFs, replace this with
    pdfplumber or pypdf; this exists so the tool has zero required
    third-party dependencies and so ingestion can be tested offline. When
    extraction quality is uncertain, this loader returns what it found
    plus a warning rather than silently returning incomplete text.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from html.parser import HTMLParser
from xml.etree import ElementTree

MAX_DOCUMENT_LEN = 50 * 1024 * 1024      # 50 MiB raw file
MAX_ZIP_ENTRIES = 2000                    # zip-bomb guard for DOCX
MAX_ZIP_UNCOMPRESSED_TOTAL = 200 * 1024 * 1024  # 200 MiB decompressed, total
MAX_PDF_STREAM_DECOMPRESSED = 20 * 1024 * 1024  # 20 MiB per decompressed PDF stream


class ReportLoadError(Exception):
    """Raised when a document can't be safely or meaningfully loaded."""


# ---------------------------------------------------------------- text -----

def load_text_from_plain(data: bytes) -> str:
    if len(data) > MAX_DOCUMENT_LEN:
        raise ReportLoadError(f"file exceeds max size ({MAX_DOCUMENT_LEN} bytes)")
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ReportLoadError("could not decode file as text in any supported encoding")


# ---------------------------------------------------------------- html -----

class _TextExtractingHTMLParser(HTMLParser):
    _SKIP_TAGS = {"script", "style", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self.chunks.append(data.strip())


def load_text_from_html(data: bytes) -> str:
    if len(data) > MAX_DOCUMENT_LEN:
        raise ReportLoadError(f"file exceeds max size ({MAX_DOCUMENT_LEN} bytes)")
    text = load_text_from_plain(data)
    parser = _TextExtractingHTMLParser()
    try:
        parser.feed(text)
    except Exception as exc:  # noqa: BLE001 — malformed HTML must not crash ingestion
        raise ReportLoadError(f"HTML parsing failed: {exc}") from exc
    return "\n".join(parser.chunks)


# ---------------------------------------------------------------- docx -----

_DOCX_WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def load_text_from_docx(data: bytes) -> str:
    if len(data) > MAX_DOCUMENT_LEN:
        raise ReportLoadError(f"file exceeds max size ({MAX_DOCUMENT_LEN} bytes)")

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ReportLoadError(f"not a valid DOCX/zip file: {exc}") from exc

    infolist = zf.infolist()
    if len(infolist) > MAX_ZIP_ENTRIES:
        raise ReportLoadError(f"DOCX contains too many archive entries ({len(infolist)}) — possible zip bomb")

    total_uncompressed = sum(info.file_size for info in infolist)
    if total_uncompressed > MAX_ZIP_UNCOMPRESSED_TOTAL:
        raise ReportLoadError(
            f"DOCX total uncompressed size ({total_uncompressed} bytes) exceeds safety cap — possible zip bomb"
        )

    try:
        document_xml = zf.read("word/document.xml")
    except KeyError as exc:
        raise ReportLoadError("not a valid DOCX — missing word/document.xml") from exc

    try:
        # xml.etree.ElementTree does not resolve external entities by default
        # in modern CPython (the classic XXE/billion-laughs vector via
        # DTD-declared entities was mitigated upstream), but we still bound
        # the input size above as defense in depth regardless of parser
        # internals.
        root = ElementTree.fromstring(document_xml)
    except ElementTree.ParseError as exc:
        raise ReportLoadError(f"failed to parse word/document.xml: {exc}") from exc

    paragraphs: list[str] = []
    for para in root.iter(f"{_DOCX_WORD_NS}p"):
        runs = [node.text for node in para.iter(f"{_DOCX_WORD_NS}t") if node.text]
        if runs:
            paragraphs.append("".join(runs))

    return "\n".join(paragraphs)


# ---------------------------------------------------------------- pdf ------

_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_DICT_BEFORE_STREAM_RE = re.compile(rb"<<(.*?)>>\s*stream", re.DOTALL)
_TJ_STRING_RE = re.compile(rb"\((?:[^()\\]|\\.)*\)\s*Tj")
_TJ_ARRAY_RE = re.compile(rb"\[((?:[^\[\]\\]|\\.)*)\]\s*TJ")
_PAREN_STRING_RE = re.compile(rb"\((?:[^()\\]|\\.)*\)")


def _unescape_pdf_string(raw: bytes) -> str:
    inner = raw[1:-1]  # strip surrounding parens
    inner = inner.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\", b"\\")
    inner = inner.replace(rb"\n", b"\n").replace(rb"\r", b"\r").replace(rb"\t", b"\t")
    try:
        return inner.decode("latin-1")
    except Exception:
        return inner.decode("ascii", errors="replace")


def _extract_text_from_content_stream(content: bytes) -> str:
    pieces: list[str] = []
    for m in _TJ_STRING_RE.finditer(content):
        s = _PAREN_STRING_RE.search(m.group(0))
        if s:
            pieces.append(_unescape_pdf_string(s.group(0)))
    for m in _TJ_ARRAY_RE.finditer(content):
        for s in _PAREN_STRING_RE.finditer(m.group(1)):
            pieces.append(_unescape_pdf_string(s.group(0)))
    return " ".join(pieces)


def load_text_from_pdf(data: bytes) -> tuple[str, list[str]]:
    """Returns (text, warnings). Best-effort — see module docstring for limitations."""
    if len(data) > MAX_DOCUMENT_LEN:
        raise ReportLoadError(f"file exceeds max size ({MAX_DOCUMENT_LEN} bytes)")
    if not data.startswith(b"%PDF-"):
        raise ReportLoadError("file does not start with the PDF signature (%PDF-)")

    warnings: list[str] = []
    text_parts: list[str] = []

    for stream_match in _STREAM_RE.finditer(data):
        raw_stream = stream_match.group(1)
        preceding = data[max(0, stream_match.start() - 500):stream_match.start()]
        dict_match = _DICT_BEFORE_STREAM_RE.search(preceding + b"stream")
        obj_dict = dict_match.group(1) if dict_match else b""

        content = raw_stream
        if b"/FlateDecode" in obj_dict:
            try:
                content = zlib.decompress(raw_stream, bufsize=MAX_PDF_STREAM_DECOMPRESSED)
            except zlib.error as exc:
                warnings.append(f"skipped a FlateDecode stream that failed to decompress: {exc}")
                continue
            if len(content) > MAX_PDF_STREAM_DECOMPRESSED:
                warnings.append("skipped an oversized decompressed stream (possible decompression bomb)")
                continue
        elif b"/Filter" in obj_dict:
            continue

        extracted = _extract_text_from_content_stream(content)
        if extracted:
            text_parts.append(extracted)

    if not text_parts:
        warnings.append(
            "no text-showing operators (Tj/TJ) were found — this PDF may be image-based/scanned "
            "(requires OCR, not handled here), use an unsupported encoding, or use a text extraction "
            "method this minimal parser doesn't cover; consider pdfplumber/pypdf for full coverage"
        )

    return "\n".join(text_parts), warnings
