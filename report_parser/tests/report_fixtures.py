"""
report_parser/tests/report_fixtures.py

Minimal, stdlib-only DOCX and PDF byte builders for testing without real
sample files or external libraries. Test support code only.
"""

from __future__ import annotations

import io
import zipfile
import zlib

_CONTENT_TYPES_XML = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

_RELS_XML = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def build_minimal_docx(paragraphs: list[str]) -> bytes:
    body_xml = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{_xml_escape(p)}</w:t></w:r></w:p>' for p in paragraphs
    )
    document_xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_DOC_NS}"><w:body>{body_xml}</w:body></w:document>'
    ).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES_XML)
        zf.writestr("_rels/.rels", _RELS_XML)
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_minimal_pdf_uncompressed(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("latin-1")
    header = b"%PDF-1.4\n"
    obj2 = (
        b"2 0 obj\n<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
        + content + b"\nendstream\nendobj\n"
    )
    return header + b"1 0 obj<< /Type /Catalog >>endobj\n" + obj2 + b"%%EOF"


def build_minimal_pdf_flate_compressed(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("latin-1")
    compressed = zlib.compress(content)
    header = b"%PDF-1.4\n"
    obj2 = (
        b"2 0 obj\n<< /Length " + str(len(compressed)).encode() + b" /Filter /FlateDecode >>\nstream\n"
        + compressed + b"\nendstream\nendobj\n"
    )
    return header + b"1 0 obj<< /Type /Catalog >>endobj\n" + obj2 + b"%%EOF"
