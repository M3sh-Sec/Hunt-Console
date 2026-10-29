"""
cve_hunt/kev.py

Offline CISA Known Exploited Vulnerabilities (KEV) enrichment. The tool never
downloads the catalog itself: the analyst supplies a KEV JSON file they fetched
from CISA (https://www.cisa.gov/known-exploited-vulnerabilities-catalog), so
no outbound call is made on untrusted input and the catalog's age is visible.
The file is untrusted data: size-capped, strictly parsed, strings length-capped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MAX_KEV_BYTES = 25 * 1024 * 1024
MAX_CVES_PER_HUNT = 500
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    short_description: str
    required_action: str
    ransomware_use: str


def _clip(v, n: int = 300) -> str:
    return str(v or "")[:n]


def parse_cve_ids(items: Iterable[str]) -> list[str]:
    """Normalise to upper case, validate strictly, de-duplicate, cap. Raises ValueError on bad input."""
    out: list[str] = []
    for raw in items:
        cve = str(raw).strip().upper()
        if not CVE_RE.match(cve):
            raise ValueError(f"not a valid CVE id: {str(raw)[:40]!r}")
        if cve not in out:
            out.append(cve)
    if not out:
        raise ValueError("no CVE ids supplied")
    if len(out) > MAX_CVES_PER_HUNT:
        raise ValueError(f"too many CVE ids ({len(out)} > {MAX_CVES_PER_HUNT})")
    return out


def load_kev_json(path: str | Path) -> dict[str, KevEntry]:
    p = Path(path)
    if p.stat().st_size > MAX_KEV_BYTES:
        raise ValueError("KEV file exceeds size limit")
    return parse_kev_json_text(p.read_text(encoding="utf-8"))


def parse_kev_json_text(text: str) -> dict[str, KevEntry]:
    """Same as load_kev_json() but for catalog text the caller has already read (and size-checked)."""
    if len(text) > MAX_KEV_BYTES:
        raise ValueError("KEV file exceeds size limit")
    data = json.loads(text)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("not a CISA KEV catalog: missing 'vulnerabilities' list")
    out: dict[str, KevEntry] = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID", "")).strip().upper()
        if not CVE_RE.match(cve):
            continue
        out[cve] = KevEntry(cve, _clip(v.get("vendorProject")), _clip(v.get("product")),
                            _clip(v.get("vulnerabilityName")), _clip(v.get("dateAdded"), 20),
                            _clip(v.get("shortDescription"), 600), _clip(v.get("requiredAction"), 300),
                            _clip(v.get("knownRansomwareCampaignUse"), 20))
    return out
