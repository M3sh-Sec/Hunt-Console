"""
cve_hunt/builder.py

Builds an IRDetection that answers "which of my devices are exposed to these CVEs?".
Honest scope: this is an EXPOSURE hunt (Defender Vulnerability Management data).
It does not prove exploitation. Exploitation hunting needs the advisory's specific
behaviours (paths, processes, request patterns) - add those as reviewed IR conditions.
"""
from __future__ import annotations

from typing import Optional

from ir.schema import (IRCondition, IRConditionGroup, IRDetection, Logic, Operator, Provenance, SourceType)
from .kev import KevEntry, parse_cve_ids


def build_ir_from_cves(cve_ids, kev: Optional[dict[str, KevEntry]] = None, *, title: str = "CVE exposure hunt") -> IRDetection:
    cves = parse_cve_ids(cve_ids)
    items: list = [IRCondition(
        field="vuln.cve_id", operator=Operator.IN, value=cves,
        notes="CVE ids supplied by analyst" + (" (KEV-enriched)" if kev else ""),
        provenance=Provenance(source_type=SourceType.MANUAL, source_id="cve-list", confidence=0.9),
    )]
    tags = ["source:cve", "exposure-hunt"] + [f"cve:{c}" for c in cves]
    notes: list[str] = []
    seen_products: set[tuple[str, str]] = set()
    for c in cves:
        e = (kev or {}).get(c)
        if not e:
            continue
        tags.append(f"kev:{c}")
        if e.ransomware_use.lower() == "known":
            tags.append(f"kev-ransomware:{c}")
        notes.append(f"{c}: {e.vendor} {e.product} - {e.name} (KEV added {e.date_added})")
        if e.vendor and e.product and (e.vendor, e.product) not in seen_products:
            seen_products.add((e.vendor, e.product))
            items.append(IRConditionGroup(logic=Logic.AND, items=[
                IRCondition("software.vendor", Operator.CONTAINS, e.vendor.split()[0]),
                IRCondition("software.name", Operator.CONTAINS, e.product.split()[0]),
            ]))
    in_kev = sum(1 for c in cves if kev and c in kev)
    desc = f"Exposure hunt for {len(cves)} CVE(s)"
    if kev is not None:
        desc += f"; {in_kev} listed in the supplied CISA KEV catalog ({len(cves) - in_kev} not listed)"
    if notes:
        desc += ". " + " | ".join(notes)
    if kev is not None:
        missing = [c for c in cves if c not in kev]
        if missing:
            desc += ". Not in supplied KEV catalog: " + ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else "")
    return IRDetection(
        name=f"{title}: {', '.join(cves[:3])}{' ...' if len(cves) > 3 else ''}",
        description=desc,
        conditions=IRConditionGroup(logic=Logic.OR, items=items),
        time_window=None,
        provenance=Provenance(source_type=SourceType.MANUAL, source_id="cve-list", confidence=0.9),
        reviewed=False,
        tags=tags,
    )
