"""
explanation/schema.py

The structured explanation object that ships alongside every generated
query, in every platform's tab, in the GUI. Generated at build time from
the IR + rendered-query metadata (see explanation/generator.py) — never a
separate free-form LLM call guessing after the fact — so it is always
accurate to what the query actually does.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"


@dataclass
class MitreContext:
    technique_id: str
    technique_name: str
    tactic: str
    short_description: str


@dataclass
class QueryExplanation:
    schema_version: str = SCHEMA_VERSION
    platform: str = ""
    dialect: str = ""
    table_or_index: str = ""

    summary: str = ""                              # 1-2 sentence plain-English summary
    expected_output: str = ""                       # what a row/hit means
    mitre_context: list[MitreContext] = field(default_factory=list)
    false_positive_guidance: list[str] = field(default_factory=list)
    data_source_requirements: list[str] = field(default_factory=list)
    severity_triage_hint: str = ""
    caveats: list[str] = field(default_factory=list)   # carried over from RenderedQuery — omitted conditions etc.

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "platform": self.platform,
            "dialect": self.dialect,
            "table_or_index": self.table_or_index,
            "summary": self.summary,
            "expected_output": self.expected_output,
            "mitre_context": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "short_description": m.short_description,
                }
                for m in self.mitre_context
            ],
            "false_positive_guidance": self.false_positive_guidance,
            "data_source_requirements": self.data_source_requirements,
            "severity_triage_hint": self.severity_triage_hint,
            "caveats": self.caveats,
        }

    def to_markdown(self) -> str:
        lines = [f"### {self.platform} ({self.dialect}) — `{self.table_or_index}`", ""]
        lines.append(f"**Summary:** {self.summary}")
        lines.append("")
        lines.append(f"**Expected output:** {self.expected_output}")
        lines.append("")
        if self.mitre_context:
            lines.append("**MITRE ATT&CK context:**")
            for m in self.mitre_context:
                lines.append(f"- `{m.technique_id}` {m.technique_name} ({m.tactic}) — {m.short_description}")
            lines.append("")
        if self.data_source_requirements:
            lines.append("**Data source requirements:**")
            for d in self.data_source_requirements:
                lines.append(f"- {d}")
            lines.append("")
        if self.false_positive_guidance:
            lines.append("**False positive guidance:**")
            for f in self.false_positive_guidance:
                lines.append(f"- {f}")
            lines.append("")
        if self.severity_triage_hint:
            lines.append(f"**Triage hint:** {self.severity_triage_hint}")
            lines.append("")
        if self.caveats:
            lines.append("**Caveats:**")
            for c in self.caveats:
                lines.append(f"- {c}")
            lines.append("")
        return "\n".join(lines)
