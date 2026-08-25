"""
backends/ms_kql.py

Converts an IRDetection into Microsoft Sentinel / Defender Advanced Hunting
KQL. An IRDetection's conditions may reference fields that live on different
Defender tables (e.g. a network IP and a file hash) — KQL cannot join
unrelated tables in a single flat query the way this tool needs to for a
simple "any of these IOCs" hunt, so this backend renders ONE query PER
TABLE referenced by the detection's conditions, each scoped to only the
conditions valid for that table.

Where a condition is pruned out of a given table's query (because it
belongs to a different table, or has no KQL field mapping at all), that is
recorded as an explicit caveat on the RenderedQuery — never silently
dropped — so the explanation layer and GUI can surface it to the analyst.
"""

from __future__ import annotations

from typing import Optional

from ir.schema import IRCondition, IRConditionGroup, IRDetection, Logic, Operator
from .base import QueryBackend, RenderedQuery, UnsupportedFieldError, sanitize_value
from .field_maps.ms_kql_fields import FIELD_MAP, TABLE_SCHEMAS, KqlFieldMapping

_OPERATOR_TEMPLATES = {
    Operator.EQUALS: lambda col, val, is_str: f'{col} == {val}' if not is_str else f'{col} == "{val}"',
    Operator.NOT_EQUALS: lambda col, val, is_str: f'{col} != {val}' if not is_str else f'{col} != "{val}"',
    Operator.CONTAINS: lambda col, val, is_str: f'{col} has "{val}"',
    Operator.NOT_CONTAINS: lambda col, val, is_str: f'{col} !has "{val}"',
    Operator.STARTS_WITH: lambda col, val, is_str: f'{col} startswith "{val}"',
    Operator.ENDS_WITH: lambda col, val, is_str: f'{col} endswith "{val}"',
    Operator.REGEX: lambda col, val, is_str: f'{col} matches regex @"{val}"',
    Operator.GREATER_THAN: lambda col, val, is_str: f'{col} > {val}',
    Operator.LESS_THAN: lambda col, val, is_str: f'{col} < {val}',
    Operator.EXISTS: lambda col, val, is_str: f'isnotempty({col})',
}


def _render_leaf(cond: IRCondition, mapping: KqlFieldMapping) -> str:
    is_str = mapping.value_type == "string"

    if cond.operator in (Operator.IN, Operator.NOT_IN):
        values = cond.value if isinstance(cond.value, (list, tuple, set)) else [cond.value]
        if is_str:
            literal = "(" + ", ".join(f'"{sanitize_value(v)}"' for v in values) + ")"
        else:
            literal = "(" + ", ".join(str(v) for v in values) + ")"
        op = "in" if cond.operator == Operator.IN else "!in"
        return f"{mapping.column} {op} {literal}"

    template = _OPERATOR_TEMPLATES.get(cond.operator)
    if template is None:
        raise UnsupportedFieldError(f"operator {cond.operator} not supported by ms_kql backend")

    val = sanitize_value(cond.value) if cond.operator != Operator.EXISTS else None
    return template(mapping.column, val, is_str)


def _prune_for_table(
    node: "IRCondition | IRConditionGroup", table: str
) -> tuple[Optional[str], list[str]]:
    """
    Recursively renders `node` keeping only sub-conditions that map to
    `table`. Returns (kql_fragment_or_None, caveats).
    """
    if isinstance(node, IRCondition):
        mapping = FIELD_MAP.get(node.field)
        if mapping is None:
            return None, [f"omitted condition on unmapped field '{node.field}' "
                          f"(value={node.value!r}) — no KQL column mapping defined"]
        if mapping.table != table:
            return None, [f"omitted condition on '{node.field}' (maps to table "
                          f"'{mapping.table}', not '{table}')"]
        try:
            return _render_leaf(node, mapping), []
        except UnsupportedFieldError as exc:
            return None, [str(exc)]

    # IRConditionGroup
    rendered_parts: list[str] = []
    all_caveats: list[str] = []
    for item in node.items:
        frag, caveats = _prune_for_table(item, table)
        all_caveats.extend(caveats)
        if frag is not None:
            rendered_parts.append(frag)

    if not rendered_parts:
        return None, all_caveats

    if node.logic == Logic.NOT:
        # A NOT group must have exactly one child by construction. If that
        # child didn't survive pruning for this table, we already returned
        # None above. If it did, negate it.
        return f"not ({rendered_parts[0]})", all_caveats

    joiner = " and " if node.logic == Logic.AND else " or "
    return "(" + joiner.join(rendered_parts) + ")", all_caveats


class MsKqlBackend(QueryBackend):
    platform_name = "ms_sentinel_defender"
    dialect = "kql"

    def render(self, detection: IRDetection) -> list[RenderedQuery]:
        # Determine which tables are actually referenced by this detection's
        # conditions, so we know how many separate queries to produce.
        referenced_tables: set[str] = set()

        def _collect_tables(node: "IRCondition | IRConditionGroup") -> None:
            if isinstance(node, IRCondition):
                mapping = FIELD_MAP.get(node.field)
                if mapping is not None:
                    referenced_tables.add(mapping.table)
            else:
                for item in node.items:
                    _collect_tables(item)

        _collect_tables(detection.conditions)

        if not referenced_tables:
            # Nothing in this detection maps to any known KQL table — return
            # a single empty-caveat result the caller/GUI can flag rather
            # than silently returning nothing.
            return [RenderedQuery(
                platform=self.platform_name,
                dialect=self.dialect,
                table_or_index="(none)",
                query_text="",
                detection_id=detection.id,
                caveats=["no condition in this detection maps to a known Defender/Sentinel table; "
                         "all fields were unmapped or the detection has no conditions"],
                unmapped_field_count=_count_leaves(detection.conditions),
                validated=False,
            )]

        results: list[RenderedQuery] = []
        for table in sorted(referenced_tables):
            where_clause, caveats = _prune_for_table(detection.conditions, table)
            if where_clause is None:
                continue  # shouldn't happen since table came from a surviving leaf, but be safe

            time_filter = ""
            if detection.time_window:
                start = detection.time_window.start.strftime("%Y-%m-%dT%H:%M:%SZ")
                end = detection.time_window.end.strftime("%Y-%m-%dT%H:%M:%SZ")
                time_filter = f'| where TimeGenerated between (datetime({start}) .. datetime({end}))\n'

            query_text = f"{table}\n{time_filter}| where {where_clause}"

            rendered = RenderedQuery(
                platform=self.platform_name,
                dialect=self.dialect,
                table_or_index=table,
                query_text=query_text,
                detection_id=detection.id,
                caveats=caveats,
                unmapped_field_count=len([c for c in caveats if "unmapped field" in c]),
            )
            errors = self.validate(rendered)
            rendered.validated = not errors
            rendered.validation_errors = errors
            results.append(rendered)

        return results

    def validate(self, rendered: RenderedQuery) -> list[str]:
        """
        Defense-in-depth: confirm every column this backend claims to have
        used against `table` actually exists in TABLE_SCHEMAS for that
        table, independent of trusting FIELD_MAP was correct at render time.
        """
        errors: list[str] = []
        valid_columns = TABLE_SCHEMAS.get(rendered.table_or_index)
        if valid_columns is None:
            return [f"no known schema for table '{rendered.table_or_index}' — cannot validate"]

        # Extract candidate column tokens conservatively: any identifier
        # immediately followed by a KQL comparison/function context. This is
        # a lightweight structural check, not a full KQL parser.
        import re
        candidates = set(re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\s*(?:==|!=|has|!has|startswith|"
                                     r"endswith|matches|>|<|in\s*\(|!in\s*\()", rendered.query_text))
        candidates |= set(re.findall(r"isnotempty\(([A-Za-z][A-Za-z0-9_]*)\)", rendered.query_text))

        for col in candidates:
            if col not in valid_columns and col != "TimeGenerated":
                errors.append(f"column '{col}' not in known schema for table '{rendered.table_or_index}'")

        return errors


def _count_leaves(node: "IRCondition | IRConditionGroup") -> int:
    if isinstance(node, IRCondition):
        return 1
    return sum(_count_leaves(i) for i in node.items)
