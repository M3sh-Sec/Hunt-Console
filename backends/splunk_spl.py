"""
backends/splunk_spl.py

Converts an IRDetection into Splunk Search Processing Language (SPL). Like
the KQL backend, an IRDetection's conditions may span multiple Splunk
index/sourcetype combinations (e.g. a network IOC and a file hash live in
entirely different indexes) — so this backend renders ONE query per
(index, sourcetype) pair referenced by the detection's conditions.

Boolean logic is rendered via SPL's `where` command using eval-language
boolean functions (like(), match(), in(), isnotnull()) rather than bare
`field=value` search-syntax filters. This is what lets this backend support
arbitrary AND/OR/NOT nesting the same way the KQL backend's `where` clause
does — bare SPL search-syntax filters don't compose the same way.
"""

from __future__ import annotations

from typing import Optional

from ir.schema import IRCondition, IRConditionGroup, IRDetection, Logic, Operator
from .base import QueryBackend, RenderedQuery, UnsupportedFieldError, sanitize_value
from .field_maps.splunk_spl_fields import FIELD_MAP, INDEX_SOURCETYPE_SCHEMAS, SplFieldMapping


def _escape_like_wildcards(value: str) -> str:
    """Escape Splunk like()'s SQL-style wildcard characters in a literal value."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _render_leaf(cond: IRCondition, mapping: SplFieldMapping) -> str:
    is_str = mapping.value_type == "string"
    field = mapping.field

    if cond.operator in (Operator.IN, Operator.NOT_IN):
        values = cond.value if isinstance(cond.value, (list, tuple, set)) else [cond.value]
        if is_str:
            literal = ", ".join(f'"{sanitize_value(v)}"' for v in values)
        else:
            literal = ", ".join(str(v) for v in values)
        expr = f'in({field}, {literal})'
        return expr if cond.operator == Operator.IN else f'NOT {expr}'

    if cond.operator == Operator.EQUALS:
        val = sanitize_value(cond.value)
        return f'{field}=="{val}"' if is_str else f'{field}=={val}'
    if cond.operator == Operator.NOT_EQUALS:
        val = sanitize_value(cond.value)
        return f'{field}!="{val}"' if is_str else f'{field}!={val}'
    if cond.operator == Operator.CONTAINS:
        val = _escape_like_wildcards(sanitize_value(cond.value))
        return f'like({field}, "%{val}%")'
    if cond.operator == Operator.NOT_CONTAINS:
        val = _escape_like_wildcards(sanitize_value(cond.value))
        return f'NOT like({field}, "%{val}%")'
    if cond.operator == Operator.STARTS_WITH:
        val = _escape_like_wildcards(sanitize_value(cond.value))
        return f'like({field}, "{val}%")'
    if cond.operator == Operator.ENDS_WITH:
        val = _escape_like_wildcards(sanitize_value(cond.value))
        return f'like({field}, "%{val}")'
    if cond.operator == Operator.REGEX:
        val = sanitize_value(cond.value)
        return f'match({field}, "{val}")'
    if cond.operator == Operator.GREATER_THAN:
        return f'{field}>{cond.value}'
    if cond.operator == Operator.LESS_THAN:
        return f'{field}<{cond.value}'
    if cond.operator == Operator.EXISTS:
        return f'isnotnull({field})'

    raise UnsupportedFieldError(f"operator {cond.operator} not supported by splunk_spl backend")


def _prune_for_key(node: "IRCondition | IRConditionGroup", key: str) -> tuple[Optional[str], list[str]]:
    """Same pruning strategy as the KQL backend, keyed by 'index:sourcetype' instead of table."""
    if isinstance(node, IRCondition):
        mapping = FIELD_MAP.get(node.field)
        if mapping is None:
            return None, [f"omitted condition on unmapped field '{node.field}' "
                          f"(value={node.value!r}) — no Splunk field mapping defined"]
        if mapping.key != key:
            return None, [f"omitted condition on '{node.field}' (maps to '{mapping.key}', not '{key}')"]
        try:
            return _render_leaf(node, mapping), []
        except UnsupportedFieldError as exc:
            return None, [str(exc)]

    rendered_parts: list[str] = []
    all_caveats: list[str] = []
    for item in node.items:
        frag, caveats = _prune_for_key(item, key)
        all_caveats.extend(caveats)
        if frag is not None:
            rendered_parts.append(frag)

    if not rendered_parts:
        return None, all_caveats

    if node.logic == Logic.NOT:
        return f"NOT ({rendered_parts[0]})", all_caveats

    joiner = " AND " if node.logic == Logic.AND else " OR "
    return "(" + joiner.join(rendered_parts) + ")", all_caveats


class SplunkSplBackend(QueryBackend):
    platform_name = "splunk"
    dialect = "spl"

    def render(self, detection: IRDetection) -> list[RenderedQuery]:
        referenced_keys: set[str] = set()

        def _collect_keys(node: "IRCondition | IRConditionGroup") -> None:
            if isinstance(node, IRCondition):
                mapping = FIELD_MAP.get(node.field)
                if mapping is not None:
                    referenced_keys.add(mapping.key)
            else:
                for item in node.items:
                    _collect_keys(item)

        _collect_keys(detection.conditions)

        if not referenced_keys:
            return [RenderedQuery(
                platform=self.platform_name,
                dialect=self.dialect,
                table_or_index="(none)",
                query_text="",
                detection_id=detection.id,
                caveats=["no condition in this detection maps to a known Splunk index/sourcetype; "
                         "all fields were unmapped or the detection has no conditions"],
                unmapped_field_count=_count_leaves(detection.conditions),
                validated=False,
            )]

        results: list[RenderedQuery] = []
        for key in sorted(referenced_keys):
            where_clause, caveats = _prune_for_key(detection.conditions, key)
            if where_clause is None:
                continue

            index, sourcetype = key.split(":", 1)

            time_range = ""
            if detection.time_window:
                start = detection.time_window.start.strftime("%m/%d/%Y:%H:%M:%S")
                end = detection.time_window.end.strftime("%m/%d/%Y:%H:%M:%S")
                time_range = f' earliest="{start}" latest="{end}"'

            query_text = (
                f'search index="{index}" sourcetype="{sourcetype}"{time_range}\n'
                f'| where {where_clause}'
            )

            rendered = RenderedQuery(
                platform=self.platform_name,
                dialect=self.dialect,
                table_or_index=key,
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
        errors: list[str] = []
        valid_fields = INDEX_SOURCETYPE_SCHEMAS.get(rendered.table_or_index)
        if valid_fields is None:
            return [f"no known schema for index/sourcetype '{rendered.table_or_index}' — cannot validate"]

        import re
        # field names appearing before ==, !=, >, < directly
        candidates = set(re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\s*(?:==|!=|>|<)", rendered.query_text))
        # field names as the first argument inside like()/match()/in()/isnotnull()
        candidates |= set(re.findall(
            r"(?:like|match|in|isnotnull)\(\s*([A-Za-z][A-Za-z0-9_]*)\s*[,)]", rendered.query_text))

        for field in candidates:
            if field not in valid_fields:
                errors.append(f"field '{field}' not in known schema for '{rendered.table_or_index}'")

        return errors


def _count_leaves(node: "IRCondition | IRConditionGroup") -> int:
    if isinstance(node, IRCondition):
        return 1
    return sum(_count_leaves(i) for i in node.items)
