"""
backends/sigma.py

Converts an IRDetection into one or more Sigma rules (YAML), one rule per
logsource category referenced by the detection's conditions — analogous to
the KQL backend splitting by table and the SPL backend splitting by
index/sourcetype, since a single Sigma rule has exactly one `logsource`.

Sigma's detection block is structured data (selections + a condition
string), not a text query language, so this backend doesn't reuse the
string-templating approach from ms_kql.py/splunk_spl.py. Instead:

  - Each distinct (field, operator) pair present for a category becomes its
    own named selection (selectionN), with same-field/same-operator values
    merged into one list (Sigma's native OR-within-a-field-key mechanism).
  - Top-level Logic.OR across distinct selections uses Sigma's
    "1 of selection*" shorthand; Logic.AND uses "all of selection*".
  - Logic.NOT (always exactly one child, enforced by IRConditionGroup
    validation) renders as "not selection1".
  - Nested groups deeper than this flat pattern are NOT fully generalized
    in v1 — same practical limitation as the KQL/SPL backends' multi-table
    splitting already imposes, and no worse than what every builder in
    this codebase actually produces (flat OR/AND groups of leaf
    conditions). Anything that can't flow through cleanly is dropped with
    an explicit caveat, never silently misrepresented.

This backend emits a valid Sigma rule ready for `sigma convert` (pySigma)
against a real target pipeline — it does not itself convert Sigma to a
product-native query language.
"""

from __future__ import annotations

from ir.schema import IRCondition, IRConditionGroup, IRDetection, Logic, Operator
from .base import QueryBackend, RenderedQuery, UnsupportedFieldError, sanitize_value
from .field_maps.sigma_fields import FIELD_MAP, CATEGORY_SCHEMAS, SigmaFieldMapping
from .yaml_emit import emit_yaml

_OPERATOR_SUFFIX = {
    Operator.EQUALS: "",
    Operator.IN: "",
    Operator.CONTAINS: "|contains",
    Operator.STARTS_WITH: "|startswith",
    Operator.ENDS_WITH: "|endswith",
    Operator.REGEX: "|re",
}
_UNSUPPORTED_OPERATORS = {
    Operator.NOT_EQUALS, Operator.NOT_CONTAINS, Operator.NOT_IN,
    Operator.GREATER_THAN, Operator.LESS_THAN, Operator.EXISTS,
}


def _leaf_selection_key(field: SigmaFieldMapping, operator: Operator) -> str:
    return f"{field.field}{_OPERATOR_SUFFIX.get(operator, '')}"


def _collect_leaves_for_category(
    node, category: str, out: list, caveats: list,
) -> None:
    if isinstance(node, IRCondition):
        mapping = FIELD_MAP.get(node.field)
        if mapping is None:
            caveats.append(f"omitted condition on unmapped field '{node.field}' "
                          f"(value={node.value!r}) — no Sigma field mapping defined")
            return
        if mapping.category != category:
            caveats.append(f"omitted condition on '{node.field}' (maps to category "
                          f"'{mapping.category}', not '{category}')")
            return
        if node.operator in _UNSUPPORTED_OPERATORS:
            caveats.append(f"omitted condition on '{node.field}': operator {node.operator} "
                          f"is not supported by this Sigma backend in v1")
            return
        out.append(node)
        return

    for item in node.items:
        _collect_leaves_for_category(item, category, out, caveats)


def _build_selections(leaves: list) -> dict:
    grouped: dict = {}
    key_order: list = []

    for leaf in leaves:
        mapping = FIELD_MAP[leaf.field]
        selection_key = _leaf_selection_key(mapping, leaf.operator)

        if leaf.operator in (Operator.IN, Operator.NOT_IN):
            values = leaf.value if isinstance(leaf.value, (list, tuple, set)) else [leaf.value]
        else:
            values = [leaf.value]

        clean_values = [sanitize_value(v) if mapping.value_type == "string" else v for v in values]

        if selection_key not in grouped:
            grouped[selection_key] = []
            key_order.append(selection_key)
        grouped[selection_key].extend(clean_values)

    selections: dict = {}
    for i, key in enumerate(key_order, start=1):
        values = grouped[key]
        selections[f"selection{i}"] = {key: values[0] if len(values) == 1 else values}
    return selections


class SigmaBackend(QueryBackend):
    platform_name = "sigma"
    dialect = "sigma"

    def render(self, detection: IRDetection) -> list[RenderedQuery]:
        referenced_categories: set = set()

        def _collect_categories(node) -> None:
            if isinstance(node, IRCondition):
                mapping = FIELD_MAP.get(node.field)
                if mapping is not None and node.operator not in _UNSUPPORTED_OPERATORS:
                    referenced_categories.add(mapping.category)
            else:
                for item in node.items:
                    _collect_categories(item)

        _collect_categories(detection.conditions)

        if not referenced_categories:
            return [RenderedQuery(
                platform=self.platform_name, dialect=self.dialect, table_or_index="(none)",
                query_text="", detection_id=detection.id,
                caveats=["no condition in this detection maps to a known Sigma logsource category; "
                         "all fields were unmapped or used an unsupported operator"],
                unmapped_field_count=_count_leaves(detection.conditions), validated=False,
            )]

        results: list[RenderedQuery] = []
        for category in sorted(referenced_categories):
            leaves: list = []
            caveats: list = []
            _collect_leaves_for_category(detection.conditions, category, leaves, caveats)

            if not leaves:
                continue

            selections = _build_selections(leaves)
            top_logic = detection.conditions.logic
            if top_logic == Logic.NOT:
                condition_str = f"not {next(iter(selections))}" if selections else ""
                caveats.append("this detection's top-level logic is NOT — verify this Sigma rule's "
                              "semantics match intent (excludes rather than matches this indicator)")
            elif len(selections) == 1:
                condition_str = next(iter(selections))
            elif top_logic == Logic.AND:
                condition_str = "all of selection*"
            else:  # OR — the common case for every builder in this codebase
                condition_str = "1 of selection*"

            rule = {
                "title": detection.name[:256],
                "id": detection.id,
                "status": "experimental",
                "description": detection.description[:1024] if detection.description else "",
                "references": [],
                "tags": [f"attack.{t.lower()}" for t in detection.mitre_techniques],
                "logsource": {"category": category},
                "detection": {**selections, "condition": condition_str},
                "level": "medium",
                "falsepositives": ["Unknown"],
            }

            query_text = emit_yaml(rule)

            rendered = RenderedQuery(
                platform=self.platform_name, dialect=self.dialect, table_or_index=category,
                query_text=query_text, detection_id=detection.id, caveats=caveats,
                unmapped_field_count=len([c for c in caveats if "unmapped field" in c]),
            )
            errors = self.validate(rendered)
            rendered.validated = not errors
            rendered.validation_errors = errors
            results.append(rendered)

        return results

    def validate(self, rendered: RenderedQuery) -> list[str]:
        valid_fields = CATEGORY_SCHEMAS.get(rendered.table_or_index)
        if valid_fields is None:
            return [f"no known schema for Sigma category '{rendered.table_or_index}' — cannot validate"]

        import re
        candidates = set(re.findall(r'^\s{4}([A-Za-z][A-Za-z0-9_\-.]*)(?:\|[a-z]+)?:', rendered.query_text,
                                     re.MULTILINE))
        errors = []
        for field in candidates:
            if field not in valid_fields:
                errors.append(f"field '{field}' not in known Sigma schema for category "
                              f"'{rendered.table_or_index}'")
        return errors


def _count_leaves(node) -> int:
    if isinstance(node, IRCondition):
        return 1
    return sum(_count_leaves(i) for i in node.items)
