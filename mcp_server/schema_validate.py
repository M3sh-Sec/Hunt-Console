"""
mcp_server/schema_validate.py

A small, strict JSON Schema validator for the subset of JSON Schema 2020-12
that this server's tool schemas use. Every tool argument object is checked
against the tool's published inputSchema before any handler runs, and every
result is checked against its outputSchema before it is returned.

Deliberately limited:
  * No `$ref` of any kind, so nothing is ever fetched (the MCP spec forbids
    dereferencing network `$ref`s by default).
  * No composition keywords, so a schema cannot become a denial-of-service vector.
  * Unknown keywords raise SchemaError, and the test suite checks that every
    published schema uses only supported keywords, so a schema can never be
    silently more permissive than it looks.
"""

from __future__ import annotations

import functools
import re
from typing import Any

SUPPORTED_KEYWORDS = {
    "type", "properties", "required", "additionalProperties", "items",
    "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern",
    "enum", "minimum", "maximum", "description", "title", "default",
}
MAX_ERRORS = 20
_SURROGATE = re.compile("[\ud800-\udfff]")


class SchemaError(Exception):
    """The schema itself uses something this validator does not implement."""


@functools.lru_cache(maxsize=256)
def _compile(pattern: str) -> tuple[re.Pattern[str], bool]:
    # A pattern written as ^...$ must match the whole string. Python's `$` also
    # matches before a trailing newline, so use fullmatch on the inner part instead.
    if pattern.startswith("^") and pattern.endswith("$") and not pattern.endswith("\\$"):
        return re.compile(f"(?:{pattern[1:-1]})"), True
    return re.compile(pattern), False


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise SchemaError(f"unsupported type {expected!r}")


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    _validate(value, schema, path, errors)
    return errors[:MAX_ERRORS]


def _validate(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    if len(errors) >= MAX_ERRORS:
        return
    unknown = set(schema) - SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaError(f"unsupported schema keyword(s) at {path}: {sorted(unknown)}")

    expected = schema.get("type")
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, t) for t in types):
            errors.append(f"{path}: expected {' or '.join(types)}, got {_json_type(value)}")
            return

    if "enum" in schema and value not in schema["enum"]:
        allowed = ", ".join(repr(v) for v in schema["enum"][:30])
        errors.append(f"{path}: must be one of {allowed}")
        return

    if isinstance(value, str):
        if _SURROGATE.search(value):
            errors.append(f"{path}: contains invalid Unicode (unpaired surrogate)")
            return
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']} characters")
        if "pattern" in schema:
            rx, whole = _compile(schema["pattern"])
            ok = rx.fullmatch(value) if whole else rx.search(value)
            if not ok:
                errors.append(f"{path}: does not match the required format {schema['pattern']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: must be <= {schema['maximum']}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: allows at most {schema['maxItems']} item(s)")
            return      # do not walk an oversized array
        if schema.get("uniqueItems"):
            seen: list[Any] = []
            for item in value:
                if item in seen:
                    errors.append(f"{path}: items must be unique")
                    break
                seen.append(item)
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(value):
                _validate(item, item_schema, f"{path}[{i}]", errors)

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required property {key!r}")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in props:
                _validate(item, props[key], f"{path}.{key}", errors)
            elif additional is False:
                errors.append(f"{path}: unexpected property {str(key)[:60]!r}")
            elif isinstance(additional, dict):
                _validate(item, additional, f"{path}.{str(key)[:60]}", errors)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def check_schema_keywords(schema: dict[str, Any], path: str = "$") -> None:
    """Raises SchemaError if a schema (recursively) uses an unsupported keyword."""
    unknown = set(schema) - SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaError(f"unsupported schema keyword(s) at {path}: {sorted(unknown)}")
    for key, sub in schema.get("properties", {}).items():
        check_schema_keywords(sub, f"{path}.{key}")
    if isinstance(schema.get("items"), dict):
        check_schema_keywords(schema["items"], f"{path}[]")
    if isinstance(schema.get("additionalProperties"), dict):
        check_schema_keywords(schema["additionalProperties"], f"{path}.*")
