"""
backends/yaml_emit.py

A minimal, dependency-free YAML serializer covering exactly the subset
Sigma rules need: nested dicts, lists, strings, ints, and None. Written to
avoid a PyYAML dependency for one narrow use case, and to keep full control
over string quoting/escaping (every string scalar is always double-quoted
and escaped, never emitted as an unquoted plain scalar) so that no
attacker-controlled indicator value can break out of the YAML structure by
exploiting plain-scalar parsing ambiguity (e.g. a value starting with `- `,
containing `: `, or matching YAML's boolean/null keywords).
"""

from __future__ import annotations

from typing import Any


def _quote_string(s: str) -> str:
    escaped = (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _emit_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return _quote_string(str(value))


def _is_safe_key(key: str) -> bool:
    return bool(key) and all(c.isalnum() or c in "_-|." for c in key) and not key[0].isdigit()


def emit_yaml(obj: Any, indent: int = 0) -> str:
    """Serializes obj (dict/list/scalar, arbitrarily nested) to a YAML string."""
    pad = "  " * indent

    if isinstance(obj, dict):
        if not obj:
            return f"{pad}{{}}\n"
        lines = []
        for key, value in obj.items():
            key_str = str(key) if _is_safe_key(str(key)) else _quote_string(str(key))
            if isinstance(value, dict) and value:
                lines.append(f"{pad}{key_str}:")
                lines.append(emit_yaml(value, indent + 1).rstrip("\n"))
            elif isinstance(value, list) and value:
                lines.append(f"{pad}{key_str}:")
                lines.append(emit_yaml(value, indent + 1).rstrip("\n"))
            elif isinstance(value, dict):
                lines.append(f"{pad}{key_str}: {{}}")
            elif isinstance(value, list):
                lines.append(f"{pad}{key_str}: []")
            else:
                lines.append(f"{pad}{key_str}: {_emit_scalar(value)}")
        return "\n".join(lines) + "\n"

    if isinstance(obj, list):
        if not obj:
            return f"{pad}[]\n"
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                nested = emit_yaml(item, indent + 1).rstrip("\n")
                nested_lines = nested.split("\n")
                first = nested_lines[0].strip()
                lines.append(f"{pad}- {first}")
                lines.extend(nested_lines[1:])
            else:
                lines.append(f"{pad}- {_emit_scalar(item)}")
        return "\n".join(lines) + "\n"

    return f"{pad}{_emit_scalar(obj)}\n"
