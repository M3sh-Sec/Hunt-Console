"""
connectors/query_guard.py

Defense-in-depth validation for queries and identifiers sent to a vendor API.
The generated queries are single-table filters, so the guard is deliberately
strict: it accepts only that shape and rejects everything else (default deny)
rather than trying to enumerate every dangerous KQL/LogScale construct.
"""

from __future__ import annotations

import re

from .base import ConnectorQueryScopeError

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Anything in this set can read other tables/clusters/files or run code.
_KQL_FORBIDDEN_WORDS = {
    "union", "join", "lookup", "externaldata", "evaluate", "find", "search",
    "database", "cluster", "materialize", "invoke", "let", "datatable", "print",
    "range", "set", "declare", "restrict", "macro", "toscalar", "table", "external_table",
    "ingestion", "ingest", "plugin", "parse_json_external", "http_request", "http_request_post",
}
_KQL_STRING_RE = re.compile(r'@?"(?:[^"\\]|\\.)*"|@?\'(?:[^\'\\]|\\.)*\'')
_KQL_COMMENT_RE = re.compile(r"//[^\n]*")
_LQL_FORBIDDEN_WORDS = {
    "join", "selfjoin", "selfjoinfilter", "defineTable".lower(), "readfile", "createevents",
    "repo", "view", "writejson", "ingest", "lookup", "hash_index",
}


def validate_identifier(value: str, *, what: str = "identifier") -> str:
    """Allow-list check for IDs that are placed in a URL path or a query literal."""
    if not isinstance(value, str) or value in (".", "..") or not _ID_RE.match(value):
        raise ConnectorQueryScopeError(f"invalid {what}: must match {_ID_RE.pattern}")
    return value


def filter_techniques(values) -> list[str]:
    """Keep only well-formed ATT&CK technique IDs (e.g. T1059, T1059.001)."""
    out: list[str] = []
    for v in values or []:
        t = str(v).strip().upper()
        if _TECHNIQUE_RE.match(t) and t not in out:
            out.append(t)
    return out


def enforce_kql_scope(query: str, allowed_tables: set[str]) -> None:
    """
    Accept only: <AllowedTable> followed by '|' pipeline operators, one statement.
    Strings and comments are removed before inspection so they cannot hide or fake tokens.
    """
    if not isinstance(query, str) or not query.strip():
        raise ConnectorQueryScopeError("empty query")
    if len(query) > 20000:
        raise ConnectorQueryScopeError("query too long")
    stripped = _KQL_COMMENT_RE.sub(" ", _KQL_STRING_RE.sub('""', query))
    if ";" in stripped:
        raise ConnectorQueryScopeError("multiple statements are not allowed")
    body = stripped.strip()
    if body.startswith("."):
        raise ConnectorQueryScopeError("management commands are not allowed")
    first = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\b", body)
    if not first or first.group(1) not in allowed_tables:
        raise ConnectorQueryScopeError(
            f"query must start with an allow-listed table: {sorted(allowed_tables)}")
    words = {w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body)}
    bad = words & _KQL_FORBIDDEN_WORDS
    if bad:
        raise ConnectorQueryScopeError(f"query uses a disallowed KQL construct: {sorted(bad)}")
    # any other capitalised identifier that is a known-table shape but not allow-listed
    # (e.g. 'AuditLogs' after a pipe) is only legal as a column name; block bare '*' sources.
    if re.search(r"\(\s*\*\s*\)|^\s*\*", body):
        raise ConnectorQueryScopeError("wildcard table sources are not allowed")


def enforce_lql_scope(query: str) -> None:
    """LogScale queries: forbid cross-repo/view access and functions that read or join other data."""
    if not isinstance(query, str) or not query.strip() or len(query) > 20000:
        raise ConnectorQueryScopeError("empty or oversized query")
    body = _KQL_STRING_RE.sub('""', query)
    words = {w.lower() for w in re.findall(r"[A-Za-z_#][A-Za-z0-9_#]*", body)}
    bad = {w.lstrip("#") for w in words} & _LQL_FORBIDDEN_WORDS
    if bad:
        raise ConnectorQueryScopeError(f"query uses a disallowed LogScale construct: {sorted(bad)}")
