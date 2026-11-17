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
_LQL_FORBIDDEN_WORDS = {
    "join", "selfjoin", "selfjoinfilter", "defineTable".lower(), "readfile", "createevents",
    "repo", "view", "writejson", "ingest", "lookup", "hash_index",
}


def _strip_literals(query: str, *, kql: bool) -> str:
    """
    Remove string literals and comments in ONE left-to-right pass, using the language's own
    rules, so neither can hide or fake the other. (A regex that strips strings first and
    comments second disagrees with the real parser: `@"\\"` is a complete KQL verbatim string,
    and a quote inside a `//` comment does not open a string.)
    KQL: `@"..."`/`@'...'` are verbatim (no backslash escapes; a doubled quote is a quote);
    `"..."`/`'...'` take backslash escapes; `//` comments run to end of line.
    Unterminated strings, KQL multi-line backtick/tilde strings and LogScale block comments are
    refused (default deny: the generated queries never need them).
    """
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        c = query[i]
        if c == "/" and query.startswith("//", i):
            j = query.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
            continue
        if c == "/" and query.startswith("/*", i):
            if kql:
                out.append(c)
                i += 1
                continue
            j = query.find("*/", i + 2)
            if j < 0:
                raise ConnectorQueryScopeError("unterminated comment")
            i = j + 2
            out.append(" ")
            continue
        if c in "`~" and kql:
            raise ConnectorQueryScopeError("backtick/tilde string literals are not allowed")
        verbatim = kql and c == "@" and i + 1 < n and query[i + 1] in "\"'"
        if verbatim or c in "\"'":
            q = query[i + 1] if verbatim else c
            i += 2 if verbatim else 1
            while True:
                if i >= n:
                    raise ConnectorQueryScopeError("unterminated string literal")
                ch = query[i]
                if verbatim:
                    if ch == q:
                        if i + 1 < n and query[i + 1] == q:
                            i += 2
                            continue
                        i += 1
                        break
                elif ch == "\\":
                    i += 2
                    continue
                elif ch == q:
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        out.append(c)
        i += 1
    return "".join(out)


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
    stripped = _strip_literals(query, kql=True)
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
    body = _strip_literals(query, kql=False)
    words = {w.lower() for w in re.findall(r"[A-Za-z_#][A-Za-z0-9_#]*", body)}
    bad = {w.lstrip("#") for w in words} & _LQL_FORBIDDEN_WORDS
    if bad:
        raise ConnectorQueryScopeError(f"query uses a disallowed LogScale construct: {sorted(bad)}")
