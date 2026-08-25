"""
backends/base.py

Every query-language backend (ms_kql.py, spl.py, eql.py, ...) implements
QueryBackend. This module also holds the ONE shared sanitizer every backend
must route interpolated values through — do not let a backend build its own
ad hoc escaping. Injection risk exists in every one of these query
languages (KQL `externaldata`/`union` abuse, SPL subsearch injection, Lucene
special-character injection, etc.), not just SQL-style ones, so this is
treated as a hard, shared choke point rather than a per-backend nicety.
"""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from typing import Any

from ir.schema import IRDetection

# Allow-list used by sanitize_value(). Deliberately conservative: printable
# ASCII minus characters that have special meaning in ANY of our target
# query languages (quotes, backslash, backtick, semicolon, pipe, angle
# brackets, braces). Legitimate IOC values (IPs, domains, hashes, most
# command-line fragments) all pass through this fine; anything that doesn't
# is a signal the value needs closer inspection, not silent pass-through.
_DISALLOWED_CHARS = re.compile(r'["\'`;|<>{}\\]')


class QueryValidationError(Exception):
    """Raised when a rendered query fails backend-specific schema validation."""


class UnsupportedFieldError(Exception):
    """Raised when an IR field has no mapping entry for this backend."""


def sanitize_value(value: Any) -> str:
    """
    The single shared sanitization choke point for every backend. Strips/
    rejects characters that could break out of a query-language string
    literal or inject additional query syntax. Values containing rejected
    characters are NOT silently truncated — the disallowed characters are
    stripped and the caller (backend) is expected to have already decided
    this field is safe to render as a string literal in the first place.

    This is defense-in-depth, not a substitute for parameterized query APIs
    where a platform offers them (e.g. Log Analytics query parameters) —
    prefer those when available.
    """
    text = str(value)
    stripped = _DISALLOWED_CHARS.sub("", text)
    stripped = stripped.replace("\n", " ").replace("\r", " ")
    return stripped


@dataclass
class RenderedQuery:
    """
    One backend's output for one table/index-scoped slice of an IRDetection.
    A single IRDetection may produce multiple RenderedQuery objects if its
    conditions span multiple tables (see docstring in ms_kql.py for why).
    """
    platform: str                  # "ms_sentinel" | "ms_defender" | "splunk" | ...
    dialect: str                   # "kql" | "spl" | "eql" | ...
    table_or_index: str
    query_text: str
    detection_id: str
    caveats: list[str] = field(default_factory=list)   # e.g. "omitted 2 conditions not valid for this table"
    unmapped_field_count: int = 0
    validated: bool = False
    validation_errors: list[str] = field(default_factory=list)


class QueryBackend(abc.ABC):
    """Base class every platform-specific query backend implements."""

    platform_name: str = "base"
    dialect: str = "base"

    @abc.abstractmethod
    def render(self, detection: IRDetection) -> list[RenderedQuery]:
        """Convert an IRDetection into one or more platform-native queries."""
        raise NotImplementedError

    @abc.abstractmethod
    def validate(self, rendered: RenderedQuery) -> list[str]:
        """
        Backend-specific schema validation (e.g. confirm every referenced
        column actually exists on the target table). Returns a list of
        error strings; empty list means valid. Must not raise for normal
        validation failures — raise only for programmer errors.
        """
        raise NotImplementedError
