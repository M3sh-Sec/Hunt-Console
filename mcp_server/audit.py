"""
mcp_server/audit.py

Audit trail and rate limiting.

Each tool call produces one JSON line: time, tool, outcome, duration, the size
and SHA-256 prefix of the arguments, and (for file tools) the requested path.
Argument contents are never logged: report text, indicators and file data can
be sensitive. Lines go to stderr, which MCP clients capture in their server
logs, and optionally to an append-only file created with owner-only permissions.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class AuditLog:
    def __init__(self, path: Path | None = None):
        self._lock = threading.Lock()
        self._fd: int | None = None
        if path is not None:
            # Owner-only, append-only, never through a symlink.
            self._fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NOFOLLOW, 0o600)

    def event(self, **fields: Any) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "logger": "huntconsole-mcp",
                  **fields}
        line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
        with self._lock:
            try:
                sys.stderr.write(line)
                sys.stderr.flush()
            except (OSError, ValueError):
                pass
            if self._fd is not None:
                try:
                    os.write(self._fd, line.encode("ascii"))
                except OSError:
                    pass

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def fingerprint_arguments(arguments: Any) -> tuple[int, str]:
    """(size in bytes, first 16 hex chars of SHA-256) of the canonical JSON arguments."""
    try:
        blob = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError):
        blob = repr(arguments).encode("utf-8", "replace")
    return len(blob), hashlib.sha256(blob).hexdigest()[:16]


class RateLimiter:
    """Token bucket: `per_minute` calls, refilled continuously."""

    def __init__(self, per_minute: int, clock=time.monotonic):
        self.capacity = float(per_minute)
        self.tokens = float(per_minute)
        self.rate = per_minute / 60.0
        self.clock = clock
        self.updated = clock()

    def try_acquire(self) -> tuple[bool, float]:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0.0
        return False, (1.0 - self.tokens) / self.rate
