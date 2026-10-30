"""
mcp_server/config.py

Operator configuration and hard limits. Everything that widens what the server
can do (file access, a bigger rate limit, an ATT&CK bundle) comes from the
command line the operator writes into the MCP client config. Nothing comes
from tool arguments, and nothing is read from environment variables, so a
model cannot widen its own permissions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ---- protocol / transport -------------------------------------------------
MAX_MESSAGE_BYTES = 4 * 1024 * 1024          # one JSON-RPC line from the client
MAX_JSON_DEPTH = 64                          # nesting depth accepted in a request
MAX_RESULT_BYTES = 2 * 1024 * 1024           # one tool result returned to the client

# ---- tool input sizes -----------------------------------------------------
MAX_REPORT_TEXT_CHARS = 1_000_000            # hunt_from_report_text
MAX_INDICATORS = 2_000                       # hunt_from_indicators
MAX_TECHNIQUES = 200
MAX_CVES = 500                               # matches cve_hunt.kev.MAX_CVES_PER_HUNT
MAX_NAME_CHARS = 200
MAX_PATH_CHARS = 1024

# ---- file access (only when --allow-dir is given) -------------------------
MAX_REPORT_FILE_BYTES = 50 * 1024 * 1024     # same cap as report_parser.format_loaders
MAX_PCAP_FILE_BYTES = 100 * 1024 * 1024
MAX_KEV_FILE_BYTES = 25 * 1024 * 1024        # same cap as cve_hunt.kev
REPORT_EXTENSIONS = {".pdf": "pdf", ".docx": "docx", ".html": "html", ".htm": "html",
                     ".txt": "text", ".md": "text"}
PCAP_EXTENSIONS = {".pcap", ".cap"}
KEV_EXTENSIONS = {".json"}

# ---- sandbox for untrusted parsing ----------------------------------------
WORKER_TIMEOUT_SECONDS = 60                  # wall clock, per tool call
WORKER_CPU_SECONDS = 90                      # RLIMIT_CPU backstop
WORKER_MEMORY_BYTES = 1536 * 1024 * 1024     # RLIMIT_AS for the worker (the pcap sub-sandbox has its own 512 MiB)
WORKER_MAX_OPEN_FILES = 64
PCAP_PARSE_TIMEOUT_SECONDS = 30              # must stay below WORKER_TIMEOUT_SECONDS

# ---- rate limiting --------------------------------------------------------
DEFAULT_CALLS_PER_MINUTE = 30
MAX_CALLS_PER_MINUTE = 600


@dataclass(frozen=True)
class ServerConfig:
    allowed_dirs: tuple[Path, ...] = field(default_factory=tuple)
    calls_per_minute: int = DEFAULT_CALLS_PER_MINUTE
    attck_bundle: Path | None = None
    audit_log: Path | None = None
    sandbox_network: bool = True             # try to drop network access in the worker

    @property
    def file_access_enabled(self) -> bool:
        return bool(self.allowed_dirs)
