"""
manual_input/schema.py

The common shape every manual-input format (CSV, JSON, STIX2) parses into,
before being handed to builder.py to become an IRDetection. Kept separate
from connectors.base.NormalizedEntity deliberately — manual entry has no
"alert" concept behind it, and decoupling avoids this module depending on
the connectors package for an unrelated feature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Same value-length cap philosophy as the rest of the pipeline: an
# individual IOC value has no legitimate reason to be enormous, and a
# very long string is a low-cost thing to reject outright at parse time
# rather than relying solely on downstream sanitization.
MAX_INDICATOR_VALUE_LEN = 2048
MAX_INDICATORS_PER_BATCH = 10_000


@dataclass
class ManualIndicator:
    indicator_type: str        # e.g. "ip", "domain", "sha256" — same vocabulary as ir.builder.ENTITY_TYPE_TO_IR_FIELD
    value: str
    notes: Optional[str] = None
    source_line: Optional[int] = None   # 1-based row/line number, for error reporting back to the analyst


class ManualInputParseError(Exception):
    """Raised for structurally invalid input (bad JSON, bad CSV headers, oversized batch, etc.)."""
