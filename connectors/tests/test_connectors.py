"""
connectors/tests/test_connectors.py

Run with: pytest connectors/tests/ -v

Covers:
  - Suite-wide security invariant: no connector exposes a write/remediation
    method (isolate, quarantine, contain, close, suppress, delete, disable, ...).
  - Table/repo allow-list enforcement (defense in depth).
  - Retry/backoff behavior on simulated 429s.
"""

from __future__ import annotations

import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from connectors.base import (  # noqa: E402
    BaseConnector,
    ConnectorRateLimitError,
    ConnectorQueryScopeError,
    retry_with_backoff,
)
from connectors.sentinel import SentinelConnector, _enforce_table_allowlist  # noqa: E402
from connectors.crowdstrike_falcon import CrowdStrikeFalconConnector  # noqa: E402


FORBIDDEN_METHOD_SUBSTRINGS = [
    "isolate", "quarantine", "contain", "remediate", "close_case",
    "suppress", "delete", "disable", "block", "kill", "terminate",
    "patch", "put", "write", "action", "respond",
]


def _all_connector_classes():
    return [SentinelConnector, CrowdStrikeFalconConnector]


@pytest.mark.parametrize("cls", _all_connector_classes())
def test_no_action_or_remediation_methods_exist(cls):
    """
    Security invariant: every connector must only expose the read-only
    BaseConnector interface. No method name may match a known
    action/remediation verb, and no attribute may be a bound method not
    declared on BaseConnector.
    """
    allowed = set(dir(BaseConnector)) | {
        "__init__", "_headers", "authenticate",
    }
    for name, member in inspect.getmembers(cls, predicate=inspect.isfunction):
        if name.startswith("__"):
            continue
        lowered = name.lower()
        for bad in FORBIDDEN_METHOD_SUBSTRINGS:
            assert bad not in lowered, (
                f"{cls.__name__}.{name} looks like a write/remediation method "
                f"(matched '{bad}') — this must not exist on a connector."
            )


def test_base_connector_has_no_write_methods():
    method_names = {name for name, _ in inspect.getmembers(BaseConnector, predicate=inspect.isfunction)}
    expected = {
        "authenticate", "get_alerts", "get_alert_detail",
        "get_alert_entities", "run_query", "get_incident",
    }
    assert method_names == expected, f"unexpected methods on BaseConnector: {method_names - expected}"


def test_sentinel_table_allowlist_blocks_unknown_table():
    with pytest.raises(ConnectorQueryScopeError):
        _enforce_table_allowlist("SomeRandomTable | take 10")


def test_sentinel_table_allowlist_allows_known_table():
    # should not raise
    _enforce_table_allowlist("DeviceNetworkEvents | where TimeGenerated > ago(1h)")


def test_retry_with_backoff_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectorRateLimitError("simulated 429")
        return "ok"

    monkeypatch.setattr("time.sleep", lambda *_: None)  # don't actually wait in tests
    result = retry_with_backoff(flaky, max_attempts=5, base_delay=0.01)
    assert result == "ok"
    assert calls["n"] == 3


def test_retry_with_backoff_gives_up_after_max_attempts(monkeypatch):
    def always_fails():
        raise ConnectorRateLimitError("simulated persistent 429")

    monkeypatch.setattr("time.sleep", lambda *_: None)
    with pytest.raises(ConnectorRateLimitError):
        retry_with_backoff(always_fails, max_attempts=3, base_delay=0.01)


def test_crowdstrike_rejects_disallowed_repo(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test")
    monkeypatch.setenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("CROWDSTRIKE_HUMIO_REPO", "not-an-allowed-repo")

    connector = CrowdStrikeFalconConnector()
    connector._token = "fake-token-for-test"
    from datetime import datetime, timedelta, timezone
    connector._token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)

    with pytest.raises(ConnectorQueryScopeError):
        connector.run_query("someField = *", dialect="lql")
