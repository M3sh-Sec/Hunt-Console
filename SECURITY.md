# Security notes - Hunt Console 1.1.0

Audit date: 2026-10-23. Scope: the Python source tree of 1.0.0. The GUI artifact was reviewed but not changed.
Every finding below was reproduced with a script on the 1.0.0 code before it was fixed, except where stated.
`tests/test_security_regressions.py` holds one regression test per finding. Those tests were also run against the
1.0.0 code to confirm that they fail there (6 fail, as expected; see "How this was verified").

## Fixed in 1.1.0

| ID | Severity | Where | Problem | Fix |
|----|----------|-------|---------|-----|
| VULN-01 | High | `connectors/sentinel.py` | The table allow-list only inspected the first pipe segment. `union AuditLogs, ...`, `... \| union X`, `let`, `union *` all passed, so any table the service principal could read was reachable. | `connectors/query_guard.py`: default-deny. One statement, must start with an allow-listed table, strings and comments stripped first, join/union/let/externaldata/evaluate/find/search/database/cluster and similar are rejected. |
| VULN-02 | High | `backends/ms_kql.py`, `backends/splunk_spl.py` | Values for numeric fields were not validated. A port of `443 or 1==1` rendered as-is, and in SPL `0 \| delete index=main` rendered with a live pipe (`GREATER_THAN` / `LESS_THAN` were not sanitised at all). Report, PCAP and alert content can reach these values. | `render_number()` accepts only real numbers or all-digit strings; anything else is rejected and reported as a caveat on an empty result. Nothing is dropped silently. |
| VULN-03 | Medium | `report_parser/format_loaders.py` | PDF FlateDecode bomb: `zlib.decompress(bufsize=...)` does not cap output; the size check ran after the memory was allocated (206 MiB peak measured for a 96 MiB payload). | Streaming `decompressobj().decompress(data, max_length)`. |
| VULN-04 | Medium | `connectors/*.py` | Alert, detection and incident IDs were placed into a management-API URL path. `../../providers/...` changed the resource requested with the service principal's token. | `validate_identifier()` allow-list on every ID before use. |
| VULN-05 | Low | `connectors/sentinel.py` | The `Tactics` column (tactic names such as `Execution`) was stored as `mitre_techniques`. | Reads `Techniques`; only well-formed `T####[.###]` IDs are kept. Same filter for CrowdStrike. |
| VULN-06 | Low | `cli.py` | Untrusted report titles and descriptions were written raw into the Markdown hunt package (HTML, links, headings, fence breakout). | `md_escape()` on untrusted fields; code fences cannot be closed by query text; file names restricted to `[A-Za-z0-9_.-]`. |
| VULN-07 | Medium | `report_parser/url_fetcher.py` | DNS rebinding: the host was validated with one lookup and fetched with another, so a hostname could pass the check and then resolve to an internal address. | The connection is pinned to an address that is checked at connect time. TLS verification and the hostname check stay on. |
| VULN-08 | Medium | `parser/sandbox.py` | The parent joined the child before reading its result. A result larger than the pipe buffer blocked the child, so valid large captures were reported as timeouts (measured: 20,000 packets timed out). | Read the result first, then join; the timeout now applies to the read. |
| HARDEN-01 | Low | `report_parser/format_loaders.py` | DOCX zip-bomb check trusted the declared sizes in the zip header. | Bounded read of the actual stream. **No dedicated regression test** (a lying zip header was not crafted). |
| HARDEN-02 | Low | `report_parser/ioc_extraction.py` | CVE regex stopped at 7 digits. | Allows 4-19 digits. |
| HARDEN-03 | Low | `connectors/crowdstrike_falcon.py` | Only the repo name was checked. | `enforce_lql_scope()` rejects join/repo/view/readFile and similar. |

## Dependency review

| Package | Finding | Action |
|---------|---------|--------|
| requests | CVE-2026-25645: predictable temp file name in `extract_zipped_paths()`; local attacker with write access to the temp dir; CVSS 4.4. Fixed in 2.33.0. | Optional-extra floor raised to `requests>=2.33.0`. This code does not call `extract_zipped_paths()`, so practical exposure is low. |
| setuptools | CVE-2026-59890: Unicode normalisation bypass of MANIFEST.in exclusions when **building source distributions**; fixed in 83.0.0. | Affects people who build sdists, not people who install. The build requirement was left at `>=68` so `--offline` installs keep working; upgrade setuptools in any environment where you build releases. |
| msal | No advisory found in the searches run. That is not proof there is none. | Unchanged (`>=1.28`). Run `pip-audit` yourself. |

Sources: the GitLab advisory database entry for CVE-2026-25645 and the Vulert entry for CVE-2026-59890, read on 2026-10-23.

## Not covered (be aware)

- **No live-tenant testing.** Connectors were exercised only with mocks.
- **`pytest` itself was never run.** It could not be installed here. All 135 tests passed under a small stand-in runner that supports the pytest features used. Run the real thing in CI.
- **No `bandit` or `pip-audit` run** (no package index access from the audit environment).
- **No dependency hash pinning or lock file.** The installers fetch the newest allowed versions at install time. In sensitive environments, install from a reviewed internal mirror.
- **The Windows installer has still never been executed.**
- **The GUI** quotes every value and strips quote characters, so it is not affected by VULN-02. It does not yet have the CVE feature.
- **Stage 2 LLM extraction is not built.** If you add it, treat model output as untrusted input.
- The KQL guard is a deny-list plus a shape check, not a parser. Keep the service principal on the least-privilege read roles; the guard is a second layer.

## How this was verified

1. Each finding was reproduced with a standalone script on the 1.0.0 code.
2. Fixes were applied, then the same scripts were re-run.
3. `tests/test_security_regressions.py` was run on 1.1.0 (all pass) and on 1.0.0 (the connector, backend, loader, fetcher, sandbox and Markdown tests fail; the tests that exercise only the new guard module pass trivially there).
4. The full suite (135 tests) passed under the stand-in runner.

## Reporting

Report suspected vulnerabilities privately to the repository owner. Do not open a public issue with a working exploit.
