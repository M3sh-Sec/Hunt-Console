# Changelog

## 1.2.2 - 2026-11-24
Security release (weekly review). See SECURITY.md, "1.2.2".
- Fixed VULN-14: IOC extraction checked "is this domain inside a URL" against every URL (quadratic; 104 KB of URLs took 1.6 s, 5 MB hours).
- Fixed VULN-15: the STIX pattern comparison regex was quadratic on long runs of path characters (40 KB -> 11 s).
- Fixed VULN-16: the report-URL fetcher's address filter allowed carrier-grade-NAT / shared space (100.64.0.0/10, e.g. Tailscale), IPv6 site-local and NAT64 addresses.
- Fixed VULN-17 (Low): an oversized CSV field and a blank KEV vendor/product raised unhandled exceptions (CLI traceback).
- Added regression tests for each. No behaviour change for well-formed input.

## 1.2.1 - 2026-11-17
Security release (weekly review). See SECURITY.md, "1.2.1".
- Fixed VULN-09: KQL/LogScale query guard could be bypassed with a verbatim string (`@"\"`) or a quote inside a `//` comment.
- Fixed VULN-10: PDF loader had no total decompression/text budget across streams (1.1 MB file -> 118 s, 227 M characters).
- Fixed VULN-11: untrusted report/alert titles reached the hunt package unescaped through the per-query explanation summary and caveats.
- Fixed VULN-12: domain and e-mail IOC regexes were quadratic (ReDoS) on dotted input.
- Fixed VULN-13: PDF stream scanning was quadratic on repeated `stream` keywords.
- Added regression tests for each. No behaviour change for well-formed input.

## 1.2.0 - 2026-10-29
- New: `huntconsole-mcp`, a local MCP server (stdio) exposing five read-only, offline tools:
  `hunt_from_indicators`, `hunt_from_report_text`, `hunt_cve_exposure`, `lookup_attack_technique`, and
  `hunt_from_file` (only with `--allow-dir`). See `mcp_server/README.md` and `mcp_server/SECURITY.md`.
- MCP protocol versions 2026-07-28, 2025-11-25, 2025-06-18 and 2025-03-26. Standard library only: no new dependencies.
- Tool catalog SHA-256: `3dce0af2…2407fd` without file access, `3f59a594…a8f1b` with `--allow-dir`.
- New: `mcp_server/Dockerfile` (digest-pinned base image, non-root, nothing downloaded at build).
- New: `cve_hunt.kev.parse_kev_json_text()` and `explanation.mitre_lookup.activate_lookup()` (used by the server).
- Installers now ship 1.2.0 and install the `huntconsole-mcp` command. `installers/build_payloads.py` rebuilds
  the embedded payloads.

## 1.1.0 - 2026-10-23
Security release. See SECURITY.md.
- Fixed VULN-01..08 and three hardening items; added `tests/test_security_regressions.py`.
- New: `huntconsole cve` (CVE exposure hunts, optional CISA KEV enrichment from a file you supply).
- New: reports that mention CVE ids now produce a Defender Vulnerability Management exposure query.
- Changed: rejected values are now reported as caveats instead of silently producing no query.
- Changed: optional `requests` floor is now 2.33.0.
- Packaging: build artefacts (`build/`, `*.egg-info`) are no longer shipped in the source archive.

## 1.0.0
Initial release.
