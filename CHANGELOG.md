# Changelog

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
