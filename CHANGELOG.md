# Changelog

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
