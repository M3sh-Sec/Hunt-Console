# Hunt Console MCP server: security design and checklist

Version 1.2.0, 2026-10-29. Revised after an independent review; its findings and fixes are listed at the end.

This document maps each MCP security recommendation to how this server meets it.
The sources are:

- MCP Security Best Practices, spec version 2026-07-28 (`modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices`)
- MCP Local Server Security guide, 2026-07-28 (`.../tutorials/security/local-server-security`)
- MCP specification 2026-07-28: base protocol, versioning, stdio transport, JSON Schema usage
- 2026 advisories against the official MCP Python SDK (listed at the end)

## What the server is

- A **local stdio server**. The MCP client starts it as a child process and talks over stdin/stdout.
- It turns IOCs, ATT&CK technique IDs, report text, report files, PCAPs and CVE IDs into KQL, SPL and Sigma queries with explanations.
- **Every tool is read-only and offline.** No tool writes a file, opens a network connection, or talks to a SIEM or EDR. The live connectors and the report-URL fetcher in the CLI are deliberately **not** exposed.
- **Standard library only.** No third-party package runs in the server process.

## Recommendations that apply, and how they are met

### Transport and local-server compromise

| Recommendation | How it is met |
|---|---|
| Local servers SHOULD use stdio to limit access to the MCP client | stdio only. The server never opens a listening socket, so other local processes and web pages (DNS rebinding) cannot reach it. |
| HTTP transports need auth tokens / IPC restrictions | Not applicable: there is no HTTP transport in this code. |
| stdout MUST carry only MCP messages; logs go to stderr | At startup the real stdout is duplicated to a private descriptor and descriptor 1 is pointed at stderr. A stray `print()` in any library or child process lands in stderr. Tested (`test_stdout_carries_only_protocol_messages`). |
| Messages MUST NOT contain embedded newlines | Messages are serialised with `ensure_ascii`, so newlines are always escaped. |
| Exit promptly when stdin closes | A reader thread watches stdin even while a call runs. On EOF it stops the running worker and the process exits (measured: 0.1 s during a long call). |
| Server MUST NOT send requests to the client | It never does. No sampling, elicitation or roots, so the server cannot ask the client to act for it. |
| Servers SHOULD stop work on a cancelled request and MUST NOT reply to it | `notifications/cancelled` is read while a call runs. It kills the worker, and no response is sent for that request. A request cancelled before it starts is dropped. |

### Provenance and dependencies (Local Server Security: "check provenance", "compromised dependency")

| Recommendation | How it is met |
|---|---|
| Know what you are running; prefer readable source from an identifiable publisher | All code is in this repository. There is no dependency tree to audit: the server imports only the Python standard library and Hunt Console's own modules. |
| Pin versions; launchers like `npx`/`uvx` resolve transitive deps fresh | Nothing is resolved at launch. The installers install a fixed, embedded wheel with `--no-index --no-deps`. The client config points at that installed binary, not at a launcher that fetches code. |
| Pin container images by digest | `mcp_server/Dockerfile` uses `python:3.13-slim@sha256:2d44738e…` and installs nothing at build time. |
| Provenance metadata (signatures, attestations, SBOM) | Partly. The installer payload is built reproducibly by `installers/build_payloads.py`, which prints the wheel's SHA-256, so anyone can rebuild and compare. Artifacts are **not signed** and no SBOM file is published; with zero dependencies the SBOM would list only this package and the Python standard library. |
| SDK vulnerabilities | The official Python SDK had six advisories in 2026 (below). This server does not use the SDK, so none of them apply. If you ever switch to the SDK, require `mcp>=1.30.0` (1.x) or `>=2.2.0` (2.x), which fixes all six. |

### Isolation (Local Server Security: "run servers in an isolated environment")

| Recommendation | How it is met |
|---|---|
| Run in a container with nothing mounted beyond what is needed | Provided: `mcp_server/Dockerfile` and `examples/claude_desktop_config.docker.json`. The image runs as uid 10001 with read-only code and no login shell for that user (the base image itself still contains `/bin/sh`). The example config uses `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=2g` and mounts one folder read-only. |
| Process sandboxing for risky work | Even outside a container, all parsing of untrusted input runs in a fresh `spawn`ed worker per call. The worker gets `/dev/null` as stdin before any parsing code runs, has a 60 s wall-clock timeout (killed by the parent), `RLIMIT_AS` 1.5 GiB, `RLIMIT_CPU` 90 s, `RLIMIT_FSIZE` 1 MiB, `RLIMIT_CORE` 0 and `RLIMIT_NOFILE` 64, and on Linux dies with the server (`PR_SET_PDEATHSIG`). On Linux it also moves into a new user and network namespace with only a loopback interface, so it cannot make TCP/UDP connections. PCAPs get a second, inner sandbox (512 MiB, 30 s). **Limits of this sandbox:** the worker can still read files the user can read, connect to filesystem Unix sockets (for example a Docker or SSH-agent socket), write small files and start programs. On a bare host it contains crashes and resource exhaustion; it is not a boundary against a parser exploit. The container is that boundary. |
| Minimal privileges | The server refuses to start as root unless `--allow-root` is passed. It sets `umask 077`. |

### Credentials

| Recommendation | How it is met |
|---|---|
| Pass secrets per server; scope narrowly; keep them out of config files | The server needs **no credentials at all** and takes no configuration from environment variables (it reads none for configuration; the home folder for the `--allow-dir` check comes from the password database). It holds no tokens that could leak. |
| stdio servers SHOULD NOT use the HTTP authorization spec and take credentials from the environment | Nothing to authorise. If a live-connector tool is added later, it must take a narrowly scoped, per-server credential and must never accept or pass through a token from the client. |

### Filesystem access

| Recommendation | How it is met |
|---|---|
| Grant the narrowest root; never the home folder | File access is **off by default**. `--allow-dir` grants specific folders. Refused at startup: filesystem roots, system folders (`/etc`, `/tmp`, `/home`, `/Users`, `/proc`, `/var` and similar), the home folder, any folder that contains it, and hidden folders. The home folder is looked up in the password database, not `$HOME`, so the environment cannot hide it. |
| Prefer read-only | The server never writes to any folder. In the container the folder is mounted `readonly`. |
| Allow-lists are cooperative; enforce with isolation | Enforced in code and, with the container, by the mount. In code: paths are resolved with symlinks followed and must stay inside an allowed folder, so `..`, symlinks and junctions are refused. On POSIX the file is then opened one component at a time from a descriptor held on the allowed folder, with `O_NOFOLLOW` at every step, so swapping a folder for a symlink between check and open fails (this closes a race the review reproduced). Files with more than one hard link are refused. Hidden files (`.env`, `.git`, `.ssh`) are refused. Only needed extensions are accepted, sizes are capped, and FIFOs and devices are refused. Missing, outside, hidden and multiply-linked files all get the same error, so the server is not an existence oracle. On Windows there is no `openat`; the server compares the opened file's identity with the checked one instead, which is weaker. |

### Network egress

| Recommendation | How it is met |
|---|---|
| Deny network where none is needed | The server needs no network. Workers are put in a network namespace with no external interface where the OS allows it; filesystem Unix sockets remain reachable from a bare-host worker. The container example uses `--network=none` and mounts nothing but the data folder, which covers both the parent process and Unix sockets. |

### Tool definitions (Local Server Security: "treat tool definitions as untrusted input"; tool poisoning, rug pulls)

| Recommendation | How it is met |
|---|---|
| Descriptions contain only what the tool does | Short, static descriptions. A test rejects instruction-like phrases (`ignore`, `system prompt`, `must call`, HTML, and similar). |
| Definitions should not change silently | The catalog is static and returned in a fixed order. Its SHA-256 is printed at startup and by `--print-tool-catalog`, and is pinned in the test suite, so any change is deliberate and visible. `listChanged` is `false`. |
| Keep the roster small | Four tools, or five with file access. File tools are not listed at all unless `--allow-dir` is set. |
| Accurate annotations | Every tool: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`. These are true of the implementation. |

### Input validation and output handling

| Recommendation | How it is met |
|---|---|
| Validate all tool inputs | Every argument object is validated server-side against the published `inputSchema` before any work: types, enums, lengths, counts, `^…$` formats (full-match, so a trailing newline is rejected), `additionalProperties: false` everywhere, and no unpaired surrogates in any string. Invalid input returns a tool error (`isError: true`), as SEP-1303 asks. |
| Validate outputs against `outputSchema` | Every result is checked against the tool's `outputSchema` before it is returned. A mismatch becomes a tool error. |
| No network `$ref`; bound schema complexity | The validator implements no `$ref` and no composition keywords, and refuses unknown keywords. |
| Bound resource use | Request line ≤ 4 MiB, JSON depth ≤ 64, batches rejected, report text ≤ 1 M characters, ≤ 2,000 indicators, ≤ 500 CVEs, report file ≤ 50 MiB, PCAP ≤ 100 MiB, worker result ≤ 2 MiB. |
| Rate limiting | Token bucket, 30 tool calls per minute by default (`--rate-limit`, 1–600). Over-limit calls get a tool error with a retry time. |
| Tool output is a prompt-injection channel | Results are built only from structured fields: indicator values, technique IDs, generated query text and the title. Report prose, report snippets and parser notes are not returned. **Indicator values themselves come from the input**, so a URL, domain or file name can still carry attacker-chosen words; the server cannot remove that without changing the indicator. Strings are stripped of control characters and of all invisible Unicode: format characters (bidi controls, zero-width, tag characters U+E0000–E007F), private-use and unassigned code points, line/paragraph separators, invisible fillers and variation selectors. Every result carries `"reviewed": false` and a notice that values are data, not instructions. |
| Errors must not leak internals | Internal errors return a generic message only; an unexpected exception inside a tool is still audited and returned as a tool error. Parser exceptions become a generic message with the exception type. Tracebacks go to stderr only. |

### Consent, review and audit

| Recommendation | How it is met |
|---|---|
| Hosts must get consent before invoking tools | That is the client's job. Leave per-call approval on in your client. The read-only annotations let the client show accurately what each tool does. |
| Users keep control of actions | The server takes no actions. Generated queries are returned for review and never executed. |
| Keep an audit trail | One JSON line per tool call to stderr (which clients keep in their MCP logs), plus an optional `--audit-log` file created `0600`, append-only and opened with `O_NOFOLLOW`. Each line has the time, tool, outcome (ok, tool_error, rate_limited, cancelled, internal_error), duration, argument size and a SHA-256 prefix, and for the two tools that take a file path, that path. No other argument contents are logged. Startup logs the version, catalog hash, allowed folders and sandbox status. |

## Recommendations that do not apply, and why

These sections of the best-practices page are about HTTP servers, OAuth, or MCP clients. This server has no HTTP listener, no OAuth, and is not a client.

| Recommendation | Why it does not apply |
|---|---|
| Confused deputy: per-client consent, redirect URI and `state` validation, consent cookies | No OAuth proxy and no third-party API calls. |
| Token passthrough and audience validation | The server accepts and forwards no tokens. |
| SSRF during OAuth discovery | The server fetches no URLs. The CLI's report-URL fetcher is not exposed through MCP. |
| State handle hijacking | The server keeps no cross-call state and mints no handles. |
| OAuth authorization URL validation, CSP, `stdio` proxy escalation | Client-side and proxy concerns. The server does not open URLs or spawn other servers. |
| Mix-up attacks, localhost redirect impersonation, CIMD trust policies | Authorization-server and client concerns. |
| Scope minimization | No OAuth scopes. The equivalent here is least privilege by flags: no file access unless granted, no network, no write tools. |
| Session hijacking (2025-11-25) | No sessions. stdio is bound to one client process. |

## Known limits (be aware)

- **The container image was not built or run during development.** There was no Docker daemon in the build environment. Build it and run `--print-tool-catalog` through it once before relying on it.
- **Windows:** `RLIMIT_*` and network namespaces do not exist there, so only the wall-clock timeout protects the parsing step. Use the container (Docker Desktop) or WSL for enforced isolation. The Windows path has not been executed.
- **Containers:** Docker's default seccomp profile blocks user namespaces, so inside the container the worker network namespace is not created. `--network=none` covers that instead. The startup log reports which applies.
- **Human review cannot be forced by the server.** Results say `"reviewed": false` and the client's approval prompt is the consent step. Elicitation-based confirmation is not implemented.
- **Calls run one at a time.** A second request waits for the first (at most 60 s).
- **multiprocessing's resource tracker:** Python starts one small helper process the first time a worker is spawned. It inherits the server's stdin but never reads it and never parses input.
- **Client-side protections are the host's job:** consent dialogs, re-prompting when tool definitions change, and sandboxing of the server process.
- **The protocol layer is this project's own code.** It is tested against the spec rules and with Claude Code as a real client, but it has not been tested against every MCP client.

## Independent review (2026-10-29) and fixes

A separate reviewer audited this server against the guidance above and reproduced each finding with a script. All were fixed in 1.2.0 before release, and regression tests were added.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | Medium | Check-then-open race: swapping a folder for a symlink let a writer inside the allowed folder read a file outside it (4,300 of ~185,000 attempts). | Component-by-component `openat` with `O_NOFOLLOW` from a descriptor on the allowed folder. Re-run: 0 outside reads. |
| 2 | Medium | Worker inherited the server's stdin and could read the next client message; sandbox claims overstated (Unix sockets, file reads). | Worker stdin is `/dev/null` before any parsing; `PR_SET_PDEATHSIG`; claims corrected above. |
| 3 | Medium | Unicode tag characters, U+2028 and other invisible characters survived into output; claim about raw text overstated. | Strip all format, private-use, unassigned and separator characters plus invisible fillers; claim corrected. |
| 4 | Medium | `--allow-dir /home` (a parent of home) and `$HOME` spoofing bypassed the home-folder refusal. | Refuse system folders and any folder containing the home folder from the password database. |
| 5 | Low | `path` argument logged for tools that do not take one. | Log only for tools whose schema defines the path. |
| 6 | Low | Unexpected exceptions skipped the audit log. | Catch-all: audited, returned as a tool error. |
| 7 | Low | Unpaired surrogates passed through to output. | Rejected during input validation. |
| 8 | Low | Slow exit when stdin closed during a call (up to 60 s). | Reader thread; worker stopped on EOF. Re-run: 0.1 s. |
| 9 | Low | Workers outlived a killed server. | `PR_SET_PDEATHSIG`. Re-run: worker gone immediately. |
| 10 | Low | Version error listed the rejected legacy version as supported. | Error lists only versions usable in `_meta`. |
| 11 | Low | Hard links bypassed confinement. | Files with more than one link are refused. |
| 12 | Low | "No shell" claim for the container was inaccurate. | Claim corrected. |
| 13 | Info | Existence oracle for hidden files, `^a|b$` anchoring, duplicated pretty-printed output. | Same error for hidden and missing files; anchored patterns wrapped in a group; compact JSON in `content`. |

Not changed: cancellation of work that has not started is best-effort; the worker sandbox on a bare host is not an exploit boundary (use the container).

## Python SDK advisories considered (2026)

All fixed in `mcp` 1.30.0 / 2.2.0. None affect this server because it does not use the SDK.

| CVE | Issue |
|---|---|
| CVE-2026-52869 | Session-ID-only routing let another authenticated client inject messages (SSE, stateful Streamable HTTP). |
| CVE-2026-52870 | Experimental task handlers did not check task ownership. |
| CVE-2026-59950 | Deprecated WebSocket transport did not check Host/Origin. |
| CVE-2026-59951 | Unbounded session table in stateful Streamable HTTP (DoS). |
| CVE-2026-116684 | Bearer auth did not check token audience (`validate_token_resource` must be enabled). |
| CVE-2026-116686 | Client-side `outputSchema` validation dereferenced external `$ref` (SSRF, DoS). |

## Reporting

Report suspected vulnerabilities privately to the repository owner. Do not open a public issue with a working exploit.
