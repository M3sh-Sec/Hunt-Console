# Hunt Console MCP server: security design and checklist

Version 1.2.0, 2026-10-28.

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
| Exit promptly when stdin closes | The read loop returns on EOF and the process exits. |
| Server MUST NOT send requests to the client | It never does. No sampling, elicitation or roots, so the server cannot ask the client to act for it. |

### Provenance and dependencies (Local Server Security: "check provenance", "compromised dependency")

| Recommendation | How it is met |
|---|---|
| Know what you are running; prefer readable source from an identifiable publisher | All code is in this repository. There is no dependency tree to audit: the server imports only the Python standard library and Hunt Console's own modules. |
| Pin versions; launchers like `npx`/`uvx` resolve transitive deps fresh | Nothing is resolved at launch. The installers install a fixed, embedded wheel with `--no-index --no-deps`. The client config points at that installed binary, not at a launcher that fetches code. |
| Pin container images by digest | `mcp_server/Dockerfile` uses `python:3.13-slim@sha256:2d44738e…` and installs nothing at build time. |
| SDK vulnerabilities | The official Python SDK had six advisories in 2026 (below). This server does not use the SDK, so none of them apply. If you ever switch to the SDK, require `mcp>=1.30.0` (1.x) or `>=2.2.0` (2.x), which fixes all six. |

### Isolation (Local Server Security: "run servers in an isolated environment")

| Recommendation | How it is met |
|---|---|
| Run in a container with nothing mounted beyond what is needed | Provided: `mcp_server/Dockerfile` and `examples/claude_desktop_config.docker.json`. The image runs as uid 10001 with read-only code and no shell. The example config uses `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=2g` and mounts one folder read-only. |
| Process sandboxing for risky work | Even outside a container, all parsing of untrusted input runs in a fresh `spawn`ed worker per call. The worker has a 60 s wall-clock timeout (killed by the parent), `RLIMIT_AS` 1.5 GiB, `RLIMIT_CPU` 90 s, `RLIMIT_FSIZE` 1 MiB, `RLIMIT_CORE` 0 and `RLIMIT_NOFILE` 64. On Linux it also moves into a new user and network namespace with no interfaces, so it cannot open a network connection. PCAPs get a second, inner sandbox (512 MiB, 30 s). |
| Minimal privileges | The server refuses to start as root unless `--allow-root` is passed. It sets `umask 077`. |

### Credentials

| Recommendation | How it is met |
|---|---|
| Pass secrets per server; scope narrowly; keep them out of config files | The server needs **no credentials at all** and reads no environment variables for configuration. It holds no tokens that could leak. |
| stdio servers SHOULD NOT use the HTTP authorization spec and take credentials from the environment | Nothing to authorise. If a live-connector tool is added later, it must take a narrowly scoped, per-server credential and must never accept or pass through a token from the client. |

### Filesystem access

| Recommendation | How it is met |
|---|---|
| Grant the narrowest root; never the home folder | File access is **off by default**. `--allow-dir` grants specific folders. Filesystem roots, the whole home folder and hidden folders are refused at startup. |
| Prefer read-only | The server never writes to any folder. In the container the folder is mounted `readonly`. |
| Allow-lists are cooperative; enforce with isolation | Enforced in code and, with the container, by the mount. In code: paths are resolved with symlinks followed and must stay inside an allowed folder, so `..`, symlinks and junctions are refused. Hidden files (`.env`, `.git`, `.ssh`) are refused. Only needed extensions are accepted, sizes are capped, the final component is opened with `O_NOFOLLOW`, FIFOs and devices are refused, and the opened inode must match the checked one. The same error message is returned whether a path outside the root exists or not. |

### Network egress

| Recommendation | How it is met |
|---|---|
| Deny network where none is needed | The server needs no network. Workers are put in an empty network namespace where the OS allows it. The container example uses `--network=none`, which also covers the parent process. |

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
| Validate all tool inputs | Every argument object is validated server-side against the published `inputSchema` before any work: types, enums, lengths, counts, `^…$` formats (full-match, so a trailing newline is rejected) and `additionalProperties: false` everywhere. Invalid input returns a tool error (`isError: true`), as SEP-1303 asks. |
| Validate outputs against `outputSchema` | Every result is checked against the tool's `outputSchema` before it is returned. A mismatch becomes a tool error. |
| No network `$ref`; bound schema complexity | The validator implements no `$ref` and no composition keywords, and refuses unknown keywords. |
| Bound resource use | Request line ≤ 4 MiB, JSON depth ≤ 64, batches rejected, report text ≤ 1 M characters, ≤ 2,000 indicators, ≤ 500 CVEs, report file ≤ 50 MiB, PCAP ≤ 100 MiB, worker result ≤ 2 MiB. |
| Rate limiting | Token bucket, 30 tool calls per minute by default (`--rate-limit`, 1–600). Over-limit calls get a tool error with a retry time. |
| Tool output is a prompt-injection channel | Results are built only from structured fields: indicator values, technique IDs and generated query text. Raw report text, report snippets and parser notes are never returned. Strings are stripped of control characters and invisible Unicode (bidi overrides, zero-width characters) and length-capped. Every result carries `"reviewed": false` and a notice that values are data, not instructions. |
| Errors must not leak internals | Internal errors return `Internal error` only. Parser exceptions become a generic message with the exception type. Tracebacks go to stderr only. |

### Consent, review and audit

| Recommendation | How it is met |
|---|---|
| Hosts must get consent before invoking tools | That is the client's job. Leave per-call approval on in your client. The read-only annotations let the client show accurately what each tool does. |
| Users keep control of actions | The server takes no actions. Generated queries are returned for review and never executed. |
| Keep an audit trail | One JSON line per tool call to stderr (which clients keep in their MCP logs), plus an optional `--audit-log` file created `0600`, append-only and opened with `O_NOFOLLOW`. Each line has the time, tool, outcome, duration, argument size and a SHA-256 prefix, and for file tools the requested path. Argument contents are never logged. Startup logs the version, catalog hash, allowed folders and sandbox status. |

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
- **Cancellation:** calls run one at a time. A `notifications/cancelled` cannot interrupt a running call, which is bounded by the 60 s timeout instead.
- **Client-side protections are the host's job:** consent dialogs, re-prompting when tool definitions change, and sandboxing of the server process.
- **The protocol layer is this project's own code.** It is tested against the spec rules and with Claude Code as a real client, but it has not been tested against every MCP client.

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
