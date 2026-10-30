# Hunt Console MCP server

Lets an MCP client (Claude Desktop, Claude Code, an IDE) use Hunt Console as tools. You hand Claude
IOCs, ATT&CK technique IDs, report text, a report file, a PCAP or a CVE list, and get back KQL, SPL and
Sigma hunting queries with explanations.

Every tool is **read-only and offline**: nothing is executed, saved, or sent to any system. The queries
come back for you to review and run yourself. The security design is in [SECURITY.md](SECURITY.md).

## Tools

| Tool | What it does | Needs file access |
|---|---|---|
| `hunt_from_indicators` | Queries from IOCs (IP, domain, URL, hashes, user, host and similar) and/or ATT&CK IDs | No |
| `hunt_from_report_text` | Extracts IOCs, CVEs and ATT&CK IDs from pasted report text (defanged indicators are handled), then generates queries | No |
| `hunt_cve_exposure` | Exposure-hunt queries for CVE IDs, optionally enriched from a CISA KEV JSON file | Only for the KEV file |
| `lookup_attack_technique` | Name, tactic and description of an ATT&CK technique | No |
| `hunt_from_file` | Queries from a report (`.pdf .docx .html .htm .txt .md`) or a classic PCAP (`.pcap .cap`) | Yes |

`hunt_from_file` and the `kev_path` argument only appear when you start the server with `--allow-dir`.

## Install

The server is part of the `huntconsole` package and has no extra dependencies. Installing Hunt Console
1.2.0 with `installers/install-linux.sh` or `installers/install-windows.cmd` also installs the
`huntconsole-mcp` command:

- Linux/macOS: `~/.huntconsole/bin/huntconsole-mcp` (also linked into `~/.local/bin`)
- Windows: `%USERPROFILE%\.huntconsole\Scripts\huntconsole-mcp.exe` (plus `%USERPROFILE%\bin\huntconsole-mcp.bat`)

Check it:

```bash
huntconsole-mcp --version
huntconsole-mcp --print-tool-catalog      # the exact tool definitions and their SHA-256
```

## Configure it

Use the **absolute path** to the installed binary, so the client never runs a launcher that downloads code.

### Claude Desktop

Settings → Developer → Edit Config, then add (see [examples/claude_desktop_config.json](examples/claude_desktop_config.json)):

```json
{
  "mcpServers": {
    "huntconsole": {
      "command": "/Users/YOU/.huntconsole/bin/huntconsole-mcp",
      "args": ["--allow-dir", "/Users/YOU/ThreatIntel/inbox"]
    }
  }
}
```

Leave out `--allow-dir` entirely if you only paste text and indicators. Restart Claude Desktop afterwards.

### Claude Code

```bash
claude mcp add --scope user huntconsole -- ~/.huntconsole/bin/huntconsole-mcp --allow-dir ~/ThreatIntel/inbox
claude mcp list        # should show huntconsole as Connected
```

Do not commit a project `.mcp.json` that grants `--allow-dir` to a shared folder unless everyone using
the repository should have that access.

### Strongest isolation: container

Build once from the repository root:

```bash
docker build -f mcp_server/Dockerfile -t huntconsole-mcp:1.2.0 .
```

Then use [examples/claude_desktop_config.docker.json](examples/claude_desktop_config.docker.json). It runs the
server with no network, a read-only filesystem, no Linux capabilities, a non-root user, memory and process
limits, and only your chosen folder mounted read-only at `/data`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--allow-dir DIR` | none | Folder the file tools may read. Repeat for more folders. Roots, system folders, your home folder (and any folder containing it) and hidden folders are refused. Relative paths in tool calls resolve against the first folder. |
| `--rate-limit N` | 30 | Tool calls per minute (1–600). |
| `--attck-bundle FILE` | built-in subset | MITRE ATT&CK enterprise STIX bundle for full technique names and descriptions. |
| `--audit-log FILE` | stderr only | Also append audit lines to this file (created owner-only). |
| `--no-sandbox-network-isolation` | off | Do not move parsing workers into an empty network namespace. Only for hosts where that misbehaves. |
| `--allow-root` | off | Permit running as root. Not recommended. |
| `--print-tool-catalog` | | Print the tool catalog JSON and SHA-256, then exit. |

## Using it well

- **Keep per-call approval on** in your client. Every tool is read-only, but approval is how you stay in control of what is sent where.
- **Review before you run.** Results always say `"reviewed": false`. Check the extracted indicators and the queries before using them in your SIEM or EDR.
- **Check the catalog after upgrades.** The startup log line and `--print-tool-catalog` show the catalog SHA-256. If it changes, read the CHANGELOG before approving the new tools.
- **Logs:** each tool call writes one JSON line to stderr (your client keeps these in its MCP server log). Argument contents are never logged.

## Troubleshooting

- **Server does not appear:** check that the `command` path exists and is absolute, and that the JSON is valid. Run the command yourself with `--version`.
- **"refusing to run as root":** run the client as a normal user, or use the container.
- **"file not found, or not readable through this server":** the path is outside every `--allow-dir` folder, goes through a symlink pointing outside, is hidden, has several hard links, or does not exist. The message is the same in every case on purpose.
- **Startup note about network namespaces:** your OS does not allow unprivileged user namespaces (common inside containers). Parsing still works. Use the container with `--network=none` for enforced isolation.

## Protocol support

stdio transport. Protocol versions 2026-07-28 (stateless, `server/discover`) and the initialize-based
2025-11-25, 2025-06-18 and 2025-03-26. Tested with Claude Code as a client.
