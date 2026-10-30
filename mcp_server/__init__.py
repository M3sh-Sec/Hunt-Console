"""
mcp_server

A local Model Context Protocol (MCP) server for Hunt Console. It lets an MCP
host (Claude Desktop, Claude Code, an IDE) turn IOCs, ATT&CK technique IDs,
threat-report text, report files, PCAPs and CVE lists into KQL, SPL and Sigma
hunting queries with explanations.

Security posture (details in mcp_server/SECURITY.md):
  * stdio transport only. The server never opens a listening socket.
  * Standard library only. No third-party code runs in this process.
  * Every tool is read-only and offline: nothing is written to disk, no
    network request is made, nothing is sent to a SIEM or EDR.
  * File access is off unless the operator passes --allow-dir.
  * Untrusted input is parsed in a short-lived child process with a wall-clock
    timeout, CPU, memory and file-size limits, and (where the OS allows) no
    network namespace.
"""

SERVER_NAME = "huntconsole"
SERVER_TITLE = "Hunt Console"
SERVER_VERSION = "1.2.0"
