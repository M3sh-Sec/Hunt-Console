"""
mcp_server/__main__.py

Entry point: `huntconsole-mcp` (or `python -m mcp_server`).

The MCP client starts this process and talks to it over stdin/stdout. All
permissions are set here, by the operator, on the command line in the client
config:

  --allow-dir DIR          let the file tools read this folder (repeatable; read-only)
  --rate-limit N           tool calls per minute (default 30)
  --attck-bundle FILE      MITRE ATT&CK enterprise STIX bundle for richer technique context
  --audit-log FILE         also append audit lines to FILE (created owner-only)
  --no-sandbox-network-isolation
                           do not move parsing workers into an empty network namespace
  --print-tool-catalog     print the tool catalog and its SHA-256, then exit
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    from . import SERVER_VERSION, config

    p = argparse.ArgumentParser(prog="huntconsole-mcp",
                                description="Hunt Console MCP server (stdio). Read-only and offline.")
    p.add_argument("--version", action="version", version=f"huntconsole-mcp {SERVER_VERSION}")
    p.add_argument("--allow-dir", action="append", default=[], metavar="DIR",
                   help="folder the file tools may read (repeatable). Without it, no file can be read.")
    p.add_argument("--rate-limit", type=int, default=config.DEFAULT_CALLS_PER_MINUTE, metavar="N",
                   help=f"tool calls per minute (1-{config.MAX_CALLS_PER_MINUTE}, default "
                        f"{config.DEFAULT_CALLS_PER_MINUTE})")
    p.add_argument("--attck-bundle", metavar="FILE", help="MITRE ATT&CK STIX 2.1 bundle (enterprise-attack.json)")
    p.add_argument("--audit-log", metavar="FILE", help="append audit lines to this file as well as stderr")
    p.add_argument("--no-sandbox-network-isolation", action="store_true",
                   help="do not try to remove network access from parsing workers")
    p.add_argument("--allow-root", action="store_true", help="permit running as root (not recommended)")
    p.add_argument("--print-tool-catalog", action="store_true",
                   help="print the tool catalog JSON and its SHA-256 to stdout, then exit")
    return p


def main(argv: list[str] | None = None) -> int:
    # Children inherit these: no .pyc writes from workers, unbuffered stderr for timely logs.
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONUNBUFFERED"] = "1"
    sys.dont_write_bytecode = True
    os.umask(0o077)
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                        format="huntconsole-mcp %(levelname)s %(name)s: %(message)s")

    from . import SERVER_VERSION, config
    from .audit import AuditLog, RateLimiter
    from .config import ServerConfig
    from .paths import validate_allowed_dirs
    from .tools import ToolState, catalog_sha256, list_tools

    args = build_parser().parse_args(argv)

    def fail(message: str) -> int:
        sys.stderr.write(f"huntconsole-mcp: {message}\n")
        return 2

    if hasattr(os, "geteuid") and os.geteuid() == 0 and not args.allow_root:
        return fail("refusing to run as root. Run as a normal user, or in the provided container image.")
    if not 1 <= args.rate_limit <= config.MAX_CALLS_PER_MINUTE:
        return fail(f"--rate-limit must be between 1 and {config.MAX_CALLS_PER_MINUTE}")
    try:
        allowed = validate_allowed_dirs(args.allow_dir)
    except ValueError as exc:
        return fail(str(exc))

    cfg = ServerConfig(
        allowed_dirs=allowed,
        calls_per_minute=args.rate_limit,
        attck_bundle=Path(args.attck_bundle).expanduser().resolve() if args.attck_bundle else None,
        audit_log=Path(args.audit_log).expanduser() if args.audit_log else None,
        sandbox_network=not args.no_sandbox_network_isolation,
    )

    if args.print_tool_catalog:
        print(json.dumps({"sha256": catalog_sha256(cfg), "tools": list_tools(cfg)}, indent=2))
        return 0

    # From here on, stdout belongs to the protocol only.
    from .protocol import McpServer, claim_stdout, serve
    from .sandbox import SandboxError, probe_network_isolation, run_job

    out = claim_stdout()

    technique_rows = None
    if cfg.attck_bundle is not None:
        try:
            loaded = run_job("attck_bundle", {"path": str(cfg.attck_bundle)}, drop_network=cfg.sandbox_network,
                             timeout=120)
        except SandboxError as exc:
            return fail(f"could not load --attck-bundle: {exc}")
        technique_rows = loaded["rows"]
        from explanation.mitre_lookup import TechniqueInfo, activate_lookup

        activate_lookup({r[0]: TechniqueInfo(*r) for r in technique_rows},
                        "ATT&CK bundle configured by the operator")

    try:
        audit = AuditLog(cfg.audit_log)
    except OSError as exc:
        return fail(f"cannot open --audit-log: {exc.strerror}")

    net_isolated = probe_network_isolation() if cfg.sandbox_network else False
    audit.event(
        event="startup", version=SERVER_VERSION, transport="stdio",
        tool_catalog_sha256=catalog_sha256(cfg),
        file_access=[str(d) for d in cfg.allowed_dirs] or "disabled",
        rate_limit_per_minute=cfg.calls_per_minute,
        attck_techniques=len(technique_rows) if technique_rows else "built-in subset",
        worker_network_isolation=net_isolated,
    )
    if cfg.sandbox_network and not net_isolated:
        sys.stderr.write("huntconsole-mcp: note: parsing workers could not be moved into an empty network "
                         "namespace on this system. They make no network calls, but for enforced isolation "
                         "run the server in the container image with --network=none.\n")

    server = McpServer(ToolState(cfg, technique_rows), audit, RateLimiter(cfg.calls_per_minute))
    try:
        serve(server, sys.stdin.buffer, out)
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        audit.event(event="shutdown")
        audit.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
