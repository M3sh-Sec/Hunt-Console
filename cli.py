#!/usr/bin/env python3
"""
cli.py

Command-line entry point tying together every input source and query
backend built so far:

  pcap    <file.pcap>                 -> IR -> queries
  manual  --csv/--json/--stix + --ttp -> IR -> queries
  report  <file>  (or --url)          -> IR -> queries
  alert   --platform X --alert-id Y   -> IR -> queries  (requires live connector credentials)

Every subcommand follows the same flow:
  1. Build an IRDetection from the input source.
  2. Print a summary (name, conditions, caveats, MITRE techniques).
  3. Require explicit approval before generating queries (--auto-approve
     skips the interactive prompt for scripted use) — this is the "nothing
     flows to query generation unreviewed" gate from the IR schema, enforced
     here at the CLI boundary. Approving sets detection.reviewed=True.
  4. Render queries for every requested --target platform, validate them,
     generate the structured explanation for each, and write everything to
     --out as individual query files plus one bundled hunt-package Markdown
     report.

Example:
  python3 cli.py manual --json iocs.json --ttp T1071.001 --target kql,spl --auto-approve
  python3 cli.py pcap capture.pcap --target kql --out ./hunt_output
  python3 cli.py report advisory.pdf --title "Vendor Advisory" --target kql,spl
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from ir.schema import IRDetection
from backends.base import QueryBackend, RenderedQuery
from backends.ms_kql import MsKqlBackend
from backends.splunk_spl import SplunkSplBackend
from backends.sigma import SigmaBackend
from explanation.generator import build_explanation
from explanation.schema import QueryExplanation

_BACKEND_REGISTRY: dict[str, type[QueryBackend]] = {
    "kql": MsKqlBackend,
    "spl": SplunkSplBackend,
    "sigma": SigmaBackend,
}

_EXTENSION_BY_DIALECT = {"kql": "kql", "spl": "spl", "sigma": "yml"}


def _resolve_targets(target_arg: str) -> list[str]:
    targets = [t.strip().lower() for t in target_arg.split(",") if t.strip()]
    unknown = [t for t in targets if t not in _BACKEND_REGISTRY]
    if unknown:
        raise SystemExit(f"unknown target platform(s): {unknown} (available: {sorted(_BACKEND_REGISTRY)})")
    return targets


def print_ir_summary(detection: IRDetection) -> None:
    print(f"\n=== IR Detection: {detection.name} ===")
    print(f"ID: {detection.id}")
    print(f"Description: {detection.description}")
    print(f"Conditions: {len(detection.conditions.items)} top-level item(s), logic={detection.conditions.logic.value}")
    print(f"MITRE techniques: {detection.mitre_techniques or '(none)'}")
    print(f"Provenance: source={detection.provenance.source_type.value}, "
          f"confidence={detection.provenance.confidence}")
    print(f"Tags: {detection.tags}")

    errors = detection.validate()
    if errors:
        print(f"VALIDATION WARNINGS: {errors}")


def confirm_or_exit(auto_approve: bool) -> None:
    if auto_approve:
        return
    response = input("\nProceed to generate queries from this (unreviewed) IR? [y/N]: ").strip().lower()
    if response != "y":
        print("Aborted — no queries generated.")
        raise SystemExit(0)


def render_all(detection: IRDetection, targets: list[str]) -> dict[str, list[tuple[RenderedQuery, QueryExplanation]]]:
    results: dict[str, list[tuple[RenderedQuery, QueryExplanation]]] = {}
    for target in targets:
        backend = _BACKEND_REGISTRY[target]()
        rendered_queries = backend.render(detection)
        pairs = [(rq, build_explanation(detection, rq)) for rq in rendered_queries]
        results[target] = pairs
    return results


def write_outputs(
    detection: IRDetection, results: dict[str, list[tuple[RenderedQuery, QueryExplanation]]], out_dir: Path
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = detection.id[:8]

    ir_path = out_dir / f"{slug}_ir.json"
    ir_path.write_text(json.dumps(detection.to_dict(), indent=2))

    hunt_package_lines = [
        f"# Hunt Package: {detection.name}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Detection ID: {detection.id}",
        f"Reviewed: {detection.reviewed} (reviewer: {detection.reviewer or 'n/a'})",
        "",
        "## Description",
        detection.description,
        "",
    ]

    query_count = 0
    for target, pairs in results.items():
        for rendered, explanation in pairs:
            query_count += 1
            ext = _EXTENSION_BY_DIALECT.get(rendered.dialect, "txt")
            safe_table = rendered.table_or_index.replace(":", "_").replace("/", "_").replace(" ", "_")
            query_filename = f"{slug}_{target}_{safe_table}.{ext}"
            query_path = out_dir / query_filename
            query_path.write_text(rendered.query_text)

            hunt_package_lines.append(f"## {target.upper()} — `{rendered.table_or_index}`")
            hunt_package_lines.append("")
            hunt_package_lines.append(f"Query file: `{query_filename}`")
            hunt_package_lines.append(f"Validated: {rendered.validated}")
            if rendered.validation_errors:
                hunt_package_lines.append(f"Validation errors: {rendered.validation_errors}")
            hunt_package_lines.append("")
            hunt_package_lines.append("```" + rendered.dialect)
            hunt_package_lines.append(rendered.query_text)
            hunt_package_lines.append("```")
            hunt_package_lines.append("")
            hunt_package_lines.append(explanation.to_markdown())
            hunt_package_lines.append("---")
            hunt_package_lines.append("")

    hunt_package_path = out_dir / f"{slug}_hunt_package.md"
    hunt_package_path.write_text("\n".join(hunt_package_lines))

    print(f"\nWrote IR snapshot: {ir_path}")
    print(f"Wrote {query_count} query file(s) to: {out_dir}")
    print(f"Wrote hunt package: {hunt_package_path}")
    return hunt_package_path


def _finish(detection: IRDetection, targets: list[str], out_dir: Path, auto_approve: bool) -> None:
    print_ir_summary(detection)
    confirm_or_exit(auto_approve)
    detection.reviewed = True
    detection.reviewer = "cli-user"
    results = render_all(detection, targets)
    write_outputs(detection, results, out_dir)


# ---------------------------------------------------------------- pcap -----

def cmd_pcap(args: argparse.Namespace) -> None:
    from parser.sandbox import parse_pcap_sandboxed
    from parser.pcap_to_ir import build_ir_from_pcap

    data = Path(args.file).read_bytes()
    result = parse_pcap_sandboxed(data, timeout_seconds=args.timeout)
    if result.warnings:
        print(f"Parser warnings: {result.warnings}")

    detection = build_ir_from_pcap(
        result, source_filename=Path(args.file).name, source_bytes_for_fingerprint=data,
    )
    _finish(detection, _resolve_targets(args.target), Path(args.out), args.auto_approve)


# -------------------------------------------------------------- manual -----

def cmd_manual(args: argparse.Namespace) -> None:
    from manual_input.builder import ingest_manual_input

    csv_text = Path(args.csv).read_text() if args.csv else None
    json_text = Path(args.json).read_text() if args.json else None
    stix_text = Path(args.stix).read_text() if args.stix else None
    ttp_ids = [t.strip() for t in args.ttp.split(",")] if args.ttp else None

    detection, warnings = ingest_manual_input(
        name=args.name or "Manual hunt",
        csv_text=csv_text, json_text=json_text, stix_text=stix_text, ttp_ids=ttp_ids,
    )
    if warnings:
        print(f"Ingestion warnings: {warnings}")

    _finish(detection, _resolve_targets(args.target), Path(args.out), args.auto_approve)


# -------------------------------------------------------------- report -----

def cmd_report(args: argparse.Namespace) -> None:
    from report_parser.ingest import ingest_report

    if args.url:
        detection, warnings, metadata = ingest_report(url=args.url, title=args.title)
    else:
        data = Path(args.file).read_bytes()
        detection, warnings, metadata = ingest_report(
            data=data, filename=Path(args.file).name, title=args.title,
        )
    if warnings:
        print(f"Ingestion warnings: {warnings}")
    print(f"Loaded report: {metadata.title} ({metadata.format}) from {metadata.source}")

    _finish(detection, _resolve_targets(args.target), Path(args.out), args.auto_approve)


# --------------------------------------------------------------- alert -----

_CONNECTOR_REGISTRY = {
    "sentinel": "connectors.sentinel.SentinelConnector",
    "crowdstrike": "connectors.crowdstrike_falcon.CrowdStrikeFalconConnector",
}


def cmd_alert(args: argparse.Namespace) -> None:
    """
    Requires live credentials for the chosen platform (see
    connectors/registry.yaml for the exact environment variables each
    connector needs) — this command cannot run without a real, reachable
    Sentinel/CrowdStrike tenant configured, and is therefore not exercised
    by the automated test suite the way the other three commands are.
    """
    import importlib

    from ir.builder import build_ir_from_alert

    if args.platform not in _CONNECTOR_REGISTRY:
        raise SystemExit(f"unknown platform '{args.platform}' (available: {sorted(_CONNECTOR_REGISTRY)})")

    module_path, class_name = _CONNECTOR_REGISTRY[args.platform].rsplit(".", 1)
    connector_cls = getattr(importlib.import_module(module_path), class_name)
    connector = connector_cls()

    alert = connector.get_alert_detail(args.alert_id)
    detection = build_ir_from_alert(alert)

    _finish(detection, _resolve_targets(args.target), Path(args.out), args.auto_approve)


def cmd_attck_bundle(args: argparse.Namespace) -> None:
    from explanation.mitre_lookup import load_and_activate_bundle

    count, warnings = load_and_activate_bundle(args.file)
    print(f"Loaded {count} techniques from {args.file}")
    if warnings:
        print(f"Warnings ({len(warnings)}):")
        for w in warnings[:20]:
            print(f"  - {w}")
        if len(warnings) > 20:
            print(f"  ... and {len(warnings) - 20} more")


# ---------------------------------------------------------------- main -----

def _add_common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--target", default="kql", help="comma-separated target platforms: kql,spl")
    sp.add_argument("--out", default="./hunt_output", help="output directory")
    sp.add_argument("--auto-approve", action="store_true",
                    help="skip interactive review confirmation (for scripted use)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="Threat-intel-to-hunting-query pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pcap = sub.add_parser("pcap", help="ingest a PCAP file")
    p_pcap.add_argument("file", help="path to .pcap file")
    p_pcap.add_argument("--timeout", type=int, default=30, help="sandbox parse timeout in seconds")
    _add_common(p_pcap)
    p_pcap.set_defaults(func=cmd_pcap)

    p_manual = sub.add_parser("manual", help="ingest manually-entered IOCs/TTPs")
    p_manual.add_argument("--csv", help="path to CSV file")
    p_manual.add_argument("--json", help="path to JSON file")
    p_manual.add_argument("--stix", help="path to STIX2 bundle JSON file")
    p_manual.add_argument("--ttp", help="comma-separated ATT&CK technique IDs")
    p_manual.add_argument("--name", help="detection name")
    _add_common(p_manual)
    p_manual.set_defaults(func=cmd_manual)

    p_report = sub.add_parser("report", help="ingest a threat intel report (PDF/DOCX/HTML/text)")
    p_report.add_argument("file", nargs="?", help="path to report file")
    p_report.add_argument("--url", help="URL to fetch report from instead of a local file")
    p_report.add_argument("--title", help="report title (for provenance)")
    _add_common(p_report)
    p_report.set_defaults(func=cmd_report)

    p_alert = sub.add_parser("alert", help="pull a live alert from a connected platform (requires credentials)")
    p_alert.add_argument("--platform", required=True, choices=sorted(_CONNECTOR_REGISTRY))
    p_alert.add_argument("--alert-id", required=True)
    _add_common(p_alert)
    p_alert.set_defaults(func=cmd_alert)

    p_bundle = sub.add_parser("load-attck-bundle", help="load a real ATT&CK STIX bundle and report its stats")
    p_bundle.add_argument("file", help="path to enterprise-attack.json (or similar STIX 2.1 bundle)")
    p_bundle.set_defaults(func=cmd_attck_bundle)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
