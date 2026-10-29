"""
mcp_server/tools.py

Tool catalog and dispatch.

Every tool:
  * is read-only and offline (annotations: readOnlyHint=true, destructiveHint=false,
    idempotentHint=true, openWorldHint=false), and really is: no handler writes
    files, opens sockets, or talks to a SIEM/EDR;
  * has a strict inputSchema (types, lengths, counts, formats,
    additionalProperties=false) that is enforced server-side before any work;
  * has an outputSchema that every result is checked against before it is returned;
  * has a short, static description with no instructions beyond what the tool
    does. The catalog is deterministic, and its SHA-256 is printed by
    `huntconsole-mcp --print-tool-catalog` so an operator can pin and diff it.

The file tools (and the kev_path argument) exist only when the operator passed
--allow-dir. Without it, the server cannot read any file at all.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ir.builder import ENTITY_TYPE_TO_IR_FIELD

from . import config
from .config import ServerConfig
from .paths import FileAccessError, read_confined_file
from .sandbox import SandboxError, run_job
from .schema_validate import validate

_ANNOTATIONS_READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

_TARGETS = {
    "type": "array",
    "description": "Query languages to generate. Defaults to all three.",
    "items": {"type": "string", "enum": ["kql", "spl", "sigma"]},
    "minItems": 1,
    "maxItems": 3,
    "uniqueItems": True,
}
_DEFAULT_TARGETS = ["kql", "spl", "sigma"]
_TECHNIQUE_ID = {"type": "string", "pattern": r"^[Tt][0-9]{4}(\.[0-9]{3})?$", "description": "ATT&CK ID, e.g. T1071.001"}
_CVE_ID = {"type": "string", "pattern": r"^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,19}$"}
_TITLE = {"type": "string", "maxLength": config.MAX_NAME_CHARS, "description": "Optional title for the hunt."}
_PATH = {"type": "string", "minLength": 1, "maxLength": config.MAX_PATH_CHARS}

_STRINGS = {"type": "array", "items": {"type": "string"}}
_HUNT_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["source", "reviewed", "notice", "detection", "warnings", "queries"],
    "properties": {
        "source": {"type": "string", "enum": ["indicators", "report_text", "report_file", "pcap_file", "cve_ids"]},
        "reviewed": {"type": "boolean"},
        "notice": {"type": "string"},
        "detection": {
            "type": "object",
            "required": ["id", "name", "mitre_techniques", "condition_count", "conditions", "conditions_truncated"],
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "mitre_techniques": _STRINGS,
                "condition_count": {"type": "integer", "minimum": 0},
                "conditions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["field", "operator", "value"],
                        "properties": {
                            "field": {"type": "string"},
                            "operator": {"type": "string"},
                            "value": {"type": ["string", "array", "null"], "items": {"type": "string"}},
                        },
                        "additionalProperties": False,
                    },
                },
                "conditions_truncated": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        "warnings": _STRINGS,
        "queries": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["target", "platform", "dialect", "table_or_index", "query", "generated",
                             "validated", "validation_errors", "caveats", "explanation"],
                "properties": {
                    "target": {"type": "string", "enum": ["kql", "spl", "sigma"]},
                    "platform": {"type": "string"},
                    "dialect": {"type": "string"},
                    "table_or_index": {"type": "string"},
                    "query": {"type": "string"},
                    "generated": {"type": "boolean"},
                    "validated": {"type": "boolean"},
                    "validation_errors": _STRINGS,
                    "caveats": _STRINGS,
                    "explanation": {
                        "type": "object",
                        "required": ["summary", "expected_output", "mitre_context", "data_source_requirements",
                                     "false_positive_guidance", "triage_hint"],
                        "properties": {
                            "summary": {"type": "string"},
                            "expected_output": {"type": "string"},
                            "mitre_context": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["technique_id", "name", "tactic", "description"],
                                    "properties": {
                                        "technique_id": {"type": "string"},
                                        "name": {"type": "string"},
                                        "tactic": {"type": "string"},
                                        "description": {"type": "string"},
                                    },
                                    "additionalProperties": False,
                                },
                            },
                            "data_source_requirements": _STRINGS,
                            "false_positive_guidance": _STRINGS,
                            "triage_hint": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
}

_LOOKUP_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["technique_id", "found", "source"],
    "properties": {
        "technique_id": {"type": "string"},
        "found": {"type": "boolean"},
        "name": {"type": "string"},
        "tactic": {"type": "string"},
        "description": {"type": "string"},
        "source": {"type": "string"},
    },
    "additionalProperties": False,
}

_READ_ONLY_NOTE = " Read-only: nothing is executed, saved, or sent to any system."


def _tool(name: str, title: str, description: str, properties: dict, required: list[str],
          output_schema: dict) -> dict[str, Any]:
    return {
        "name": name,
        "title": title,
        "description": description + _READ_ONLY_NOTE,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
        "outputSchema": output_schema,
        "annotations": {"title": title, **_ANNOTATIONS_READ_ONLY},
    }


def list_tools(cfg: ServerConfig) -> list[dict[str, Any]]:
    """The tool catalog for this configuration, in a fixed order."""
    indicator = {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": sorted(ENTITY_TYPE_TO_IR_FIELD)},
            "value": {"type": "string", "minLength": 1, "maxLength": 2048},
            "notes": {"type": "string", "maxLength": 500},
        },
        "required": ["type", "value"],
        "additionalProperties": False,
    }
    tools = [
        _tool(
            "hunt_from_indicators", "Hunt from indicators",
            "Generate KQL, SPL and Sigma hunting queries, with explanations, from IOCs "
            "(IPs, domains, URLs, hashes and similar) and/or MITRE ATT&CK technique IDs.",
            {
                "name": _TITLE,
                "indicators": {"type": "array", "items": indicator, "maxItems": config.MAX_INDICATORS},
                "techniques": {"type": "array", "items": _TECHNIQUE_ID, "maxItems": config.MAX_TECHNIQUES,
                               "uniqueItems": True},
                "targets": _TARGETS,
            },
            [], _HUNT_OUTPUT_SCHEMA,
        ),
        _tool(
            "hunt_from_report_text", "Hunt from report text",
            "Extract IOCs, CVE IDs and ATT&CK technique IDs from threat-report text (defanged indicators such "
            "as hxxp:// and 1[.]2[.]3[.]4 are handled) and generate hunting queries from them.",
            {
                "text": {"type": "string", "minLength": 1, "maxLength": config.MAX_REPORT_TEXT_CHARS},
                "title": _TITLE,
                "targets": _TARGETS,
            },
            ["text"], _HUNT_OUTPUT_SCHEMA,
        ),
        _tool(
            "hunt_cve_exposure", "Hunt CVE exposure",
            "Generate exposure-hunt queries that find devices running software affected by the given CVE IDs. "
            "This shows exposure, not exploitation.",
            {
                "cve_ids": {"type": "array", "items": _CVE_ID, "minItems": 1, "maxItems": config.MAX_CVES,
                            "uniqueItems": True},
                **({"kev_path": {**_PATH, "description": "Optional CISA KEV catalog JSON file inside an "
                                                         "allowed folder, used to enrich results."}}
                   if cfg.file_access_enabled else {}),
                "targets": _TARGETS,
            },
            ["cve_ids"], _HUNT_OUTPUT_SCHEMA,
        ),
        _tool(
            "lookup_attack_technique", "Look up ATT&CK technique",
            "Return the name, tactic and a short description of a MITRE ATT&CK technique ID from the local "
            "reference data.",
            {"technique_id": _TECHNIQUE_ID},
            ["technique_id"], _LOOKUP_OUTPUT_SCHEMA,
        ),
    ]
    if cfg.file_access_enabled:
        tools.insert(2, _tool(
            "hunt_from_file", "Hunt from report or capture file",
            "Generate hunting queries from a threat report (.pdf, .docx, .html, .htm, .txt, .md) or a classic "
            "packet capture (.pcap, .cap). The file must be inside a folder the operator allowed; "
            "relative paths are resolved against the first allowed folder.",
            {"path": _PATH, "title": _TITLE, "targets": _TARGETS},
            ["path"], _HUNT_OUTPUT_SCHEMA,
        ))
    return tools


def catalog_sha256(cfg: ServerConfig) -> str:
    blob = json.dumps(list_tools(cfg), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


class UnknownToolError(Exception):
    pass


class ToolInputError(Exception):
    """Bad arguments or a refused request. The message is safe to return to the model."""


class ToolState:
    """Per-process state the dispatcher needs: config, the active ATT&CK rows, the tool index."""

    def __init__(self, cfg: ServerConfig, technique_rows: list | None = None):
        self.cfg = cfg
        self.technique_rows = technique_rows
        self.tools = {t["name"]: t for t in list_tools(cfg)}
        self.cancel_event = None        # set by the protocol layer; lets a cancelled call stop its worker


def call_tool(state: ToolState, name: str, arguments: Any) -> dict[str, Any]:
    """
    Validates and runs one tool. Returns the structured result.
    Raises UnknownToolError (protocol error) or ToolInputError / SandboxError (tool error).
    """
    tool = state.tools.get(name)
    if tool is None:
        raise UnknownToolError(name)
    if arguments is None:
        arguments = {}
    errors = validate(arguments, tool["inputSchema"], "arguments")
    if errors:
        raise ToolInputError("invalid arguments: " + "; ".join(errors))

    args = dict(arguments)
    targets = args.get("targets") or list(_DEFAULT_TARGETS)

    if name == "lookup_attack_technique":
        result = _lookup(args["technique_id"])
    elif name == "hunt_from_indicators":
        if not args.get("indicators") and not args.get("techniques"):
            raise ToolInputError("provide at least one indicator or technique")
        result = _sandboxed(state, "indicators", {
            "name": args.get("name"), "indicators": args.get("indicators", []),
            "techniques": args.get("techniques", []), "targets": targets,
        })
    elif name == "hunt_from_report_text":
        if not args["text"].strip():
            raise ToolInputError("text is empty")
        result = _sandboxed(state, "report_text", {"text": args["text"], "title": args.get("title"),
                                                   "targets": targets})
    elif name == "hunt_cve_exposure":
        kev_data = None
        if args.get("kev_path"):
            kev_data, _ = _read(state, args["kev_path"], config.KEV_EXTENSIONS, config.MAX_KEV_FILE_BYTES)
        result = _sandboxed(state, "cve", {"cve_ids": args["cve_ids"], "kev_data": kev_data, "targets": targets})
    elif name == "hunt_from_file":
        result = _hunt_from_file(state, args, targets)
    else:   # listed but not dispatched: a programming error, never reachable from input
        raise UnknownToolError(name)

    out_errors = validate(result, tool["outputSchema"], "result")
    if out_errors:
        raise SandboxError("internal error: the result did not match this tool's output schema")
    return result


def _read(state: ToolState, path: str, extensions, max_bytes: int) -> tuple[bytes, str]:
    try:
        return read_confined_file(path, state.cfg.allowed_dirs, extensions=extensions, max_bytes=max_bytes)
    except FileAccessError as exc:
        raise ToolInputError(str(exc)) from None


def _hunt_from_file(state: ToolState, args: dict[str, Any], targets: list[str]) -> dict[str, Any]:
    path = args["path"]
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if suffix in config.PCAP_EXTENSIONS:
        data, filename = _read(state, path, config.PCAP_EXTENSIONS, config.MAX_PCAP_FILE_BYTES)
        return _sandboxed(state, "pcap_file", {"data": data, "filename": filename, "targets": targets})
    data, filename = _read(state, path, config.REPORT_EXTENSIONS, config.MAX_REPORT_FILE_BYTES)
    fmt = config.REPORT_EXTENSIONS["." + filename.rsplit(".", 1)[-1].lower()]
    return _sandboxed(state, "report_file", {"data": data, "filename": filename, "format": fmt,
                                             "title": args.get("title"), "targets": targets})


def _sandboxed(state: ToolState, job: str, payload: dict[str, Any]) -> dict[str, Any]:
    return run_job(job, payload, technique_lookup=state.technique_rows, drop_network=state.cfg.sandbox_network,
                   cancel=state.cancel_event)


def _lookup(technique_id: str) -> dict[str, Any]:
    from explanation.mitre_lookup import get_active_source_description, lookup_technique

    tid = technique_id.strip().upper()
    info = lookup_technique(tid)
    source = get_active_source_description()
    if info is None:
        return {"technique_id": tid, "found": False, "source": source}
    from .jobs import clean

    return {"technique_id": info.technique_id, "found": True, "name": clean(info.name, 200),
            "tactic": clean(info.tactic, 100), "description": clean(info.short_description, 400),
            "source": source}
