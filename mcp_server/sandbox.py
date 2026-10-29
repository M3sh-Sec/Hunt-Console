"""
mcp_server/sandbox.py

Runs one tool job in a fresh, short-lived child process. Report text, report
files, PCAPs and KEV catalogs are untrusted input; parsing them in the server
process would let a crafted file hang the server, exhaust its memory, or (if a
parser bug were ever exploitable) act with the server's full privileges.

The child:
  * is started with `spawn`, so it inherits no Python state from the server;
  * gets a wall-clock timeout, enforced by the parent, which kills it;
  * on POSIX: RLIMIT_AS (memory), RLIMIT_CPU, RLIMIT_FSIZE (no large file writes),
    RLIMIT_CORE=0 (no core dumps holding input data) and RLIMIT_NOFILE;
  * on Linux, where unprivileged user namespaces are available, moves into a new
    network namespace with no interfaces, so it cannot open network connections;
  * never sees stdin, and its stdout is the server's stderr (see protocol.py),
    so it cannot write into the MCP stream;
  * returns at most MAX_RESULT_BYTES of JSON over a one-way pipe.

These limits are defence in depth for the parsing step. They are not a
substitute for running the whole server in a container (see SECURITY.md).
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sys
import time
from typing import Any

from . import config


class SandboxError(Exception):
    """The job did not complete. The message is safe to return to the model."""


class JobInputError(Exception):
    """Raised inside a job for bad input. The message is safe to return to the model."""


def _drop_network() -> bool:
    """Best effort: put this process in an empty network namespace. Returns True on success."""
    if not sys.platform.startswith("linux"):
        return False
    clone_newuser, clone_newnet = 0x10000000, 0x40000000      # same values as os.CLONE_NEWUSER / CLONE_NEWNET
    uid, gid = os.getuid(), os.getgid()
    unshare = getattr(os, "unshare", None)                     # Python 3.12+
    try:
        if unshare is not None:
            unshare(clone_newuser | clone_newnet)
        else:                                                  # Python 3.10 / 3.11: call libc directly
            import ctypes
            import ctypes.util

            libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
            if libc.unshare(ctypes.c_int(clone_newuser | clone_newnet)) != 0:
                return False
    except (OSError, AttributeError):
        return False
    # Keep the same uid/gid inside the new user namespace so file permissions behave as before.
    try:
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/uid_map", "w") as f:
            f.write(f"{uid} {uid} 1")
        with open("/proc/self/gid_map", "w") as f:
            f.write(f"{gid} {gid} 1")
    except OSError:
        pass
    return True


def _apply_limits(drop_network: bool) -> dict[str, Any]:
    applied: dict[str, Any] = {"network_namespace": False, "rlimits": False}
    if drop_network:
        applied["network_namespace"] = _drop_network()
    try:
        import resource
        import signal

        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)      # oversize writes fail with an error instead of killing us
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (config.WORKER_CPU_SECONDS, config.WORKER_CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_NOFILE, (config.WORKER_MAX_OPEN_FILES, config.WORKER_MAX_OPEN_FILES))
        resource.setrlimit(resource.RLIMIT_AS, (config.WORKER_MEMORY_BYTES, config.WORKER_MEMORY_BYTES))
        applied["rlimits"] = True
    except (ImportError, ValueError, OSError):
        pass        # Windows, or a tighter limit already in force: the parent's timeout still applies
    return applied


def _child_main(conn, job: str, payload: dict[str, Any], technique_lookup, drop_network: bool) -> None:
    sys.dont_write_bytecode = True
    try:
        applied = _apply_limits(drop_network)
        from . import jobs                      # imported after the limits are in place

        jobs.SANDBOX_STATE.update(applied)
        if technique_lookup:
            jobs.install_technique_lookup(technique_lookup)
        result = jobs.run(job, payload)
        message = {"ok": True, "result": result}
    except JobInputError as exc:
        message = {"ok": False, "error": str(exc)[:1000]}
    except MemoryError:
        message = {"ok": False, "error": "input needed more memory than this server allows"}
    except Exception as exc:  # noqa: BLE001 — never let a parser exception text or traceback leak raw input
        message = {"ok": False, "error": f"could not process the input ({type(exc).__name__})"}
    try:
        data = json.dumps(message, ensure_ascii=True, default=str).encode("ascii")
        if len(data) > config.MAX_RESULT_BYTES:
            data = json.dumps({"ok": False, "error": "result was larger than this server returns; "
                                                      "split the input into smaller pieces"}).encode("ascii")
        conn.send_bytes(data)
    finally:
        conn.close()


def probe_network_isolation() -> bool:
    """Runs a no-op child to learn whether network namespaces work here. Used for the startup log."""
    try:
        return bool(run_job("probe", {}, timeout=20).get("network_namespace"))
    except SandboxError:
        return False


def run_job(
    job: str,
    payload: dict[str, Any],
    *,
    technique_lookup: list | None = None,
    drop_network: bool = True,
    timeout: float = config.WORKER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child_main, args=(sender, job, payload, technique_lookup, drop_network),
                       daemon=False)
    started = time.monotonic()
    proc.start()
    sender.close()
    data: bytes | None = None
    try:
        if receiver.poll(timeout):
            try:
                data = receiver.recv_bytes(maxlength=config.MAX_RESULT_BYTES + 4096)
            except (EOFError, OSError):
                data = None
    finally:
        receiver.close()
        if data is not None:
            proc.join(timeout=5)                # finished normally: give it a moment to exit
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=5)

    if data is None:
        if time.monotonic() - started >= timeout:
            raise SandboxError(f"processing took longer than {timeout:g} seconds and was stopped")
        raise SandboxError("processing stopped unexpectedly (the input may exceed the memory or CPU limit)")
    message = json.loads(data)
    if not message.get("ok"):
        raise SandboxError(message.get("error") or "processing failed")
    return message["result"]
