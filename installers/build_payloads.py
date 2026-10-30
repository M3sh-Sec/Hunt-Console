#!/usr/bin/env python3
"""
installers/build_payloads.py

Rebuilds the payload embedded at the end of install-linux.sh (base64 tar.gz)
and install-windows.ps1 (base64 zip) from the current source tree:

  huntconsole-<version>-py3-none-any.whl, README.md, SECURITY.md, CHANGELOG.md,
  HuntConsole.jsx, MCP-README.md, MCP-SECURITY.md, claude_desktop_config.example.json

Run from the repository root with an interpreter whose setuptools can build
wheels offline (setuptools>=68 and wheel installed):

  python3 installers/build_payloads.py

SOURCE_DATE_EPOCH (default: the time of the last commit outside installers/)
fixes archive timestamps, so a reviewer can rebuild and compare. The SHA-256
of the wheel is printed.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "installers" / "install-linux.sh"
WINDOWS = ROOT / "installers" / "install-windows.ps1"
DOCS = {
    "README.md": ROOT / "README.md",
    "SECURITY.md": ROOT / "SECURITY.md",
    "CHANGELOG.md": ROOT / "CHANGELOG.md",
    "HuntConsole.jsx": ROOT / "gui" / "HuntConsole.jsx",
    "MCP-README.md": ROOT / "mcp_server" / "README.md",
    "MCP-SECURITY.md": ROOT / "mcp_server" / "SECURITY.md",
    "claude_desktop_config.example.json": ROOT / "mcp_server" / "examples" / "claude_desktop_config.json",
}


def _epoch() -> int:
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        # Time of the last commit that changed anything outside installers/, so rebuilding after the
        # installers themselves are committed gives the same timestamps.
        out = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%ct", "--", ".", ":!installers"],
                             capture_output=True, text=True, check=True).stdout.strip()
        return int(out)
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        return int(time.time())


def build_wheel(out_dir: Path, epoch: int) -> Path:
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps", "--no-index",
                    "-w", str(out_dir), str(ROOT)], check=True, env=env, cwd=str(out_dir))
    wheels = list(out_dir.glob("huntconsole-*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected one wheel, found {wheels}")
    return wheels[0]


def _files(wheel: Path) -> list[tuple[str, bytes]]:
    files = [(wheel.name, wheel.read_bytes())]
    files += [(name, path.read_bytes()) for name, path in DOCS.items()]
    return sorted(files)


def tar_gz(files: list[tuple[str, bytes]], epoch: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), epoch, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=epoch)     # fixed gzip header time, for reproducibility


def zip_bytes(files: list[tuple[str, bytes]], epoch: int) -> bytes:
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files:
            zi = zipfile.ZipInfo(name, date_time=stamp)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, data)
    return buf.getvalue()


def splice(script: Path, marker: str, payload: bytes, *, wrap: int) -> None:
    text = script.read_text(encoding="utf-8")
    head, sep, _old = text.rpartition("\n" + marker + "\n")
    if not sep:
        raise SystemExit(f"payload marker not found in {script}")
    b64 = base64.b64encode(payload).decode("ascii")
    lines = "\n".join(b64[i:i + wrap] for i in range(0, len(b64), wrap))
    script.write_text(head + sep + lines + "\n", encoding="utf-8")


def main() -> int:
    epoch = _epoch()
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(Path(tmp), epoch)
        files = _files(wheel)
        splice(LINUX, "__PAYLOAD_BELOW__", tar_gz(files, epoch), wrap=76)
        splice(WINDOWS, "##__PAYLOAD_BELOW__##", zip_bytes(files, epoch), wrap=76)
        print(f"{wheel.name} sha256={hashlib.sha256(wheel.read_bytes()).hexdigest()}")
    for name, _ in files:
        print(f"  embedded: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
