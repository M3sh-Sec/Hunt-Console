"""
mcp_server/paths.py

Confined, read-only file access for the file-based tools.

Rules:
  * Access is possible only when the operator passed --allow-dir. With no
    allowed folders the file tools are not even listed.
  * A requested path is resolved with all symlinks followed, and the result
    must sit inside one of the allowed folders. `..`, symlinks and junctions
    pointing outside are therefore rejected.
  * Hidden files and folders (any path segment starting with ".") are refused,
    so secrets such as .env, .git or .ssh inside an allowed folder stay out of reach.
  * Only the extensions a tool needs are accepted, and size is capped.
  * The file is opened without following a final symlink, must be a regular
    file (not a FIFO or device), and must be the same file that was checked.
  * Errors never reveal whether a path outside the allowed folders exists.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


class FileAccessError(Exception):
    """A requested file is not readable under the operator's policy. The message is safe to show the model."""


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_NOT_PERMITTED = "file not found, or not inside a folder this server is allowed to read"


def validate_allowed_dirs(raw_dirs: list[str]) -> tuple[Path, ...]:
    """
    Startup check for --allow-dir values. Raises ValueError with an operator-facing
    message. Refuses filesystem roots and the whole home folder, because granting
    either defeats the point of an allow-list.
    """
    out: list[Path] = []
    home = Path(os.path.realpath(Path.home()))
    for raw in raw_dirs:
        p = Path(os.path.realpath(os.path.expanduser(raw)))
        if not p.is_dir():
            raise ValueError(f"--allow-dir {raw!r} is not an existing folder")
        if p == Path(p.anchor):
            raise ValueError(f"--allow-dir {raw!r} is a filesystem root; grant a specific project folder instead")
        if p == home:
            raise ValueError(f"--allow-dir {raw!r} is your whole home folder; grant a specific folder inside it instead")
        if any(part.startswith(".") for part in p.parts[1:]):
            raise ValueError(f"--allow-dir {raw!r} is inside a hidden folder; choose a normal folder")
        if p not in out:
            out.append(p)
    return tuple(out)


def _inside(child: str, root: Path) -> bool:
    root_s = str(root)
    try:
        return os.path.commonpath([child, root_s]) == root_s
    except ValueError:      # different drives on Windows
        return False


def read_confined_file(
    requested: str,
    allowed_dirs: tuple[Path, ...],
    *,
    extensions: set[str] | dict[str, str],
    max_bytes: int,
) -> tuple[bytes, str]:
    """Returns (file bytes, file name). Raises FileAccessError."""
    if not allowed_dirs:
        raise FileAccessError("file access is disabled on this server (the operator did not pass --allow-dir)")
    if not isinstance(requested, str) or not requested.strip() or "\x00" in requested:
        raise FileAccessError("path must be a non-empty string")

    candidate = Path(os.path.expanduser(requested.strip()))
    if not candidate.is_absolute():
        candidate = allowed_dirs[0] / candidate

    try:
        real = os.path.realpath(candidate, strict=True)
    except (OSError, RuntimeError):
        raise FileAccessError(_NOT_PERMITTED) from None

    root = next((r for r in allowed_dirs if _inside(real, r)), None)
    if root is None:
        raise FileAccessError(_NOT_PERMITTED)

    rel_parts = Path(real).relative_to(root).parts
    if not rel_parts or any(part.startswith(".") for part in rel_parts):
        raise FileAccessError("hidden files and folders are not readable through this server")

    suffix = Path(real).suffix.lower()
    if suffix not in extensions:
        raise FileAccessError(f"file type {suffix or '(none)'!r} is not accepted here; allowed: {sorted(extensions)}")

    try:
        checked = os.stat(real, follow_symlinks=False)
        fd = os.open(real, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY)
    except OSError:
        raise FileAccessError(_NOT_PERMITTED) from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise FileAccessError("only regular files can be read")
        if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            raise FileAccessError("the file changed while it was being opened; try again")
        if opened.st_size > max_bytes:
            raise FileAccessError(f"file is larger than the {max_bytes // (1024 * 1024)} MiB limit for this tool")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise FileAccessError(f"file is larger than the {max_bytes // (1024 * 1024)} MiB limit for this tool")
    finally:
        os.close(fd)
    return b"".join(chunks), Path(real).name
