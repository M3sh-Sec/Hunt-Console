"""
mcp_server/paths.py

Confined, read-only file access for the file-based tools.

Rules:
  * Access is possible only when the operator passed --allow-dir. With no
    allowed folders the file tools are not even listed.
  * Allowed folders may not be a filesystem root, a system folder, the home
    folder, or any folder that contains the home folder.
  * A requested path is resolved with all symlinks followed, and the result
    must sit inside one of the allowed folders. `..`, symlinks and junctions
    pointing outside are therefore rejected.
  * On POSIX the file is then opened component by component from a descriptor
    held on the allowed folder, with O_NOFOLLOW at every step. If any folder in
    the path is swapped for a symlink between the check and the open, the open
    fails. This closes the check-then-open race.
  * Hidden files and folders (any segment starting with ".") are refused, so
    .env, .git or .ssh inside an allowed folder stay out of reach.
  * Files with more than one hard link are refused: a hard link inside the
    folder could point at a file outside it.
  * Only the extensions a tool needs are accepted, size is capped, and only
    regular files (not FIFOs or devices) are read.
  * Errors for missing, outside, hidden and multiply-linked files are identical,
    so the server is not an existence oracle.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


class FileAccessError(Exception):
    """A requested file is not readable under the operator's policy. The message is safe to show the model."""


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOT_PERMITTED = "file not found, or not readable through this server"

_SYSTEM_DIRS_POSIX = {"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/proc",
                      "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/home", "/Users",
                      "/System", "/Library", "/Applications", "/private", "/private/tmp", "/private/var",
                      "/private/etc", "/Volumes", "/mnt", "/media"}


def _account_home() -> Path:
    """The account's home folder from the password database, not from $HOME (which the environment controls)."""
    if os.name == "posix":
        import pwd

        try:
            return Path(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))
        except KeyError:
            pass
    return Path(os.path.realpath(Path.home()))


def validate_allowed_dirs(raw_dirs: list[str]) -> tuple[Path, ...]:
    """
    Startup check for --allow-dir values. Raises ValueError with an operator-facing message.
    """
    out: list[Path] = []
    homes = {_account_home(), Path(os.path.realpath(Path.home()))}
    for raw in raw_dirs:
        p = Path(os.path.realpath(os.path.expanduser(raw)))
        if not p.is_dir():
            raise ValueError(f"--allow-dir {raw!r} is not an existing folder")
        if p == Path(p.anchor):
            raise ValueError(f"--allow-dir {raw!r} is a filesystem root; grant a specific project folder instead")
        if os.name == "posix" and str(p) in _SYSTEM_DIRS_POSIX:
            raise ValueError(f"--allow-dir {raw!r} is a system folder; grant a specific project folder instead")
        if os.name == "nt" and len(p.parts) <= 2 and p.parts[-1].lower() in (
                "windows", "users", "program files", "program files (x86)", "programdata"):
            raise ValueError(f"--allow-dir {raw!r} is a system folder; grant a specific project folder instead")
        for home in homes:
            if p == home or home.is_relative_to(p):
                raise ValueError(f"--allow-dir {raw!r} is or contains your home folder; "
                                 f"grant a specific folder inside it instead")
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


def _open_beneath(root: Path, rel_parts: tuple[str, ...]) -> int:
    """
    Opens root/rel_parts without following any symlink, walking from a descriptor on root.
    POSIX only (needs dir_fd support). Raises OSError.
    """
    dir_fd = os.open(str(root), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    try:
        for part in rel_parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return os.open(rel_parts[-1], os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


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

    try:
        candidate = Path(os.path.expanduser(requested.strip()))
        if not candidate.is_absolute():
            candidate = allowed_dirs[0] / candidate
        real = os.path.realpath(candidate, strict=True)
    except (OSError, RuntimeError, ValueError, UnicodeError):
        raise FileAccessError(_NOT_PERMITTED) from None

    root = next((r for r in allowed_dirs if _inside(real, r)), None)
    if root is None:
        raise FileAccessError(_NOT_PERMITTED)

    rel_parts = Path(real).relative_to(root).parts
    if not rel_parts or any(part.startswith(".") for part in rel_parts):
        raise FileAccessError(_NOT_PERMITTED)

    suffix = Path(real).suffix.lower()
    if suffix not in extensions:
        raise FileAccessError(f"file type {suffix or '(none)'!r} is not accepted here; allowed: {sorted(extensions)}")

    try:
        if os.open in os.supports_dir_fd and _O_NOFOLLOW:
            fd = _open_beneath(root, rel_parts)
        else:   # Windows: no openat; fall back to opening the checked path and comparing identities
            checked = os.stat(real, follow_symlinks=False)
            fd = os.open(real, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY)
            opened_id = os.fstat(fd)
            if (opened_id.st_dev, opened_id.st_ino) != (checked.st_dev, checked.st_ino):
                os.close(fd)
                raise FileAccessError("the file changed while it was being opened; try again")
    except (OSError, UnicodeError):
        raise FileAccessError(_NOT_PERMITTED) from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise FileAccessError("only regular files can be read")
        if opened.st_nlink > 1 and sys.platform != "win32":
            raise FileAccessError(_NOT_PERMITTED)
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
