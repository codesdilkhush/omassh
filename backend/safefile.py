from __future__ import annotations

import os
import stat
import errno
import struct
import secrets
import hashlib
import contextlib
from collections.abc import Callable

READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CREATE_FLAGS = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY | os.O_CLOEXEC
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
ACL_XATTR = "system.posix_acl_access"
_NO_XATTR = {errno.ENODATA, errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP), getattr(errno, "ENOATTR", errno.ENODATA)}


class Refused(Exception):

    def __init__(self, code: str, detail: str = "") -> None:
        """Carry a short refusal code and an optional human-readable detail."""
        super().__init__(code)
        self.code = code
        self.detail = detail


def _plain(name: str) -> str:
    """name unchanged when it is a single plain file name; anything that could leave the directory raises ValueError."""
    if name in ("", ".", "..") or "/" in name or "\0" in name:
        raise ValueError("not a plain file name")
    return name


def _open_dir(path: str) -> int:
    """A file descriptor for the directory at path, following symlinks."""
    try:
        return os.open(path, DIR_FLAGS)
    except FileNotFoundError as exc:
        raise Refused("missing") from exc
    except NotADirectoryError as exc:
        raise Refused("dir", "not a directory") from exc
    except OSError as exc:
        raise Refused("io", exc.strerror or "cannot open") from exc


def open_dir(path: str, create: bool = False) -> int:
    """A descriptor for the directory at path that we own and nobody else can write to, created with mode 0700 when create is set."""
    try:
        fd = _open_dir(path)
    except Refused as exc:
        if exc.code != "missing" or not create:
            raise
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as err:
            raise Refused("io", err.strerror or "cannot create") from err
        fd = _open_dir(path)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        os.close(fd)
        raise Refused("dir", "directory is not private to you")
    return fd


def read_nofollow(dfd: int, name: str, limit: int) -> tuple[bytes | None, os.stat_result | None]:
    """The bytes and status of the regular file name inside dfd, or (None, None) when it is missing; anything unsafe raises Refused."""
    try:
        fd = os.open(_plain(name), READ_FLAGS, dir_fd=dfd)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Refused("symlink") from exc
        raise Refused("io", exc.strerror or "cannot open") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("not-regular")
        if info.st_uid != os.geteuid():
            raise Refused("owner")
        if info.st_mode & 0o022:
            raise Refused("mode")
        if info.st_size > limit:
            raise Refused("too-large")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        raise Refused("io", exc.strerror or "cannot read") from exc
    finally:
        os.close(fd)
    if len(data) > limit:
        raise Refused("too-large")
    return data, info


def read_acl_fd(fd: int) -> bytes | None:
    """Read the POSIX access ACL xattr from an open descriptor if supported and present, or None."""
    if not hasattr(os, "getxattr"):
        return None
    try:
        return os.getxattr(fd, ACL_XATTR)
    except OSError:
        return None


def read_acl(dfd: int, name: str) -> bytes | None:
    """Read the POSIX access ACL xattr if supported and present, or None."""
    if not hasattr(os, "getxattr"):
        return None
    try:
        fd = os.open(_plain(name), READ_FLAGS, dir_fd=dfd)
    except OSError:
        return None
    try:
        return read_acl_fd(fd)
    finally:
        os.close(fd)


def _acl_entries(blob: bytes) -> list[tuple[int, int, int]] | None:
    """Decode Linux POSIX ACL xattr entries as (tag, perm, id), or None when malformed."""
    if len(blob) < 4 or (len(blob) - 4) % 8 != 0:
        return None
    if struct.unpack_from("<I", blob, 0)[0] != 2:
        return None
    return [struct.unpack_from("<HHI", blob, offset) for offset in range(4, len(blob), 8)]


def _acl_matches(actual: bytes | None, expected: bytes | None, mode: int) -> bool:
    """True when actual matches expected (or matches expected with execute bits masked out to mode)."""
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if actual == expected:
        return True
    act = _acl_entries(actual)
    exp = _acl_entries(expected)
    if act is None or exp is None or len(act) != len(exp):
        return False
    masked = {1: (mode >> 6) & 7, 16: (mode >> 3) & 7, 32: mode & 7}
    for (a_tag, a_perm, a_id), (e_tag, e_perm, e_id) in zip(act, exp, strict=True):
        if a_tag != e_tag or a_id != e_id:
            return False
        want_perm = (e_perm & masked[e_tag]) if e_tag in masked else e_perm
        if a_perm != want_perm:
            return False
    return True


def _verify_fd_acl_and_mode(fd: int, mode: int, acl: bytes | None) -> None:
    """Refuse unless the open file descriptor has exactly mode and the expected POSIX ACL state."""
    if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
        raise Refused("mode", "the file permissions could not be kept")
    if not _acl_matches(read_acl_fd(fd), acl, mode):
        raise Refused("acl", "the access control list could not be kept")


def _identity(info: os.stat_result | None) -> tuple | None:
    """The fields that tell two states of a file apart, or None for a missing file."""
    if info is None:
        return None
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode, info.st_gid)


def remove(dfd: int, name: str) -> None:
    """Delete name inside dfd, ignoring a name that is already gone."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_plain(name), dir_fd=dfd)


def _create(dfd: int, name: str, data: bytes, mode: int, gid: int | None = None, acl: bytes | None = None) -> None:
    """Create name exclusively inside dfd with exactly mode, in group gid when given, keeping or removing ACLs, and write data to disk."""
    fd = os.open(name, CREATE_FLAGS, 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb") as fh:
            if gid is not None and os.fstat(fh.fileno()).st_gid != gid:
                try:
                    os.fchown(fh.fileno(), -1, gid)
                except PermissionError as exc:
                    raise Refused("group", "the group of the file cannot be kept") from exc
            if acl is not None:
                if not hasattr(os, "setxattr"):
                    raise Refused("acl", "the access control list cannot be kept")
                try:
                    os.setxattr(fh.fileno(), ACL_XATTR, acl)
                except OSError as exc:
                    raise Refused("acl", "the access control list cannot be kept") from exc
            elif hasattr(os, "removexattr"):
                try:
                    os.removexattr(fh.fileno(), ACL_XATTR)
                except OSError as exc:
                    if exc.errno not in _NO_XATTR:
                        raise Refused("acl", "the access control list cannot be cleared") from exc
            os.fchmod(fh.fileno(), mode)
            _verify_fd_acl_and_mode(fh.fileno(), mode, acl)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        remove(dfd, name)
        raise


def create_exclusive(dfd: int, name: str, data: bytes) -> None:
    """Create name inside dfd with mode 0600 and data; refuses when anything, including a symlink, already has that name."""
    try:
        _create(dfd, _plain(name), data, 0o600)
    except OSError as exc:
        raise Refused("io", exc.strerror or "cannot create") from exc


def _publish(
    dfd: int,
    name: str,
    data: bytes,
    mode: int,
    guard: Callable[[], None] | None,
    check: Callable[[str], None] | None,
    backup: Callable[[], None] | None,
    gid: int | None,
    acl: bytes | None = None,
) -> None:
    """Write data to a private temporary file, run the check and the guard, verify mode/ACL and take the backup, then rename over name and sync the directory."""
    temp = ".%s.%s.tmp" % (_plain(name), secrets.token_hex(8))
    try:
        _create(dfd, temp, data, mode, gid, acl)
    except OSError as exc:
        raise Refused("io", exc.strerror or "cannot create") from exc
    try:
        if check is not None:
            check(temp)
        if guard is not None:
            guard()
        tfd = os.open(temp, READ_FLAGS, dir_fd=dfd)
        try:
            _verify_fd_acl_and_mode(tfd, mode, acl)
        finally:
            os.close(tfd)
        if backup is not None:
            backup()
        os.replace(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
    except OSError as exc:
        remove(dfd, temp)
        raise Refused("io", exc.strerror or "cannot write") from exc
    except BaseException:
        remove(dfd, temp)
        raise


def _ensure_unchanged(dfd: int, name: str, before: os.stat_result | None, before_acl: bytes | None = None) -> None:
    """Refuse with conflict unless name still has the identity, mode, group and ACL it had when it was read."""
    try:
        current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        current = None
    if _identity(current) != _identity(before):
        raise Refused("conflict")
    if before is not None and read_acl(dfd, name) != before_acl:
        raise Refused("conflict")


def install(
    dfd: int,
    name: str,
    data: bytes,
    mode: int,
    before: os.stat_result | None,
    check: Callable[[str], None] | None = None,
    backup: Callable[[], None] | None = None,
    gid: int | None = None,
    acl: bytes | None = None,
) -> None:
    """Replace name with data atomically, in group gid when given, refusing with conflict unless it is still exactly the file that was read as before (None means absent)."""
    _publish(dfd, name, data, mode, lambda: _ensure_unchanged(dfd, name, before, acl), check, backup, gid, acl)


def replace(dfd: int, name: str, data: bytes, mode: int) -> None:
    """Replace name with data atomically without looking at what was there; a symlink at name is replaced, not followed."""
    _publish(dfd, name, data, mode, None, None, None, None)


def token(data: bytes | None, path: str) -> str:
    """A 16 hex digit fingerprint of a path together with the exact bytes of its file, or its absence."""
    digest = hashlib.sha256()
    digest.update(os.fsencode(path))
    digest.update(b"\0")
    digest.update(b"\0" if data is None else b"\1" + data)
    return digest.hexdigest()[:16]
