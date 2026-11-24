from __future__ import annotations

import os
import time
import secrets
import hostfile
import safefile
import sshconfig
from collections.abc import Callable
from sshconfig import clean, split_keyword

INCLUDE_LINE = "Include ~/.ssh/omassh.config"
MAX_BYTES = 1 << 20
BOM = b"\xef\xbb\xbf"
CONTEXT = 3
LINE_CAP = 120
MAX_MESSAGE = 200
REFUSALS = {"owner": "owner", "mode": "mode", "too-large": "too-large", "acl": "acl"}
FAILURES = {"conflict": "conflict", "io": "io", "check-failed": "check-failed"}


def _lines(data: bytes) -> list[tuple[int, str, bytes]]:
    """The byte offset, the text and the raw bytes with their newline of every line of data, split on newline only, as ssh reads it."""
    parts = data.split(b"\n")
    if parts[-1] == b"":
        parts.pop()
        whole = [part + b"\n" for part in parts]
    else:
        whole = [part + b"\n" for part in parts[:-1]] + [parts[-1]]
    rows = []
    offset = 0
    for part, raw in zip(parts, whole, strict=True):
        rows.append((offset, part.decode("utf-8", errors="surrogateescape"), raw))
        offset += len(raw)
    return rows


def insert_point(data: bytes) -> tuple[int, int]:
    """The byte offset and 1-based line number of the first directive line of data; the end of data when it has none."""
    rows = _lines(data)
    for number, (offset, text, _) in enumerate(rows, 1):
        if split_keyword(text) is not None:
            return offset, number
    return len(data), len(rows) + 1


def _splice(data: bytes, offset: int) -> bytes:
    """data with the single Include line inserted at offset, ending like the line it precedes and closing an unterminated last line first."""
    rows = _lines(data)
    anchor = next((raw for start, _, raw in rows if start == offset), rows[-1][2] if rows else b"")
    newline = b"\r\n" if anchor.endswith(b"\r\n") else b"\n"
    line = INCLUDE_LINE.encode("ascii") + newline
    if rows and offset == len(data) and not rows[-1][2].endswith(b"\n"):
        line = newline + line
    return data[:offset] + line + data[offset:]


def _context(data: bytes, line: int) -> tuple[list[str], list[str]]:
    """The cleaned lines before and from the insertion line, a few of each."""
    text = [row[1] for row in _lines(data)]
    index = line - 1
    return [clean(item, LINE_CAP) for item in text[max(0, index - CONTEXT) : index]], [clean(item, LINE_CAP) for item in text[index : index + CONTEXT]]


def _read_target(snap: dict) -> str:
    """Read the file behind ~/.ssh/config into snap and return the refusal code, or an empty string."""
    try:
        snap["dfd"] = safefile.open_dir(os.path.dirname(snap["target"]))
    except safefile.Refused:
        return "dir"
    try:
        data, info = safefile.read_nofollow(snap["dfd"], os.path.basename(snap["target"]), MAX_BYTES)
    except safefile.Refused as exc:
        return REFUSALS.get(exc.code, "not-regular")
    if data is None or info is None:
        return "not-regular"
    snap["data"], snap["info"] = data, info
    snap["acl"] = safefile.read_acl(snap["dfd"], os.path.basename(snap["target"]))
    if info.st_nlink != 1:
        return "links"
    if os.geteuid() != 0 and info.st_gid != os.getegid() and info.st_gid not in os.getgroups():
        return "group"
    return "bom" if data.startswith(BOM) else ""


def _ssh_refusal() -> str:
    """The refusal code for the ssh directory or for a host file that is not safe or not in the format the plugin writes, or an empty string."""
    try:
        dfd = safefile.open_dir(hostfile.ssh_dir())
    except safefile.Refused as exc:
        return "" if exc.code == "missing" else "dir"
    try:
        return {"unsafe": "managed-unsafe", "foreign": "managed-foreign"}.get(hostfile.load_managed(dfd)[3], "")
    finally:
        os.close(dfd)


def _inspect() -> dict:
    """Everything known about ~/.ssh/config and the inclusion of the host file; an open descriptor of the target directory may stay in the result."""
    ssh = hostfile.ssh_dir()
    path = os.path.join(ssh, "config")
    parsed = sshconfig.load(managed_path=hostfile.managed_path())
    snap = {
        "path": path,
        "target": os.path.realpath(path),
        "create": not os.path.lexists(path),
        "include": parsed["managedInclude"],
        "where": parsed["managedWhere"],
        "dfd": None,
        "data": None,
        "info": None,
    }
    snap["refusal"] = "" if snap["create"] else _read_target(snap)
    if not snap["refusal"]:
        snap["refusal"] = _ssh_refusal()
    snap["expect"] = "" if snap["refusal"] else safefile.token(snap["data"], path if snap["create"] else snap["target"])
    return snap


def _release(snap: dict) -> None:
    """Close the descriptor left open by _inspect."""
    if snap["dfd"] is not None:
        os.close(snap["dfd"])
        snap["dfd"] = None


def _shown(snap: dict) -> dict:
    """The public description of snap."""
    data = snap["data"] or b""
    line = insert_point(data)[1]
    before, after = _context(data, line)
    own = os.path.join(os.path.realpath(hostfile.ssh_dir()), "config")
    return {
        "include": snap["include"],
        "where": snap["where"],
        "path": snap["path"],
        "target": snap["target"] if snap["target"] != own else "",
        "create": snap["create"],
        "line": line,
        "insert": INCLUDE_LINE,
        "before": before,
        "after": after,
        "expect": snap["expect"],
        "refusal": snap["refusal"],
    }


def preview() -> dict:
    """The status of the inclusion of the host file together with the line that apply would insert and where."""
    snap = _inspect()
    try:
        return _shown(snap)
    finally:
        _release(snap)


def _failure(reason: str, snap: dict, message: str, refusal: str = "") -> dict:
    """The failed reply for apply, with the line to add by hand unless the host file is what is wrong."""
    refusal = refusal or snap["refusal"]
    text = message if refusal.startswith("managed-") else "%s; add this line at the top of ~/.ssh/config yourself: %s" % (message, INCLUDE_LINE)
    return {"ok": False, "reason": reason, "message": clean(text, MAX_MESSAGE), "refusal": refusal, "insert": INCLUDE_LINE}


def _candidate_check(directory: str) -> Callable[[str], None]:
    """A hook for safefile.install that refuses a candidate file unless our parser reads the host file from it before any directive and the host file and the ssh directory are still usable."""

    def check(name: str) -> None:
        """Raise Refused unless the candidate file called name makes the inclusion active and nothing else became unusable."""
        candidate = os.path.join(directory, name)
        if sshconfig.load(config_path=candidate, managed_path=hostfile.managed_path())["managedInclude"] != "active":
            raise safefile.Refused("check-failed", "the inserted line would not take effect")
        refusal = _ssh_refusal()
        if refusal:
            raise safefile.Refused("unsafe", "omassh.config or the ssh directory changed (%s)" % refusal)

    return check


def _install(snap: dict, new: bytes) -> str:
    """Write new over ~/.ssh/config with a backup in the ssh directory and return the backup path, or an empty string for a new file."""
    ssh = hostfile.ssh_dir()
    if snap["create"]:
        dfd = safefile.open_dir(ssh, create=True)
        try:
            real = os.path.realpath(ssh)
            safefile.install(dfd, "config", new, 0o600, None, _candidate_check(real))
        finally:
            os.close(dfd)
        return ""
    name = "config.omassh-%s-%s.bak" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), secrets.token_hex(2))
    sfd = safefile.open_dir(ssh)
    try:
        old = snap["data"]
        mode = snap["info"].st_mode & 0o644
        check = _candidate_check(os.path.dirname(snap["target"]))
        safefile.install(
            snap["dfd"],
            os.path.basename(snap["target"]),
            new,
            mode,
            snap["info"],
            check,
            lambda: safefile.create_exclusive(sfd, name, old),
            snap["info"].st_gid,
            snap.get("acl"),
        )
    finally:
        os.close(sfd)
    return os.path.join(ssh, name)


def apply(expect: str) -> dict:
    """Insert the Include line before the first directive of ~/.ssh/config after checking expect; nothing is touched when the inclusion is already active."""
    snap = _inspect()
    try:
        if snap["include"] == "active":
            return {"ok": True, "changed": False, "backup": "", "include": "active"}
        if snap["refusal"]:
            return _failure("unsafe", snap, "%s cannot be changed safely (%s)" % ("omassh.config" if snap["refusal"].startswith("managed-") else "~/.ssh/config", snap["refusal"]))
        if expect != snap["expect"]:
            return _failure("conflict", snap, "~/.ssh/config changed since the preview")
        data = snap["data"] or b""
        try:
            backup = _install(snap, _splice(data, insert_point(data)[0]))
        except safefile.Refused as exc:
            return _failure(FAILURES.get(exc.code, "unsafe"), snap, exc.detail or exc.code, "group" if exc.code == "group" else "")
        state = sshconfig.load(managed_path=hostfile.managed_path())["managedInclude"]
        return {"ok": True, "changed": True, "backup": backup, "include": state}
    finally:
        _release(snap)
