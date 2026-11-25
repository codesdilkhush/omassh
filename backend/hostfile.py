from __future__ import annotations

import os
import launch
import hostform
import safefile
from sshconfig import clean
from collections.abc import Callable

NAME = "omassh.config"
BACKUP = "omassh.config.bak"
CHECK_TIMEOUT = 5.0
CHECK_LIMIT = 65536
MAX_MESSAGE = 200


def ssh_dir() -> str:
    """The ssh directory of the current user."""
    return os.path.join(os.path.expanduser("~"), ".ssh")


def managed_path() -> str:
    """The path of the plugin-owned host file."""
    return os.path.join(ssh_dir(), NAME)


def load_managed_state(dfd: int) -> tuple[list | None, bytes | None, os.stat_result | None, str, str, bytes | None]:
    """The hosts, bytes, status, state (missing, ok, foreign or unsafe), refusal code and POSIX ACL of the host file inside dfd."""
    try:
        data, info, acl = safefile.read_state(dfd, NAME, hostform.MAX_BYTES)
    except safefile.Refused as exc:
        return None, None, None, "unsafe", exc.code, None
    if data is None:
        return [], None, None, "missing", "", None
    hosts = hostform.parse(data)
    if hosts is None:
        return None, data, info, "foreign", "", acl
    return hosts, data, info, "ok", "", acl


def load_managed(dfd: int) -> tuple[list | None, bytes | None, os.stat_result | None, str, str]:
    """The hosts, bytes, status, state (missing, ok, foreign or unsafe) and refusal code of the host file inside dfd."""
    return load_managed_state(dfd)[:5]


def peek() -> tuple[list | None, bytes | None, os.stat_result | None, str, str]:
    """load_managed for the real ssh directory without creating anything; an unusable directory reads as missing or unsafe."""
    try:
        dfd = safefile.open_dir(ssh_dir())
    except safefile.Refused as exc:
        if exc.code == "missing":
            return [], None, None, "missing", ""
        return None, None, None, "unsafe", exc.code
    try:
        return load_managed(dfd)
    finally:
        os.close(dfd)


def editor_state(parsed: dict, loaded: tuple | None) -> dict:
    """The editor block of the list reply; loaded is None when the editor is off."""
    if loaded is None:
        return {"enabled": False}
    hosts, _, _, state, reason = loaded
    shown = hosts if state == "ok" else []
    return {
        "enabled": True,
        "file": state,
        "fileReason": reason,
        "include": parsed["managedInclude"],
        "where": parsed["managedWhere"],
        "incomplete": parsed["incomplete"],
        "path": managed_path(),
        "count": len(shown),
        "hosts": [hostform.to_form(host) for host in shown],
    }


def is_editable(host: dict, editor: dict) -> bool:
    """True when the panel may edit host: the editor is on, the config was read completely, the file is canonical, ssh reads it first and only it defines the host."""
    return editor["enabled"] and not editor["incomplete"] and editor["file"] == "ok" and editor["include"] == "active" and host["origin"] == "managed"


def hops(value: str) -> list[str]:
    """The lowercase host names of the hops of a ProxyJump value; none and anything unreadable give nothing."""
    if value.strip().lower() == "none":
        return []
    names = []
    for hop in value.split(","):
        rest = hop.strip().removeprefix("ssh://").rpartition("@")[2]
        name = rest[1:].partition("]")[0] if rest.startswith("[") else rest.partition(":")[0]
        if name:
            names.append(name.lower())
    return names


def has_cycle(alias: str, original: str, host: dict, parsed: list[dict]) -> bool:
    """True when a hop of host leads, through the jump chains of the parsed hosts other than alias and original, back to alias."""
    skip = {alias.lower(), original.lower()}
    chains = {entry["alias"].lower(): entry["jump"] for entry in parsed if entry["alias"].lower() not in skip}
    pending = hops(host["proxyJump"])
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name == alias.lower():
            return True
        if name not in seen:
            seen.add(name)
            pending.extend(hops(chains.get(name, "")))
    return False


def check_with_ssh(ssh_path: str, directory: str, name: str, alias: str, host: dict) -> tuple[str, str]:
    """Ask ssh -G about alias in the candidate file name inside directory; returns a reason code and message, both empty when ssh agrees with host."""
    argv = [ssh_path, "-G", "-F", os.path.join(directory, name), "--", alias]
    try:
        status, out, err = launch.capture(argv, CHECK_TIMEOUT, CHECK_LIMIT)
    except OSError as exc:
        return "ssh-missing", clean(exc.strerror or "cannot run ssh", MAX_MESSAGE)
    if status is None:
        return "check-failed", "ssh did not answer in time"
    if status != 0:
        return "ssh-rejected", clean(" ".join(err.decode("utf-8", errors="replace").split()), MAX_MESSAGE)
    option = hostform.diff_g(hostform.dash_g(alias, host), out.decode("utf-8", errors="replace"))
    if option:
        return "check-failed", "ssh printed nothing" if option == "empty" else "ssh reports a different %s" % option
    return "", ""


def checker(ssh_path: str, directory: str, alias: str, host: dict) -> Callable[[str], None]:
    """A hook for safefile.install that refuses the candidate file unless ssh -G reports exactly host for alias."""

    def check(name: str) -> None:
        """Raise Refused unless ssh accepts the candidate file called name."""
        code, message = check_with_ssh(ssh_path, directory, name, alias, host)
        if code:
            raise safefile.Refused(code, message)

    return check


def write_hosts(
    dfd: int,
    hosts: list[dict],
    old: bytes | None,
    before: os.stat_result | None,
    check: Callable[[str], None] | None = None,
    before_acl: bytes | None = None,
) -> None:
    """Replace the host file with hosts: render, self-parse, validate through check, keep the old bytes in the backup file, then install."""
    text = hostform.render(hosts)
    if len(hosts) > hostform.MAX_HOSTS or len(text) > hostform.MAX_BYTES:
        raise safefile.Refused("limit")
    if hostform.parse(text) != hosts:
        raise safefile.Refused("check-failed", "the host file did not read back as written")
    backup = None if old is None else lambda: safefile.replace(dfd, BACKUP, old, 0o600)
    safefile.install(dfd, NAME, text.encode("ascii"), 0o600, before, check, backup, before_acl=before_acl)
