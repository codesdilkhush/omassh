from __future__ import annotations

import os
import stat
import time
import store
import launch
import select
import signal
import tempfile
import contextlib
from typing import IO, Any
from sshconfig import clean, is_safe_path, is_valid_alias

PROC = "/proc"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
START_TIMEOUT = 20.0
STOP_WAIT = 3.0
ABORT_WAIT = 2.0
MAX_CMDLINE = 65536
MAX_LOG = 4096
MAX_MESSAGE = 200
AGENT_SOCKET = "ssh-agent.socket"


def tunnel_args(alias: str, config: str) -> list[str]:
    """Every argument after the ssh program of the background tunnel for alias; ssh reads the forwards from its config."""
    args = [
        "-N",
        "-f",
        "-o",
        "BatchMode=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "RemoteCommand=none",
        "-o",
        "PermitLocalCommand=no",
    ]
    if config:
        args += ["-F", config]
    return args + ["--", alias]


def down(alias: str, reason: str, message: str = "") -> dict:
    """The failure result of a tunnel start."""
    return {"version": 1, "alias": alias, "state": "down", "reason": reason, "message": clean(message, MAX_MESSAGE)}


def boot_id(path: str = BOOT_ID_PATH) -> str:
    """The kernel boot id, or an empty string when it cannot be read."""
    try:
        with open(path, encoding="ascii") as fh:
            value = fh.read(64).strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return value if store.BOOT_RE.fullmatch(value) else ""


def _read(path: str, limit: int) -> bytes | None:
    """Up to limit bytes of a file, or None when it cannot be read."""
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def proc_info(pid: int, proc: str = PROC) -> dict | None:
    """Start time, state, owners and arguments of a process from its /proc entry, or None."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
        return None
    base = os.path.join(proc, str(pid))
    raw_stat = _read(os.path.join(base, "stat"), 8192)
    raw_status = _read(os.path.join(base, "status"), 16384)
    raw_cmdline = _read(os.path.join(base, "cmdline"), MAX_CMDLINE + 1)
    if raw_stat is None or raw_status is None or raw_cmdline is None or len(raw_cmdline) > MAX_CMDLINE:
        return None
    fields = raw_stat.decode("utf-8", errors="replace").rpartition(")")[2].split()
    if len(fields) < 20 or not fields[19].isdecimal():
        return None
    uids = [line.split()[1:3] for line in raw_status.decode("utf-8", errors="replace").splitlines() if line.startswith("Uid:")]
    if len(uids) != 1 or len(uids[0]) != 2 or not all(u.isdecimal() for u in uids[0]):
        return None
    parts = raw_cmdline.decode("utf-8", errors="replace").split("\0")
    if parts and parts[-1] == "":
        parts.pop()
    return {"start": int(fields[19]), "state": fields[0], "uid_real": int(uids[0][0]), "uid_eff": int(uids[0][1]), "cmdline": parts}


def matches(info: dict | None, args: list[str], uid: int) -> bool:
    """True for a live process of ours whose command line is an ssh program followed by exactly args."""
    if info is None or info["state"] in ("Z", "X") or info["uid_real"] != uid or info["uid_eff"] != uid:
        return False
    cmdline = info["cmdline"]
    if len(cmdline) <= len(args) or cmdline[len(cmdline) - len(args) :] != args:
        return False
    return os.path.basename(cmdline[len(cmdline) - len(args) - 1]) == "ssh"


def verify(rec: dict, alias: str, proc: str, boot: str, uid: int) -> bool:
    """True when rec still describes the live tunnel of alias: same boot, start time, owner and rebuilt arguments."""
    config = rec.get("config", "")
    if not boot or rec.get("boot") != boot or not is_valid_alias(alias) or not (config == "" or is_safe_path(config)):
        return False
    info = proc_info(rec.get("pid"), proc)
    return info is not None and info["start"] == rec.get("start") and matches(info, tunnel_args(alias, config), uid)


def scan(args: list[str], after: int, proc: str, uid: int) -> list[tuple[int, int]]:
    """Every (pid, start) of our ssh processes running exactly args that started at or after the given start time."""
    found = []
    for name in os.listdir(proc):
        if not (name.isascii() and name.isdecimal()):
            continue
        info = proc_info(int(name), proc)
        if info is not None and info["start"] >= after and matches(info, args, uid):
            found.append((int(name), info["start"]))
    return found


def live(state: dict, proc: str = PROC, boot_path: str = BOOT_ID_PATH, uid: int | None = None) -> dict:
    """The tunnel records of state that still verify, by alias."""
    boot = boot_id(boot_path)
    uid = os.getuid() if uid is None else uid
    return {alias: rec for alias, rec in state["tunnels"].items() if verify(rec, alias, proc, boot, uid)}


def tunnel_env(env: dict, uid: int | None = None) -> dict:
    """A copy of env that never lets ssh ask through askpass and points SSH_AUTH_SOCK at the systemd user agent socket when none is set and the socket is ours."""
    out = dict(env)
    out["SSH_ASKPASS_REQUIRE"] = "never"
    runtime = env.get("XDG_RUNTIME_DIR", "")
    if env.get("SSH_AUTH_SOCK") or not os.path.isabs(runtime):
        return out
    sock = os.path.join(runtime, AGENT_SOCKET)
    try:
        info = os.lstat(sock)
    except (OSError, ValueError):
        return out
    if stat.S_ISSOCK(info.st_mode) and info.st_uid == (os.getuid() if uid is None else uid):
        out["SSH_AUTH_SOCK"] = sock
    return out


def _tail(log: IO[bytes]) -> str:
    """The last three non-empty lines of ssh's error output."""
    size = log.seek(0, os.SEEK_END)
    log.seek(max(0, size - MAX_LOG))
    lines = [line.strip() for line in log.read(MAX_LOG).decode("utf-8", errors="replace").splitlines() if line.strip()]
    return " ".join(lines[-3:])


def _exited(fd: int, timeout: float) -> bool:
    """True when the process behind the pidfd has exited, waiting at most timeout seconds; the process is not reaped."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return bool(poller.poll(int(timeout * 1000)))


def _abort(proc: Any) -> None:
    """Terminate, then kill, the process group of our own unreaped child, members included, and reap the child."""
    try:
        fd = os.pidfd_open(proc.pid)
    except OSError:
        fd = -1
    try:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, sig)
            if fd >= 0:
                _exited(fd, ABORT_WAIT)
    finally:
        if fd >= 0:
            os.close(fd)
    launch.wait(proc, ABORT_WAIT)


def _record(path: str, alias: str, pid: int, began: int, boot: str, config: str) -> dict:
    """Save the tunnel record of alias and build the success result."""
    rec = {"pid": pid, "start": began, "boot": boot, "since": int(time.time()), "config": config}
    store.modify(path, lambda s: store.set_tunnel(s, alias, rec))
    return {"version": 1, "alias": alias, "state": "up", "since": rec["since"], "already": False}


def start(alias: str, config: str, ssh_path: str | None, path: str, timeout: float = START_TIMEOUT) -> dict:
    """Bring up the tunnel of alias in the background and record it; the result is the JSON the CLI prints."""
    if not ssh_path:
        return down(alias, "ssh-missing", "ssh was not found")
    boot = boot_id()
    if not is_valid_alias(alias) or not (config == "" or is_safe_path(config)) or not boot:
        return down(alias, "failed", "cannot start the tunnel")
    uid = os.getuid()
    args = tunnel_args(alias, config)
    with store.tunnel_lock(path):
        recorded = store.load(path)["tunnels"]
        current = recorded.get(alias)
        if current is not None and verify(current, alias, PROC, boot, uid):
            return {"version": 1, "alias": alias, "state": "up", "since": current["since"], "already": True}
        if alias not in recorded and len(recorded) >= store.MAX_TUNNELS:
            return down(alias, "limit", "%d tunnels are already running" % store.MAX_TUNNELS)
        existing = scan(args, 0, PROC, uid)
        if len(existing) > 1:
            return down(alias, "ambiguous", "several identical tunnels are already running")
        if existing:
            result = _record(path, alias, existing[0][0], existing[0][1], boot, config)
            result["already"] = True
            return result
        with tempfile.TemporaryFile(dir=os.path.dirname(path)) as log:
            try:
                child = launch.spawn([ssh_path, *args], stderr=log.fileno(), env=tunnel_env(os.environ, uid))
            except OSError as exc:
                return down(alias, "failed", exc.strerror or "cannot run ssh")
            info = proc_info(child.pid)
            began = info["start"] if info else 0
            code = launch.wait(child, timeout)
            if code is None:
                _abort(child)
                return down(alias, "timeout", "ssh did not finish connecting in %g seconds" % timeout)
            if code != 0:
                return down(alias, "failed", _tail(log))
        found = scan(args, began, PROC, uid)
        if not found:
            return down(alias, "vanished", "ssh exited without leaving a tunnel running")
        if len(found) > 1:
            return down(alias, "ambiguous", "several tunnels match; none was recorded")
        return _record(path, alias, found[0][0], found[0][1], boot, config)


def _terminate(rec: dict, alias: str, boot: str, uid: int) -> str:
    """Signal a verified tunnel through its pidfd; returns stopped, stale or running."""
    try:
        fd = os.pidfd_open(rec["pid"])
    except OSError:
        return "stale"
    try:
        if not verify(rec, alias, PROC, boot, uid):
            return "stale"
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        except OSError:
            return "stale"
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        return "stopped" if poller.poll(int(STOP_WAIT * 1000)) else "running"
    finally:
        os.close(fd)


def _stop_one(alias: str, path: str, boot: str, uid: int) -> str:
    """Stop the recorded tunnel of alias and forget it unless it kept running."""
    rec = store.load(path)["tunnels"].get(alias)
    if rec is None:
        return "stale"
    outcome = _terminate(rec, alias, boot, uid)
    if outcome != "running":
        store.modify(path, lambda s: store.drop_tunnel(s, alias, rec))
    return outcome


def stop(alias: str, path: str) -> dict:
    """Stop the recorded tunnel of alias after verifying it is still that process; unrelated processes are never signalled."""
    with store.tunnel_lock(path):
        outcome = _stop_one(alias, path, boot_id(), os.getuid())
    return {"version": 1, "alias": alias, "state": "up" if outcome == "running" else "down", "stopped": outcome == "stopped"}


def stop_all(path: str) -> dict:
    """Stop every recorded tunnel; the result lists the aliases that were stopped."""
    boot, uid = boot_id(), os.getuid()
    with store.tunnel_lock(path):
        stopped = [alias for alias in sorted(store.load(path)["tunnels"]) if _stop_one(alias, path, boot, uid) == "stopped"]
    return {"version": 1, "stopped": stopped}


def prune(path: str, proc: str = PROC, boot_path: str = BOOT_ID_PATH, uid: int | None = None) -> list[str]:
    """Drop the records that no longer verify and return their aliases."""
    boot = boot_id(boot_path)
    uid = os.getuid() if uid is None else uid
    stale = [alias for alias, rec in store.load(path)["tunnels"].items() if not verify(rec, alias, proc, boot, uid)]
    if not stale:
        return []
    dropped: list[str] = []

    def change(state: dict) -> None:
        """Remove each stale record that still fails verification under the state lock."""
        for alias in stale:
            rec = state["tunnels"].get(alias)
            if rec is not None and not verify(rec, alias, proc, boot, uid):
                store.drop_tunnel(state, alias, rec)
                dropped.append(alias)

    store.modify(path, change)
    return dropped
