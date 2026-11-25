from __future__ import annotations

import os
import re
import json
import errno
import fcntl
import tempfile
import contextlib
from collections.abc import Callable, Iterator
from sshconfig import is_safe_path, is_valid_alias

STATE_VERSION = 2
MAX_STATE_BYTES = 256 * 1024
MAX_ENTRIES = 500
MAX_TUNNELS = 64
PID_MIN = 2
PID_MAX = 4_194_304
START_MAX = 2**63 - 1
TS_MIN = 1
TS_MAX = 4_102_444_800
BOOT_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def state_path(env: dict | None = None) -> str:
    """Location of the state file under an absolute XDG_STATE_HOME, else under ~/.local/state."""
    env = os.environ if env is None else env
    base = env.get("XDG_STATE_HOME", "")
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "omassh", "state.json")


def empty() -> dict:
    """A state with nothing pinned, used or running."""
    return {"version": STATE_VERSION, "pinned": [], "recent": {}, "tunnels": {}}


def _int_in(value: object, low: int, high: int) -> bool:
    """True for a real int (not a bool) within the inclusive range."""
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _valid_tunnel(rec: object) -> dict | None:
    """A clean tunnel record, or None unless every field is valid."""
    if not isinstance(rec, dict):
        return None
    pid, start, boot, since, config = (rec.get(k) for k in ("pid", "start", "boot", "since", "config"))
    if not (_int_in(pid, PID_MIN, PID_MAX) and _int_in(start, 0, START_MAX) and _int_in(since, TS_MIN, TS_MAX)):
        return None
    if not (isinstance(boot, str) and BOOT_RE.fullmatch(boot)):
        return None
    if not (config == "" or (is_safe_path(config) and len(config) <= 4096)):
        return None
    return {"pid": pid, "start": start, "boot": boot, "since": since, "config": config}


def sanitize(raw: object) -> dict:
    """Return a clean state dict built only from valid parts of ``raw``."""
    state = empty()
    if not isinstance(raw, dict):
        return state
    pinned = raw.get("pinned")
    if isinstance(pinned, list):
        seen: set[str] = set()
        for alias in pinned:
            if is_valid_alias(alias) and alias not in seen and len(seen) < MAX_ENTRIES:
                seen.add(alias)
                state["pinned"].append(alias)
    recent = raw.get("recent")
    if isinstance(recent, dict):
        items = []
        for alias, ts in recent.items():
            if is_valid_alias(alias) and isinstance(ts, int) and not isinstance(ts, bool) and TS_MIN <= ts <= TS_MAX:
                items.append((alias, ts))
        items.sort(key=lambda kv: kv[1], reverse=True)
        state["recent"] = dict(items[:MAX_ENTRIES])
    tunnels = raw.get("tunnels")
    if isinstance(tunnels, dict):
        state["tunnels"] = {alias: rec for alias, raw_rec in tunnels.items() if is_valid_alias(alias) and (rec := _valid_tunnel(raw_rec))}
    return state


def _quarantine(path: str) -> None:
    """Move an unusable state file aside so the next save does not trip over it."""
    with contextlib.suppress(OSError):
        os.replace(path, path + ".corrupt")


def load(path: str) -> dict:
    """Read the state file; missing, oversize or corrupt means "empty"."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return empty()
    try:
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_STATE_BYTES + 1)
    except OSError:
        return empty()
    finally:
        os.close(fd)
    if len(data) > MAX_STATE_BYTES:
        _quarantine(path)
        return empty()
    try:
        return sanitize(json.loads(data.decode("utf-8")))
    except (ValueError, UnicodeDecodeError, RecursionError):
        _quarantine(path)
        return empty()


def save(path: str, state: dict) -> None:
    """Atomically write ``state`` (re-sanitised and bounded to MAX_STATE_BYTES) with owner-only permissions."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    clean_state = sanitize(state)
    payload = json.dumps(clean_state, sort_keys=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_STATE_BYTES and clean_state["recent"]:
        by_time = sorted(clean_state["recent"].items(), key=lambda kv: kv[1], reverse=True)
        while by_time and len(payload.encode("utf-8")) > MAX_STATE_BYTES:
            by_time.pop()
            clean_state["recent"] = dict(by_time)
            payload = json.dumps(clean_state, sort_keys=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_STATE_BYTES:
        raise OSError(errno.EFBIG if hasattr(errno, "EFBIG") else 27, "state exceeds maximum size")
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def _locked(lock_path: str) -> Iterator[None]:
    """Hold an exclusive lock on lock_path for the duration of the block."""
    os.makedirs(os.path.dirname(lock_path), mode=0o700, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def modify(path: str, change: Callable[[dict], None]) -> dict:
    """Load, apply ``change`` in place, save -- all under one lock."""
    with _locked(path + ".lock"):
        state = load(path)
        change(state)
        save(path, state)
        return sanitize(state)


def tunnel_lock(path: str) -> contextlib.AbstractContextManager[None]:
    """Exclusive lock held for a whole tunnel start or stop, separate from the pins and recents lock."""
    return _locked(path + ".tunnels.lock")


def hosts_lock(path: str) -> contextlib.AbstractContextManager[None]:
    """Exclusive lock held for a whole host file edit; always taken before the tunnel lock and the state lock."""
    return _locked(path + ".hosts.lock")


def record_use(state: dict, alias: str, now: int) -> None:
    """Remember that alias was used at the given time."""
    state["recent"][alias] = int(now)


def set_pinned(state: dict, alias: str, pinned: bool) -> None:
    """Pin alias (moving it to the end of the pins, capped at MAX_ENTRIES) or unpin it."""
    current = [a for a in state["pinned"] if a != alias]
    if pinned:
        if len(current) >= MAX_ENTRIES:
            current = current[-(MAX_ENTRIES - 1) :]
        current.append(alias)
    state["pinned"] = current


def set_tunnel(state: dict, alias: str, rec: dict) -> None:
    """Remember rec as the tunnel of alias."""
    state["tunnels"][alias] = rec


def drop_tunnel(state: dict, alias: str, rec: dict | None = None) -> None:
    """Forget the tunnel of alias; with rec, only when the stored pid and start still match it."""
    current = state["tunnels"].get(alias)
    if current is not None and (rec is None or (current["pid"], current["start"]) == (rec["pid"], rec["start"])):
        del state["tunnels"][alias]


def forget(state: dict, alias: str) -> None:
    """Drop the pin and the recent entry of alias."""
    set_pinned(state, alias, False)
    state["recent"].pop(alias, None)


def rename(state: dict, old: str, new: str) -> None:
    """Move the pin of old to new keeping its position, and move its recent entry, keeping the later of two timestamps."""
    if old == new:
        return
    pinned = [new if alias == old else alias for alias in state["pinned"]]
    state["pinned"] = list(dict.fromkeys(pinned))
    if old in state["recent"]:
        stamp = state["recent"].pop(old)
        state["recent"][new] = max(stamp, state["recent"].get(new, stamp))
