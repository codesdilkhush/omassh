from __future__ import annotations

import os
import re
import json
import stat
import hashlib
from sshconfig import clean, is_valid_alias

MAX_BYTES = 65536
MAX_COMMANDS = 50
MAX_NAME = 60
MAX_COMMAND = 1000
MAX_HOSTS = 200
PREVIEW = 80
ID_RE = re.compile(r"[0-9a-f]{16}")
EMPTY = b'{"commands": []}\n'


def commands_path(env: dict | None = None) -> str:
    """Location of the saved commands file under an absolute XDG_CONFIG_HOME, else under ~/.config."""
    env = os.environ if env is None else env
    base = env.get("XDG_CONFIG_HOME", "")
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "omassh", "commands.json")


def command_id(name: str, command: str) -> str:
    """Sixteen hex digits bound to both the name and the text of a command."""
    return hashlib.sha256((name + "\0" + command).encode("utf-8")).hexdigest()[:16]


def _plain(value: object, limit: int) -> bool:
    """True for a non-blank string of at most limit characters without control, format, separator or unassigned characters."""
    return isinstance(value, str) and 0 < len(value) <= limit and bool(value.strip()) and clean(value, limit + 1) == value


def _hosts(value: object) -> bool:
    """True when value is a short list of valid aliases."""
    return isinstance(value, list) and len(value) <= MAX_HOSTS and all(is_valid_alias(alias) for alias in value)


def _entry(raw: object) -> dict | None:
    """A clean command entry, or None when any field breaks the rules."""
    if not isinstance(raw, dict):
        return None
    name, command, hosts = raw.get("name"), raw.get("command"), raw.get("hosts")
    if not (_plain(name, MAX_NAME) and _plain(command, MAX_COMMAND) and (hosts is None or _hosts(hosts))):
        return None
    return {"id": command_id(name, command), "name": name, "command": command, "hosts": None if hosts is None else list(hosts)}


def _read(path: str) -> tuple[bytes | None, str]:
    """The file contents (None when it does not exist or is unusable) and an error code; a missing file is no error."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return None, ""
    except OSError:
        return None, "invalid"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "not-regular"
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            return None, "insecure"
        if info.st_size > MAX_BYTES:
            return None, "too-large"
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_BYTES + 1)
    except OSError:
        return None, "invalid"
    finally:
        os.close(fd)
    return (data, "") if len(data) <= MAX_BYTES else (None, "too-large")


def _ours(path: str) -> bool:
    """True when path, following symlinks, is a regular file owned by the current user."""
    try:
        info = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()


def ensure(path: str) -> str:
    """Create the commands file with an empty list when it is missing; an error code when the path holds something else or cannot be created, else an empty string."""
    for _ in range(2):
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError:
            return "invalid"
        else:
            return "" if _ours(path) else "not-regular"
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            continue
        except OSError:
            return "invalid"
        try:
            os.write(fd, EMPTY)
        except OSError:
            return "invalid"
        finally:
            os.close(fd)
        return ""
    return "invalid"


def load(path: str) -> dict:
    """Read the saved commands: the valid entries, an error code and the number of entries skipped."""
    result = {"commands": [], "error": "", "skipped": 0}
    data, error = _read(path)
    if data is None:
        result["error"] = error
        return result
    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        result["error"] = "invalid"
        return result
    raw = doc.get("commands") if isinstance(doc, dict) else None
    if not isinstance(raw, list):
        result["error"] = "invalid"
    elif len(raw) > MAX_COMMANDS:
        result["error"] = "too-large"
    else:
        seen: set[str] = set()
        for item in raw:
            entry = _entry(item)
            if entry is None or entry["id"] in seen:
                result["skipped"] += 1
                continue
            seen.add(entry["id"])
            result["commands"].append(entry)
    return result


def summary(loaded: dict) -> list[dict]:
    """The commands as shown to the panel: id, name, a short preview and the host restriction, never the full text."""
    return [{"id": e["id"], "name": e["name"], "preview": clean(e["command"], PREVIEW), "hosts": e["hosts"]} for e in loaded["commands"]]


def find(loaded: dict, cid: object, alias: str | None) -> str | None:
    """The text of the command with this id when it is allowed for alias and still hashes to the id, else None."""
    if not (isinstance(cid, str) and ID_RE.fullmatch(cid)):
        return None
    for entry in loaded["commands"]:
        if entry["id"] == cid:
            hosts = entry["hosts"]
            if command_id(entry["name"], entry["command"]) != cid or (hosts is not None and alias not in hosts):
                return None
            return entry["command"]
    return None
