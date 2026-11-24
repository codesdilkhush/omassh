from __future__ import annotations

import re
import hashlib
import ipaddress
from collections.abc import Callable
from sshconfig import ALIAS_RE, COPY_USER_RE

HEADER = "# OmaSSH host file. Edit these hosts in the OmaSSH panel; a hand edit makes the panel leave this file alone."
FIELDS = ("alias", "hostname", "user", "port", "proxyJump", "identityFile")
KEYWORDS = {
    "hostname": "HostName",
    "user": "User",
    "port": "Port",
    "proxyJump": "ProxyJump",
    "identityFile": "IdentityFile",
    "L": "LocalForward",
    "R": "RemoteForward",
    "D": "DynamicForward",
}
MAX_HOSTS = 200
MAX_BYTES = 262144
MAX_HOPS = 8
MAX_FORWARDS = 16
LIMITS = {"alias": 128, "hostname": 253, "user": 64, "port": 5, "proxyJump": 1024, "identityFile": 1024, "forward": 300}
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
IPV6_RE = re.compile(r"[0-9A-Fa-f:.]{2,45}")
IDENTITY_RE = re.compile(r"~?(?:/[A-Za-z0-9._+@-]+)+")
LOOPBACK = ("localhost", "127.0.0.1")
LOOPBACK_V6 = "[::1]"

_SCALARS = ("hostname", "user", "port", "proxyJump", "identityFile")
_PREFIXES = {"    %s " % keyword: field for field, keyword in KEYWORDS.items()}
_KINDS = {"L": "L", "l": "L", "R": "R", "r": "R", "D": "D", "d": "D"}
_ARITY = {"L": (3,), "R": (2, 3), "D": (2,)}
_ORDER = {"L": 0, "R": 1, "D": 2}
_GAP_RE = re.compile(r"[ \t]+")
_NUMERIC_HOP_RE = re.compile(r"\[([0-9.]+)\]")
_NUMBER_RE = re.compile(r"[0-9]+|0[xX][0-9A-Fa-f]*")
_OCTET_RE = re.compile(r"0|[1-9][0-9]{0,2}")


def _trim(value: str) -> str:
    """Drop leading and trailing spaces and tabs, and nothing else."""
    return value.strip(" \t")


def _port(value: str) -> bool:
    """True for a decimal port from 1 to 65535 written without leading zeros."""
    return PORT_RE.fullmatch(value) is not None and int(value) <= 65535


def _ipv6(value: str) -> bool:
    """True for a bare IPv6 address without brackets or zone."""
    if IPV6_RE.fullmatch(value) is None or ":" not in value:
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _canonical_v6(value: str) -> str:
    """The canonical text of a bare IPv6 hostname, or an empty string when it is invalid or in the IPv4-compatible range, which ssh prints in another form."""
    if not _ipv6(value):
        return ""
    address = ipaddress.IPv6Address(value)
    if address.packed[:12] == bytes(12) and int(address) > 1:
        return ""
    return str(address)


def _shorthand(value: str) -> bool:
    """True for a number-only host that the resolver reads as an address other than a plain dotted quad, such as 9, 010.1 or 0x7f.1."""
    parts = value.split(".")
    if len(parts) > 4 or not all(_NUMBER_RE.fullmatch(part) for part in parts):
        return False
    return not (len(parts) == 4 and all(_OCTET_RE.fullmatch(part) and int(part) <= 255 for part in parts))


def _name(value: str) -> bool:
    """True for a DNS name or an IPv4 address that the resolver reads literally."""
    return NAME_RE.fullmatch(value) is not None and not _shorthand(value)


def _hop(value: str, alias: str) -> str:
    """The error code for one ProxyJump hop, or an empty string when it is valid."""
    if value.lower() == "none":
        return "hop"
    user, at, rest = value.rpartition("@")
    if at and COPY_USER_RE.fullmatch(user) is None:
        return "hop"
    if rest.startswith("["):
        close = rest.find("]")
        host, tail = rest[1:close], rest[close + 1 :]
        if close < 0 or not _ipv6(host):
            return "hop"
    else:
        host, colon, port = rest.partition(":")
        tail = colon + port
        if not _name(host):
            return "hop"
    if tail and not (tail[0] == ":" and _port(tail[1:])):
        return "hop"
    return "self" if host.lower() == alias.lower() else ""


def _endpoint(value: str, listen: bool) -> bool:
    """True for a forward listen address (bare port or loopback) or, when listen is false, a target host and port."""
    if value.startswith("["):
        close = value.find("]")
        host, tail = value[: close + 1], value[close + 1 :]
        valid = host == LOOPBACK_V6 if listen else close > 0 and _ipv6(host[1:-1])
    else:
        host, colon, port = value.partition(":")
        if listen and not colon:
            return _port(value)
        tail = colon + port
        valid = host in LOOPBACK if listen else _name(host)
    return valid and tail[:1] == ":" and _port(tail[1:])


def _forward(row: str) -> list[str] | None:
    """The canonical tokens of one forward row, or None when it is not valid."""
    tokens = _GAP_RE.split(row)
    kind = _KINDS.get(tokens[0])
    if kind is None or len(tokens) not in _ARITY[kind]:
        return None
    if not _endpoint(tokens[1], True):
        return None
    if kind == "L" or (kind == "R" and len(tokens) == 3):
        if not _endpoint(tokens[2], False):
            return None
    return [kind, *tokens[1:]]


def _text(raw: dict, field: str) -> str | None:
    """The trimmed string value of field, or None when it is not a string."""
    value = raw.get(field, "")
    return _trim(value) if isinstance(value, str) else None


def _alias(value: str | None) -> str:
    """The error code for an alias, or an empty string."""
    if value is None:
        return "invalid"
    if not value:
        return "required"
    if len(value) > LIMITS["alias"]:
        return "too-long"
    return "" if ALIAS_RE.fullmatch(value) else "invalid"


def _hostname(value: str) -> str:
    """The error code for a hostname, or an empty string."""
    if len(value) > LIMITS["hostname"]:
        return "too-long"
    return "" if not value or _name(value) or _canonical_v6(value) else "invalid"


def _user(value: str) -> str:
    """The error code for a user name, or an empty string."""
    if len(value) > LIMITS["user"]:
        return "too-long"
    return "" if not value or COPY_USER_RE.fullmatch(value) else "invalid"


def _port_code(value: str) -> str:
    """The error code for a port, or an empty string."""
    return "" if not value or (len(value) <= LIMITS["port"] and _port(value)) else "port"


def _jump(value: str, alias: str) -> str:
    """The error code for a ProxyJump list, or an empty string."""
    if len(value) > LIMITS["proxyJump"]:
        return "too-long"
    if not value:
        return ""
    hops = [_trim(hop) for hop in value.split(",")]
    if len(hops) > MAX_HOPS:
        return "too-many"
    for hop in hops:
        code = _hop(hop, alias)
        if code:
            return code
    return ""


def _identity(value: str, exists: Callable[[str], bool]) -> str:
    """The error code for an IdentityFile path, or an empty string."""
    if len(value) > LIMITS["identityFile"]:
        return "too-long"
    if not value:
        return ""
    if IDENTITY_RE.fullmatch(value) is None or any(part in (".", "..") for part in value.split("/")):
        return "invalid"
    try:
        found = exists(value)
    except (OSError, ValueError):
        found = False
    return "" if found else "not-found"


def _forwards(raw: dict) -> tuple[list[str], list[dict]]:
    """Canonical forward rows ordered by kind, plus the errors found in the submitted rows."""
    rows = raw.get("forwards", [])
    if not isinstance(rows, list):
        return [], [{"field": "forwards", "code": "invalid"}]
    errors: list[dict] = []
    found: list[tuple[int, str]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, str):
            errors.append({"field": "forwards", "index": index, "code": "forward"})
        elif _trim(row):
            found.append((index, _trim(row)))
    if len(found) > MAX_FORWARDS:
        return [], [{"field": "forwards", "code": "too-many"}]
    seen: set[str] = set()
    canonical: list[str] = []
    for index, row in found:
        tokens = None if len(row) > LIMITS["forward"] else _forward(row)
        line = " ".join(tokens) if tokens else ""
        code = "too-long" if len(row) > LIMITS["forward"] else "forward" if tokens is None else "duplicate" if line in seen else ""
        if code:
            errors.append({"field": "forwards", "index": index, "code": code})
        else:
            seen.add(line)
            canonical.append(line)
    canonical.sort(key=lambda line: _ORDER[line[0]])
    return canonical, errors


def normalize(raw: dict, exists: Callable[[str], bool]) -> tuple[dict | None, list[dict]]:
    """The canonical host for the submitted form values, or the list of field errors; never raises."""
    if not isinstance(raw, dict):
        return None, [{"field": "alias", "code": "required"}]
    values = {field: _text(raw, field) for field in FIELDS}
    name = values["alias"] or ""
    checks = {
        "alias": _alias,
        "hostname": _hostname,
        "user": _user,
        "port": _port_code,
        "proxyJump": lambda value: _jump(value, name),
        "identityFile": lambda value: _identity(value, exists),
    }
    errors = []
    for field in FIELDS:
        code = "invalid" if values[field] is None else checks[field](values[field])
        if code:
            errors.append({"field": field, "code": code})
    if not errors and not values["hostname"] and _shorthand(name):
        errors.append({"field": "alias", "code": "invalid"})
    forwards, forward_errors = _forwards(raw)
    errors.extend(forward_errors)
    if errors:
        return None, errors
    host = dict(values)
    host["hostname"] = _canonical_v6(values["hostname"]) or values["hostname"].lower()
    host["proxyJump"] = ",".join(_trim(hop) for hop in values["proxyJump"].split(",")) if values["proxyJump"] else ""
    host["forwards"] = forwards
    return host, []


def block_hash(host: dict) -> str:
    """The first 16 hex characters of the sha256 of the host's canonical block."""
    return hashlib.sha256(render_block(host).encode("ascii")).hexdigest()[:16]


def to_form(host: dict) -> dict:
    """The form values of a canonical host together with its block hash."""
    form = {field: host[field] for field in FIELDS}
    form["forwards"] = list(host["forwards"])
    form["expect"] = block_hash(host)
    return form


def render_block(host: dict) -> str:
    """The canonical text of one host block."""
    lines = ["Host " + host["alias"]]
    lines.extend("    %s %s" % (KEYWORDS[field], host[field]) for field in _SCALARS if host[field])
    for row in host["forwards"]:
        lines.append("    %s %s" % (KEYWORDS[row[0]], row[2:]))
    return "\n".join(lines) + "\n"


def render(hosts: list[dict]) -> str:
    """The canonical text of the managed file for hosts."""
    return HEADER + "\n" + "".join("\n" + render_block(host) for host in hosts)


def _collect(lines: list[str]) -> list[dict] | None:
    """The raw host values found in the body lines of the managed file, or None for an unknown line."""
    raws: list[dict] = []
    for line in lines:
        if not line:
            continue
        if line.startswith("Host "):
            raws.append({"alias": line[5:], "forwards": []})
            continue
        prefix = next((p for p in _PREFIXES if line.startswith(p)), None)
        if prefix is None or not raws:
            return None
        field, value = _PREFIXES[prefix], line[len(prefix) :]
        if field in _ORDER:
            raws[-1]["forwards"].append("%s %s" % (field, value))
        else:
            raws[-1][field] = value
    return raws


def parse(data: bytes | str) -> list[dict] | None:
    """The hosts of a managed file, or None unless rendering them gives back exactly the same text."""
    try:
        text = (data if isinstance(data, bytes) else data.encode("ascii")).decode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None
    lines = text.split("\n")
    if len(text) > MAX_BYTES or lines[0] != HEADER or lines[-1] != "":
        return None
    raws = _collect(lines[1:-1])
    if raws is None or len(raws) > MAX_HOSTS:
        return None
    hosts = []
    for raw in raws:
        host, _ = normalize(raw, lambda path: True)
        if host is None:
            return None
        hosts.append(host)
    if len({host["alias"] for host in hosts}) != len(hosts) or render(hosts) != text:
        return None
    return hosts


def _g_endpoint(token: str) -> str:
    """A forward endpoint the way ssh -G prints it."""
    if token.startswith("[") or PORT_RE.fullmatch(token):
        return token
    host, _, port = token.rpartition(":")
    return "[%s]:%s" % (host, port)


def _g_forward(row: str) -> tuple[str, str]:
    """The ssh -G option name and value line of one canonical forward row."""
    tokens = row.split(" ")
    line = _g_endpoint(tokens[1])
    if tokens[0] == "R" and len(tokens) == 2:
        line += " [socks]:0"
    elif tokens[0] != "D":
        line += " " + _g_endpoint(tokens[2])
    return KEYWORDS[tokens[0]].lower(), line


def dash_g(alias: str, host: dict) -> dict:
    """What ssh -G must report for host: exact values, absent options, options that must appear and ordered lists."""
    equal = {"hostname": (host["hostname"] or alias).lower(), "port": host["port"] or "22", "clearallforwardings": "no"}
    absent = []
    if host["user"]:
        equal["user"] = host["user"]
    if host["proxyJump"]:
        equal["proxyjump"] = host["proxyJump"]
    else:
        absent.append("proxyjump")
    among = {"identityfile": host["identityFile"]} if host["identityFile"] else {}
    ordered: dict[str, list[str]] = {"localforward": [], "remoteforward": [], "dynamicforward": []}
    for row in host["forwards"]:
        name, line = _g_forward(row)
        ordered[name].append(line)
    return {"equal": equal, "absent": absent, "among": among, "ordered": ordered}


def diff_g(expected: dict, output: str) -> str:
    """The name of the first option where the ssh -G output differs from expected, or an empty string."""
    seen: dict[str, list[str]] = {}
    for line in filter(None, output.splitlines()):
        key, _, value = line.partition(" ")
        seen.setdefault(key, []).append(value)
    if not seen:
        return "empty"
    for key, value in expected["equal"].items():
        got = seen.get(key, [None])[0]
        if key == "proxyjump" and got is not None:
            got = _NUMERIC_HOP_RE.sub(r"\1", got)
        if got != value:
            return key
    for key in expected["absent"]:
        if key in seen:
            return key
    for key, value in expected["among"].items():
        if value not in seen.get(key, []):
            return key
    for key, lines in expected["ordered"].items():
        if seen.get(key, []) != lines:
            return key
    return ""
