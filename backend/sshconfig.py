from __future__ import annotations

import os
import re
import glob
import stat
import ipaddress
import unicodedata

MAX_FILE_BYTES = 1 << 20
MAX_FILES = 50
MAX_DEPTH = 5
MAX_HOSTS = 2000
MAX_BLOCKS = 5000
MAX_WORK = 2_000_000
MAX_NOTES = 50
MAX_FIELD = 255

ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
CONFIG_PATH_RE = re.compile(r"/[A-Za-z0-9._+@:,=/-]*")
COPY_USER_RE = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]{0,63}")
COPY_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
COPY_LITERAL_RE = re.compile(r"[0-9A-Fa-f:.]{2,45}")

MAX_FORWARDS = 32
MAX_FORWARD_LINES = 5000
FORWARD_FIELD = 64

_RESOLVED = ("hostname", "user", "port", "proxyjump", "proxycommand", "clearallforwardings", "canonicalizehostname")
_ROUTING = ("hostname", "port", "proxyjump", "proxycommand", "canonicalizehostname")
_FORWARDS = {"localforward": "L", "remoteforward": "R", "dynamicforward": "D"}
_FORWARD_ARGS = {"L": (2,), "R": (1, 2), "D": (1,)}
_BOOLEANS = {"yes": True, "true": True, "no": False, "false": False}

_SPACE = " \t\r\f\v"
_ORIGIN_BITS = {"config": 1, "managed": 2}
_ORIGINS = {1: "config", 2: "managed", 3: "both"}
_INCLUDE_RANK = {"missing": 0, "scoped": 1, "late": 2, "active": 3}
SYSTEM_CONFIG_PATH = "/etc/ssh/ssh_config"
_DEFAULT = object()


def is_valid_alias(value: object) -> bool:
    """True when ``value`` is safe to use as an ``ssh`` destination alias."""
    return isinstance(value, str) and ALIAS_RE.fullmatch(value) is not None


def is_safe_path(value: object) -> bool:
    """True when ``value`` is an absolute path made only of shell-neutral characters."""
    return isinstance(value, str) and CONFIG_PATH_RE.fullmatch(value) is not None


def clean(value: object, limit: int = MAX_FIELD) -> str:
    """Make ``value`` safe to display: drop control/format/separator chars."""
    out = []
    for ch in str(value):
        cat = unicodedata.category(ch)
        if cat[0] == "C" or cat in ("Zl", "Zp"):
            continue
        out.append(ch)
        if len(out) >= limit:
            break
    return "".join(out)


def split_args(text: str) -> list[str]:
    """Split the argument part of a config line the way ssh does."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in _SPACE:
            i += 1
            continue
        if ch == "#":
            break
        buf: list[str] = []
        quote = ""
        while i < n:
            ch = text[i]
            if ch == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt in "'\"\\" or (not quote and nxt == " "):
                    buf.append(nxt)
                    i += 2
                    continue
            if quote:
                if ch == quote:
                    quote = ""
                else:
                    buf.append(ch)
                i += 1
                continue
            if ch in _SPACE:
                break
            if ch in "'\"":
                quote = ch
                i += 1
                continue
            buf.append(ch)
            i += 1
        if quote:
            raise ValueError("unterminated quote")
        tokens.append("".join(buf))
    return tokens


def split_keyword(line: str) -> tuple[str, str] | None:
    """Split a config line into keyword and arguments; None for blank lines and comments."""
    s = line.strip(_SPACE + "\n")
    if not s or s.startswith("#"):
        return None
    i, n = 0, len(s)
    while i < n and s[i] not in _SPACE and s[i] != "=":
        i += 1
    keyword = s[:i]
    while i < n and s[i] in _SPACE:
        i += 1
    if i < n and s[i] == "=":
        i += 1
    while i < n and s[i] in _SPACE:
        i += 1
    return keyword, s[i:]


def _parse_port(value: str) -> int | None:
    """The port number in value, or None when it is not a valid port."""
    if value.isascii() and value.isdigit() and len(value) <= 5:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    return None


def _wild_match(pattern: str, text: str, ctx: _Context) -> bool:
    """Match text against an ssh pattern (* and ?, case-sensitive) in bounded time."""
    ctx.work += 1 + len(pattern)
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "*":
            star = p
            mark = t
            p += 1
        elif p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


class _Context:

    def __init__(self, ssh_dir: str, managed_real: str = "", system_dir: str = "") -> None:
        """Start an empty parse of the configuration under ssh_dir; managed_real is the real path of the plugin-owned file."""
        self.ssh_dir = ssh_dir
        self.system_dir = system_dir
        self.managed_real = managed_real
        self.origins: dict[str, int] = {}
        self.directive_seen = False
        self.managed_include = "missing"
        self.managed_where: dict | None = None
        self.open_files: list[str] = []
        self.files = 0
        self.skipped = 0
        self.errors: list[dict] = []
        self.work = 0
        self.seq = 0
        self.global_block: dict = {"kind": "global", "pos": [], "neg": [], "opts": {}, "parent": None, "fwd": []}
        self.forward_lines = 0
        self.too_many_forwards = False
        self.blocks: list[dict] = [self.global_block]
        self.candidates: dict[str, tuple[str, int]] = {}
        self.too_many_hosts = False
        self.too_many_blocks = False
        self.incomplete = False

    def error(self, path: str, message: str) -> None:
        """Record a short note about path, up to a fixed number of notes."""
        if len(self.errors) < MAX_NOTES:
            self.errors.append({"file": clean(os.path.basename(path), 80), "message": clean(message, 120)})


def _read_text(path: str, ctx: _Context) -> str | None:
    """Read one bounded regular file; report (don't raise) on trouble."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        ctx.incomplete = True
        ctx.error(path, exc.strerror or "cannot open")
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            ctx.incomplete = True
            ctx.error(path, "not a regular file")
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        ctx.incomplete = True
        ctx.error(path, exc.strerror or "cannot read")
        return None
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        ctx.incomplete = True
        ctx.error(path, "file too large (over 1 MiB), skipped")
        return None
    if data.startswith(b"\xef\xbb\xbf"):
        ctx.incomplete = True
        ctx.error(path, "starts with a byte order mark")
        return None
    return data.decode("utf-8", errors="replace")


def _new_block(kind: str, pos: list[str], neg: list[str], enclosing: dict, path: str, ctx: _Context) -> dict:
    """A new Host or Match block inside enclosing, registered unless the block cap is reached."""
    block = {"kind": kind, "pos": pos, "neg": neg, "opts": {}, "parent": enclosing, "fwd": []}
    if len(ctx.blocks) >= MAX_BLOCKS:
        ctx.incomplete = True
        if not ctx.too_many_blocks:
            ctx.too_many_blocks = True
            ctx.error(path, "more than %d Host/Match blocks, the rest are ignored" % MAX_BLOCKS)
        return block
    ctx.blocks.append(block)
    return block


def _host_line(args: list[str], enclosing: dict, path: str, lineno: int, ctx: _Context, is_system: bool = False) -> dict:
    """Handle a ``Host`` line: register its aliases, open a block."""
    pos = [a for a in args if not a.startswith("!")]
    neg = [a[1:] for a in args if a.startswith("!")]
    bit = _ORIGIN_BITS["managed" if ctx.managed_real and ctx.open_files[-1] == ctx.managed_real else "config"]
    if not is_system:
        for pattern in pos:
            if "*" in pattern or "?" in pattern:
                continue
            if not is_valid_alias(pattern):
                ctx.skipped += 1
                continue
            if pattern not in ctx.candidates:
                if len(ctx.candidates) >= MAX_HOSTS:
                    ctx.incomplete = True
                    if not ctx.too_many_hosts:
                        ctx.too_many_hosts = True
                        ctx.error(path, "more than %d hosts, the rest are ignored" % MAX_HOSTS)
                    continue
                ctx.candidates[pattern] = (clean(os.path.basename(path), 80), lineno)
            ctx.origins[pattern] = ctx.origins.get(pattern, 0) | bit
    return _new_block("host", pos, neg, enclosing, path, ctx)


def _note_managed(current: dict, lineno: int, ctx: _Context) -> None:
    """Record how the managed file is included: active before any directive at global scope, late after one, scoped inside a block."""
    if current is not ctx.global_block:
        state = "scoped"
    else:
        state = "late" if ctx.directive_seen else "active"
    if _INCLUDE_RANK[state] > _INCLUDE_RANK[ctx.managed_include]:
        ctx.managed_include = state
        ctx.managed_where = {"file": clean(os.path.basename(ctx.open_files[-1]), 80), "line": lineno}


def _include(pattern: str, depth: int, current: dict, lineno: int, ctx: _Context, is_system: bool = False) -> None:
    """Read every file an Include pattern names; flags the parse incomplete for what it cannot follow."""
    if "\x00" in pattern or "%" in pattern or "$" in pattern:
        ctx.incomplete = True
        return
    pattern = os.path.expanduser(pattern)
    if not os.path.isabs(pattern):
        base = ctx.system_dir if is_system else ctx.ssh_dir
        pattern = os.path.join(base, pattern)
    matches = sorted(glob.glob(pattern))
    if not is_system and ctx.managed_real and not matches and not any(ch in pattern for ch in "*?[") and os.path.realpath(pattern) == ctx.managed_real:
        _note_managed(current, lineno, ctx)
    for match in matches:
        if ctx.files >= MAX_FILES:
            ctx.incomplete = True
            ctx.error(match, "too many config files, the rest are ignored")
            return
        if not is_system and ctx.managed_real and os.path.realpath(match) == ctx.managed_real:
            _note_managed(current, lineno, ctx)
        _walk(match, depth + 1, current, ctx, is_system=is_system)


def _walk(path: str, depth: int, enclosing: dict, ctx: _Context, is_system: bool = False) -> None:
    """Read one file, resolving its Host, Match and Include lines."""
    real = os.path.realpath(path)
    if real in ctx.open_files:
        return
    text = _read_text(path, ctx)
    if text is None:
        return
    ctx.files += 1
    ctx.open_files.append(real)
    try:
        _parse_lines(path, text, depth, enclosing, ctx, is_system=is_system)
    finally:
        ctx.open_files.pop()


def _forward_line(keyword: str, args: list[str], current: dict, path: str, lineno: int, ctx: _Context) -> None:
    """Record one LocalForward, RemoteForward or DynamicForward line in the current block."""
    kind = _FORWARDS[keyword]
    if len(args) not in _FORWARD_ARGS[kind]:
        ctx.error(path, "line %d: bad forwarding specification" % lineno)
        return
    if ctx.forward_lines >= MAX_FORWARD_LINES:
        ctx.incomplete = True
        if not ctx.too_many_forwards:
            ctx.too_many_forwards = True
            ctx.error(path, "more than %d forwarding lines, the rest are ignored" % MAX_FORWARD_LINES)
        return
    ctx.forward_lines += 1
    ctx.seq += 1
    current["fwd"].append((ctx.seq, kind, tuple(args)))


def _directive(keyword: str, rest: str, path: str, lineno: int, depth: int, enclosing: dict, current: dict, ctx: _Context, is_system: bool = False) -> dict:
    """Interpret one config line and return the block that is current afterwards."""
    try:
        args = split_args(rest)
    except ValueError:
        ctx.incomplete = True
        ctx.error(path, "line %d: unterminated quote" % lineno)
        return current
    if keyword == "host":
        return _host_line(args, enclosing, path, lineno, ctx, is_system=is_system)
    if keyword == "match":
        return _new_block("match", [], [], enclosing, path, ctx)
    if keyword == "include":
        if depth >= MAX_DEPTH:
            ctx.incomplete = True
            ctx.error(path, "Include nested too deeply, skipped")
            return current
        for pattern in args:
            _include(pattern, depth, current, lineno, ctx, is_system=is_system)
    elif keyword in _FORWARDS:
        _forward_line(keyword, args, current, path, lineno, ctx)
    elif keyword == "clearallforwardings":
        if len(args) == 1 and args[0].lower() in _BOOLEANS:
            ctx.seq += 1
            current["opts"].setdefault(keyword, (ctx.seq, args[0].lower()))
        else:
            ctx.error(path, "line %d: bad ClearAllForwardings value" % lineno)
    elif keyword == "proxyjump" and (not args or args[0] == ""):
        ctx.incomplete = True
        ctx.error(path, "line %d: empty ProxyJump" % lineno)
    elif keyword in _RESOLVED and args:
        ctx.seq += 1
        current["opts"].setdefault(keyword, (ctx.seq, args[0]))
    return current


def _parse_lines(path: str, text: str, depth: int, enclosing: dict, ctx: _Context, is_system: bool = False) -> None:
    """Interpret the lines of one file inside the enclosing block."""
    current = enclosing
    for lineno, raw in enumerate(text.split("\n"), 1):
        parts = split_keyword(raw)
        if parts is None:
            continue
        current = _directive(parts[0].lower(), parts[1], path, lineno, depth, enclosing, current, ctx, is_system=is_system)
        ctx.directive_seen = True


def _block_applies(block: dict, alias: str, ctx: _Context) -> bool | None:
    """True if the block and its enclosing blocks apply to alias; None when the work budget runs out."""
    while block is not None:
        kind = block["kind"]
        if kind == "match":
            return False
        if kind == "host":
            if ctx.work > MAX_WORK:
                return None
            if any(_wild_match(p, alias, ctx) for p in block["neg"]):
                return False
            if not any(_wild_match(p, alias, ctx) for p in block["pos"]):
                return False
        block = block["parent"]
    return True


def _depends_on_match(block: dict) -> bool:
    """True when the block, or one enclosing it, is a Match block."""
    while block is not None:
        if block["kind"] == "match":
            return True
        block = block["parent"]
    return False


def _resolve(alias: str, blocks: list[dict], ctx: _Context) -> tuple[dict, list] | None:
    """For each option the earliest value of any applying block, plus every applying forward line."""
    best: dict[str, tuple[int, str]] = {}
    fwds: list[tuple[int, str, tuple[str, ...]]] = []
    for block in blocks:
        applies = _block_applies(block, alias, ctx)
        if applies is None:
            return None
        if applies:
            ctx.work += len(block["fwd"])
            fwds.extend(block["fwd"])
            for key, (seq, value) in block["opts"].items():
                if key not in best or seq < best[key][0]:
                    best[key] = (seq, value)
    return best, fwds


def _forwards(fwds: list, best: dict[str, tuple[int, str]]) -> tuple[list[dict], int]:
    """Forwards in config order without exact duplicates, capped for display; empty under ClearAllForwardings."""
    if _BOOLEANS[best.get("clearallforwardings", (0, "no"))[1]]:
        return [], 0
    seen: set[tuple] = set()
    shown: list[dict] = []
    total = 0
    for _, kind, tokens in sorted(fwds, key=lambda f: f[0]):
        key = (kind, tuple(t.replace("[", "").replace("]", "") for t in tokens))
        if key in seen:
            continue
        seen.add(key)
        total += 1
        if len(shown) < MAX_FORWARDS:
            target = clean(tokens[1], FORWARD_FIELD) if len(tokens) > 1 else ""
            shown.append({"kind": kind, "listen": clean(tokens[0], FORWARD_FIELD), "target": target})
    return shown, total - len(shown)


def _routing(best: dict[str, tuple[int, str]]) -> tuple[str, bool]:
    """Effective jump host and proxy-command flag for one host, following ssh's precedence."""
    jump = best.get("proxyjump")
    command = best.get("proxycommand")
    jump_none = jump is not None and jump[1].lower() == "none"
    command_none = command is not None and command[1].lower() == "none"
    if jump is not None and command is not None:
        if jump_none or command[0] < jump[0]:
            return "", not command_none
        return jump[1], False
    if jump is not None:
        return ("" if jump_none else jump[1]), False
    if command is not None:
        return "", not command_none
    return "", False


def _copy_target(alias: str, user: str, hostname: str) -> str:
    """``user@host`` when both parts are plain enough to paste into a shell, otherwise an empty string."""
    host = (hostname or alias).replace("%h", alias)
    if COPY_USER_RE.fullmatch(user) is None:
        return ""
    if COPY_HOST_RE.fullmatch(host) is not None:
        return "%s@%s" % (user, host)
    if COPY_LITERAL_RE.fullmatch(host) is not None and ("." in host or ":" in host):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return ""
        return "%s@%s" % (user, host)
    return ""


def _root_present(path: str, ctx: _Context) -> bool:
    """True when path should be walked; missing path is False quietly, while broken symlinks or stat errors mark incomplete."""
    try:
        os.stat(path)
        return True
    except FileNotFoundError:
        if os.path.lexists(path):
            ctx.incomplete = True
            ctx.error(path, "broken symbolic link")
        return False
    except OSError as exc:
        ctx.incomplete = True
        ctx.error(path, exc.strerror or "cannot stat")
        return False


def load(
    config_path: str | None = None,
    ssh_dir: str | None = None,
    managed_path: str | None = None,
    system_path: str | None | object = _DEFAULT,
) -> dict:
    """Parse the SSH client config and return the hosts it defines; managed_path names the plugin-owned file whose inclusion is reported."""
    ssh_dir = ssh_dir or os.path.join(os.path.expanduser("~"), ".ssh")
    path = config_path or os.path.join(ssh_dir, "config")
    sys_path = SYSTEM_CONFIG_PATH if system_path is _DEFAULT else system_path
    sys_dir = os.path.dirname(os.path.abspath(sys_path)) if isinstance(sys_path, str) and sys_path else ""
    ctx = _Context(ssh_dir, os.path.realpath(managed_path) if managed_path else "", sys_dir)
    found = _root_present(path, ctx)
    if found:
        _walk(path, 0, ctx.global_block, ctx)
    if config_path is None and isinstance(sys_path, str) and sys_path and _root_present(sys_path, ctx):
        if ctx.files >= MAX_FILES:
            ctx.incomplete = True
            ctx.error(sys_path, "too many config files, the rest are ignored")
        else:
            _walk(sys_path, 0, ctx.global_block, ctx, is_system=True)

    relevant = [b for b in ctx.blocks if b["opts"] or b["fwd"]]
    match_reroutes = any(_depends_on_match(b) and any(k in _ROUTING for k in b["opts"]) for b in relevant)
    match_forwards = any(_depends_on_match(b) and (b["fwd"] or "clearallforwardings" in b["opts"]) for b in relevant)
    match_identity = any(_depends_on_match(b) and ("hostname" in b["opts"] or "user" in b["opts"]) for b in relevant)
    unsure = ctx.incomplete

    hosts = []
    unresolved_any = False
    for alias, (source, line) in ctx.candidates.items():
        resolved = _resolve(alias, relevant, ctx)
        unresolved = resolved is None
        unresolved_any = unresolved_any or unresolved
        best, fwds = resolved or ({}, [])
        forwards, forwards_more = _forwards(fwds, best)
        opts = {key: value for key, (_, value) in best.items()}
        jump, proxy = _routing(best)
        port = _parse_port(opts["port"]) if "port" in opts else None
        bad_port = "port" in opts and port is None
        canon = opts.get("canonicalizehostname", "").lower()
        canon_on = bool(canon) and canon not in ("no", "false")
        hosts.append(
            {
                "alias": alias,
                "hostname": clean(opts.get("hostname", "")),
                "user": clean(opts.get("user", ""), 64),
                "port": port,
                "jump": clean(jump),
                "proxy": proxy,
                "noProbe": match_reroutes or unresolved or unsure or canon_on or bad_port,
                "forwards": forwards,
                "forwardsMore": forwards_more,
                "forwardsUncertain": match_forwards or unresolved or unsure or canon_on,
                "target": "" if match_identity or unsure or canon_on else _copy_target(alias, opts.get("user", ""), opts.get("hostname", "")),
                "source": source,
                "line": line,
                "origin": _ORIGINS[ctx.origins.get(alias, _ORIGIN_BITS["config"])],
            }
        )
    if unresolved_any:
        ctx.error(path, "config too complex to resolve completely; some details are missing")
    return {
        "configPath": path,
        "configFound": found,
        "hosts": hosts,
        "skipped": ctx.skipped,
        "errors": ctx.errors,
        "files": ctx.files,
        "managedInclude": ctx.managed_include,
        "managedWhere": ctx.managed_where,
        "incomplete": ctx.incomplete or unresolved_any,
    }
