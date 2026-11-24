from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import select
import argparse
from typing import NoReturn
from collections.abc import Callable

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import probe
import store
import launch
import tunnels
import commands
import hostform
import hostfile
import safefile
import sshconfig
import mainconfig

APP_ID = "omassh"
EXIT_USAGE, EXIT_UNKNOWN_HOST, EXIT_LAUNCH, EXIT_TUNNEL, EXIT_REFUSED = 2, 3, 4, 5, 6
COPY_WAIT = 2.0
REQUEST_LIMIT = 65536
REQUEST_WAIT = 5.0
MAX_MESSAGE = 200
REQUEST_KEYS = {"version", "original", "expect", "host"}
HOST_KEYS = {*hostform.FIELDS, "forwards"}
LIST_KEYS = ("configPath", "configFound", "hosts", "skipped", "errors", "files")
EXPECT_RE = re.compile(r"[0-9a-f]{16}")
REASON_EXITS = {"usage": EXIT_USAGE, "invalid": EXIT_UNKNOWN_HOST, "not-managed": EXIT_UNKNOWN_HOST, "ssh-missing": EXIT_LAUNCH}
REFUSAL_REASONS = {
    "missing": "not-included",
    "conflict": "conflict",
    "limit": "limit",
    "io": "io",
    "check-failed": "check-failed",
    "ssh-rejected": "ssh-rejected",
    "ssh-missing": "ssh-missing",
}
PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SESSION_SCRIPT = os.path.join(PLUGIN_DIR, "scripts", "session.sh")


def die(code: int, message: str) -> NoReturn:
    """Print an error and exit with code."""
    print("omassh: " + message, file=sys.stderr)
    sys.exit(code)


def resolve_config(arg: str | None) -> str | None:
    """Validate the optional ``--config`` path (from the user's settings)."""
    if not arg:
        return None
    path = os.path.expanduser(arg)
    if not sshconfig.is_safe_path(path):
        die(EXIT_USAGE, "--config must be an absolute path using only letters, digits and . _ + @ : , = / -")
    return path


def parse(config_arg: str | None) -> dict:
    """Parse the SSH config named by the optional --config argument; the host file is tracked only for the default config."""
    config = resolve_config(config_arg)
    return sshconfig.load(config_path=config, managed_path=None if config else hostfile.managed_path())


def find_host(parsed: dict, alias: str) -> dict:
    """The parsed host for ``alias``, or exit. Never trusts the raw argument."""
    if not sshconfig.is_valid_alias(alias):
        die(EXIT_UNKNOWN_HOST, "not a valid host alias: %r" % sshconfig.clean(alias, 40))
    for host in parsed["hosts"]:
        if host["alias"] == alias:
            return host
    die(EXIT_UNKNOWN_HOST, "no host %r in your SSH config" % alias)


def emit(payload: dict) -> None:
    """Print payload as one line of compact JSON."""
    json.dump(payload, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    sys.stdout.flush()


def cmd_list(args: argparse.Namespace) -> int:
    """Print hosts, tunnels, tools, saved commands and the host editor state as version 3 JSON."""
    parsed = parse(args.config)
    path = store.state_path()
    state = store.load(path)
    running = tunnels.live(state)
    pinned = set(state["pinned"])
    editor = hostfile.editor_state(parsed, None if args.config else hostfile.peek())
    active_config = resolve_config(args.config) or ""
    active_tunnels = 0
    for host in parsed["hosts"]:
        alias = host["alias"]
        host["pinned"] = alias in pinned
        host["lastUsed"] = state["recent"].get(alias, 0)
        is_active = alias in running and running[alias].get("config", "") == active_config
        if is_active:
            active_tunnels += 1
            host["tunnel"] = {"since": running[alias]["since"]}
        else:
            host["tunnel"] = None
        host["editable"] = hostfile.is_editable(host, editor)
    parsed["hosts"].sort(key=lambda h: (not h["pinned"], -h["lastUsed"], h["alias"].casefold()))
    saved = commands.commands_path()
    loaded = commands.load(saved)
    payload = {key: parsed[key] for key in LIST_KEYS}
    payload.update(
        version=3,
        editor=editor,
        sshFound=shutil.which("ssh") is not None,
        tunnels=active_tunnels,
        tools={
            "wlCopy": shutil.which("wl-copy") is not None,
            "sshCopyId": shutil.which("ssh-copy-id") is not None,
            "code": shutil.which("code") is not None,
        },
        commands=commands.summary(loaded),
        commandsPath=saved,
        commandsError=loaded["error"],
        commandsSkipped=loaded["skipped"],
    )
    emit(payload)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    """Print the TCP reachability of the hosts as JSON."""
    parsed = parse(args.config)
    hosts = parsed["hosts"]
    if args.aliases:
        wanted = set(args.aliases)
        hosts = [h for h in hosts if h["alias"] in wanted]
    emit({"version": 1, "results": probe.probe_all(hosts)})
    os._exit(0)


def terminal_argv(kind: str, alias: str, options: list[str]) -> list[str]:
    """Argument list that opens a terminal running session.sh for a kind, an alias and its option tokens."""
    session = [SESSION_SCRIPT, kind, alias, *options]
    launcher = shutil.which("omarchy-launch-tui")
    if launcher:
        return [launcher, "--app-id=" + APP_ID] + session
    exec_ = shutil.which("xdg-terminal-exec")
    if exec_:
        return [exec_, "--app-id=" + APP_ID, "-e"] + session
    raise FileNotFoundError("no terminal launcher found (omarchy-launch-tui / xdg-terminal-exec)")


def connect_kind(args: argparse.Namespace) -> str:
    """The session mode selected by the connect flags."""
    for kind, chosen in (("sftp", args.sftp), ("tmux", args.tmux), ("copy-id", args.copy_id), ("run", args.run is not None)):
        if chosen:
            return kind
    return "ssh"


def connect_options(args: argparse.Namespace, kind: str, alias: str) -> list[str]:
    """The session.sh option tokens for a connection, refusing what cannot run."""
    options = []
    config = resolve_config(args.config)
    if config:
        options += ["--config", config]
    if kind == "run":
        if commands.find(commands.load(commands.commands_path()), args.run, alias) is None:
            die(EXIT_UNKNOWN_HOST, "no saved command with that id is available for %s" % alias)
        options += ["--command", args.run]
    if kind == "copy-id" and not shutil.which("ssh-copy-id"):
        die(EXIT_LAUNCH, "ssh-copy-id was not found")
    running = tunnels.live(store.load(store.state_path()))
    active_config = config or ""
    if kind != "sftp" and alias in running and running[alias].get("config", "") == active_config:
        options.append("--no-forwards")
    return options


def cmd_connect(args: argparse.Namespace) -> int:
    """Open a terminal running a session for a host in the chosen mode."""
    host = find_host(parse(args.config), args.alias)
    kind = connect_kind(args)
    options = connect_options(args, kind, host["alias"])
    try:
        argv = terminal_argv(kind, host["alias"], options)
    except FileNotFoundError as exc:
        die(EXIT_LAUNCH, str(exc))
    if not sshconfig.is_safe_path(SESSION_SCRIPT):
        die(EXIT_LAUNCH, "the plugin folder path must use only letters, digits and . _ + @ : , = / - to be handed to a terminal")
    if not os.access(SESSION_SCRIPT, os.X_OK):
        die(EXIT_LAUNCH, "session script is missing or not executable")
    try:
        store.modify(store.state_path(), lambda s: store.record_use(s, host["alias"], int(time.time())))
    except OSError as exc:
        print("omassh: could not save recent hosts: %s" % exc, file=sys.stderr)
    try:
        launch.spawn(argv)
    except OSError as exc:
        die(EXIT_LAUNCH, "could not launch a terminal: %s" % exc)
    return 0


def cmd_copy(args: argparse.Namespace) -> int:
    """Copy the ssh command, or user@host with --target, of a host to the clipboard."""
    host = find_host(parse(args.config), args.alias)
    config = resolve_config(args.config)
    if args.target:
        text = host["target"]
        if not text:
            die(EXIT_UNKNOWN_HOST, "%s has no user@host that is safe to copy" % host["alias"])
    else:
        text = "ssh -F %s %s" % (config, host["alias"]) if config else "ssh " + host["alias"]
    if not shutil.which("wl-copy"):
        die(EXIT_LAUNCH, "wl-copy was not found")
    try:
        code = launch.wait(launch.spawn(["wl-copy", "--", text]), COPY_WAIT)
    except OSError as exc:
        die(EXIT_LAUNCH, "could not run wl-copy: %s" % exc)
    if code is None:
        die(EXIT_LAUNCH, "wl-copy did not finish within %g seconds" % COPY_WAIT)
    if code != 0:
        die(EXIT_LAUNCH, "wl-copy failed with status %d" % code)
    return 0


def cmd_code(args: argparse.Namespace) -> int:
    """Open a host in a VS Code remote window."""
    host = find_host(parse(None), args.alias)
    if not shutil.which("code"):
        die(EXIT_LAUNCH, "code was not found")
    argv = ["code", "--remote", "ssh-remote+" + host["alias"]]
    if shutil.which("uwsm-app"):
        argv = ["uwsm-app", "--", *argv]
    try:
        launch.spawn(argv)
    except OSError as exc:
        die(EXIT_LAUNCH, "could not launch code: %s" % exc)
    return 0


def cmd_command_text(args: argparse.Namespace) -> int:
    """Print the text of a saved command for the session script."""
    if args.alias is not None and not sshconfig.is_valid_alias(args.alias):
        die(EXIT_UNKNOWN_HOST, "not a valid host alias")
    loaded = commands.load(commands.commands_path())
    if loaded["error"]:
        die(EXIT_UNKNOWN_HOST, "the saved commands file cannot be used: " + loaded["error"])
    text = commands.find(loaded, args.id, args.alias)
    if text is None:
        die(EXIT_UNKNOWN_HOST, "no saved command with that id is available")
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


def cmd_commands_edit(args: argparse.Namespace) -> int:
    """Create the saved commands file when it is missing and open it in the editor."""
    path = commands.commands_path()
    if not os.path.isabs(path) or "\n" in path:
        die(EXIT_UNKNOWN_HOST, "the saved commands path is not usable")
    omarchy = shutil.which("omarchy")
    if not omarchy:
        die(EXIT_LAUNCH, "omarchy was not found")
    error = commands.ensure(path)
    if error:
        reason = "is not a regular file owned by you" if error == "not-regular" else "cannot be created"
        die(EXIT_UNKNOWN_HOST, "the saved commands file %s %s" % (sshconfig.clean(path, 200), reason))
    try:
        launch.spawn([omarchy, "launch", "editor", path])
    except OSError as exc:
        die(EXIT_LAUNCH, "could not launch the editor: %s" % exc)
    return 0


def cmd_tunnel_start(args: argparse.Namespace) -> int:
    """Start the background tunnel of a host and print the result as JSON."""
    host = find_host(parse(args.config), args.alias)
    alias = host["alias"]
    if not host["forwards"] and not host["forwardsUncertain"]:
        result = tunnels.down(alias, "no-forwards", "this host has no port forwards in your SSH config")
    else:
        path = store.state_path()
        try:
            tunnels.prune(path)
            result = tunnels.start(alias, resolve_config(args.config) or "", shutil.which("ssh"), path)
        except OSError as exc:
            result = tunnels.down(alias, "failed", "cannot use the state directory: %s" % (exc.strerror or "error"))
    emit(result)
    return EXIT_TUNNEL if result["state"] == "down" else 0


def cmd_tunnel_stop(args: argparse.Namespace) -> int:
    """Stop the tunnel of a host, or every tunnel, and print the result as JSON."""
    if args.all == (args.alias is not None):
        die(EXIT_USAGE, "give either an alias or --all")
    if args.alias is not None and not sshconfig.is_valid_alias(args.alias):
        die(EXIT_UNKNOWN_HOST, "not a valid host alias")
    path = store.state_path()
    try:
        tunnels.prune(path)
        emit(tunnels.stop_all(path) if args.all else tunnels.stop(args.alias, path))
    except OSError as exc:
        die(EXIT_TUNNEL, "cannot use the state directory: %s" % (exc.strerror or "error"))
    return 0


def cmd_tunnel_list(args: argparse.Namespace) -> int:
    """Print the running tunnels as JSON after dropping stale records."""
    path = store.state_path()
    try:
        tunnels.prune(path)
    except OSError as exc:
        print("omassh: could not clean up tunnel records: %s" % exc, file=sys.stderr)
    running = tunnels.live(store.load(path))
    if getattr(args, "config", None) is not None:
        active_config = resolve_config(args.config) or ""
        running = {a: r for a, r in running.items() if r.get("config", "") == active_config}
    emit({"version": 1, "tunnels": [{"alias": alias, "since": rec["since"]} for alias, rec in sorted(running.items())]})
    return 0


def cmd_pin(args: argparse.Namespace) -> int:
    """Pin a host to the top of the list."""
    host = find_host(parse(args.config), args.alias)
    store.modify(store.state_path(), lambda s: store.set_pinned(s, host["alias"], True))
    return 0


def cmd_unpin(args: argparse.Namespace) -> int:
    """Remove a host from the pinned list."""
    if not sshconfig.is_valid_alias(args.alias):
        die(EXIT_UNKNOWN_HOST, "not a valid host alias")
    store.modify(store.state_path(), lambda s: store.set_pinned(s, args.alias, False))
    return 0


class BadRequest(Exception):
    pass


class Fail(Exception):

    def __init__(self, reason: str, message: str = "", **extra: object) -> None:
        """Carry the reason code, a message and extra reply fields of a failed host command."""
        super().__init__(reason)
        self.reason = reason
        self.message = message
        self.extra = extra


def reply(payload: dict, code: int) -> int:
    """Print the versioned reply as one line of ASCII JSON and return code."""
    emit({"version": 1, **payload})
    return code


def failure(exc: Fail) -> int:
    """Print the failed reply of exc; its exit status follows the reason, refused by default."""
    payload = {"ok": False, "reason": exc.reason, "message": sshconfig.clean(exc.message, MAX_MESSAGE), **exc.extra}
    return reply(payload, REASON_EXITS.get(exc.reason, EXIT_REFUSED))


def refusal(exc: safefile.Refused) -> Fail:
    """The failure that reports a refusal of the safe file layer."""
    return Fail(REFUSAL_REASONS.get(exc.code, "unsafe"), exc.detail or exc.code)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    """The object made of pairs, refusing a repeated key."""
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("repeated key")
    return dict(pairs)


def _no_constant(name: str) -> NoReturn:
    """Refuse the JSON constants NaN and Infinity."""
    raise ValueError(name)


def _text(value: object) -> bool:
    """True for a string."""
    return isinstance(value, str)


def check_request(request: object) -> dict:
    """The request itself when it has exactly the expected keys and string values, otherwise BadRequest."""
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise BadRequest("the request has the wrong keys")
    host = request["host"]
    version = request["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise BadRequest("unsupported request version")
    if not isinstance(host, dict) or set(host) != HOST_KEYS:
        raise BadRequest("the host has the wrong keys")
    rows = host["forwards"]
    if not (_text(request["original"]) and _text(request["expect"]) and all(_text(host[field]) for field in hostform.FIELDS)):
        raise BadRequest("every value must be a string")
    if not isinstance(rows, list) or not all(_text(row) for row in rows):
        raise BadRequest("forwards must be a list of strings")
    if request["original"] and not sshconfig.is_valid_alias(request["original"]):
        raise BadRequest("original is not a host alias")
    if request["expect"] and not EXPECT_RE.fullmatch(request["expect"]):
        raise BadRequest("expect is not a block fingerprint")
    return request


def read_request(fd: int = 0, timeout: float = REQUEST_WAIT, limit: int = REQUEST_LIMIT) -> dict:
    """The request sent as one line of JSON on fd within timeout seconds and limit bytes; BadRequest for anything else."""
    deadline = time.monotonic() + timeout
    data = b""
    while b"\n" not in data:
        left = deadline - time.monotonic()
        if len(data) > limit:
            raise BadRequest("the request is too large")
        try:
            ready = left > 0 and select.select([fd], [], [], left)[0]
            chunk = os.read(fd, limit + 2 - len(data)) if ready else b""
        except (OSError, ValueError) as exc:
            raise BadRequest("the request cannot be read") from exc
        if not ready:
            raise BadRequest("no request arrived in time")
        if not chunk:
            raise BadRequest("the request does not end with a newline")
        data += chunk
    line, _, rest = data.partition(b"\n")
    if rest or len(line) > limit:
        raise BadRequest("the request must be one line within the size limit")
    try:
        request = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BadRequest("the request is not valid JSON") from exc
    return check_request(request)


def identity_exists(path: str) -> bool:
    """True when path, with a leading ~/ read through HOME, is a regular file or a link to one."""
    full = os.path.join(os.path.expanduser("~"), path[2:]) if path.startswith("~/") else path
    return os.path.isfile(full)


def open_ssh_dir(missing: str) -> int:
    """A descriptor for the ssh directory; Fail with the reason missing when it does not exist and unsafe when it is not private."""
    try:
        return safefile.open_dir(hostfile.ssh_dir())
    except safefile.Refused as exc:
        if exc.code == "missing":
            raise Fail(missing, "the ssh directory does not exist") from exc
        raise refusal(exc) from exc


def usable_hosts(dfd: int) -> tuple[list, bytes | None, os.stat_result | None]:
    """The hosts, bytes and status of the host file; Fail unless it is missing or canonical and safe."""
    hosts, data, info, state, reason = hostfile.load_managed(dfd)
    if state == "foreign":
        raise Fail("foreign", "omassh.config was edited by hand")
    if state == "unsafe":
        raise Fail("unsafe", "omassh.config is not safe to change (%s)" % reason)
    return hosts or [], data, info


def origins(parsed: dict) -> dict[str, str]:
    """The origin of every host of the parsed config by alias."""
    return {host["alias"]: host["origin"] for host in parsed["hosts"]}


def taken_error(alias: str, hosts: list, original: str, elsewhere: dict) -> list[dict]:
    """The error list that says alias is already defined in another file or by another managed host, or an empty list."""
    inside = alias != original and any(host["alias"] == alias for host in hosts)
    if inside or elsewhere.get(alias) in ("config", "both"):
        return [{"field": "alias", "code": "taken"}]
    return []


def normalized(request: dict, hosts: list, parsed: dict) -> tuple[dict | None, list[dict]]:
    """The canonical host of the request together with every field error, the taken alias included."""
    raw = request["host"]
    host, errors = hostform.normalize(raw, identity_exists)
    alias = host["alias"] if host else raw["alias"].strip(" \t")
    if not any(error["field"] == "alias" for error in errors):
        errors = errors + taken_error(alias, hosts, request["original"], origins(parsed))
    if host and hostfile.has_cycle(host["alias"], request["original"], host, parsed["hosts"]):
        errors = errors + [{"field": "proxyJump", "code": "cycle"}]
    return (None if errors else host), errors


def invalid(errors: list[dict]) -> int:
    """Print the field errors reply."""
    return reply({"ok": False, "reason": "invalid", "errors": errors}, EXIT_UNKNOWN_HOST)


def tunnels_running(path: str) -> dict:
    """The verified tunnel records by alias."""
    return tunnels.live(store.load(path))


def current_block(request: dict, hosts: list, parsed: dict) -> dict | None:
    """The managed host being edited, checked against the owner and the fingerprint the panel saw; None for a new host."""
    original = request["original"]
    if not original:
        if request["expect"]:
            raise Fail("usage", "a new host has no fingerprint")
        return None
    current = next((host for host in hosts if host["alias"] == original), None)
    if current is None or origins(parsed).get(original) != "managed":
        raise Fail("not-managed", "%s is not a host of the plugin file" % original)
    if not request["expect"]:
        raise Fail("usage", "an edit needs the fingerprint")
    if request["expect"] != hostform.block_hash(current):
        raise Fail("conflict", "the host changed since it was loaded")
    return current


def write_or_fail(dfd: int, hosts: list, data: bytes | None, info: os.stat_result | None, check: Callable[[str], None] | None = None) -> None:
    """hostfile.write_hosts with every refusal turned into a Fail."""
    try:
        hostfile.write_hosts(dfd, hosts, data, info, check)
    except safefile.Refused as exc:
        raise refusal(exc) from exc
    except OSError as exc:
        raise Fail("io", exc.strerror or "cannot write") from exc


def remember(path: str, change: Callable[[dict], None]) -> None:
    """Apply change to the pins and recents; a state file that cannot be written does not undo the saved host."""
    try:
        store.modify(path, change)
    except OSError as exc:
        print("omassh: could not update pins and recent hosts: %s" % exc, file=sys.stderr)


def save_locked(request: dict, dfd: int, path: str) -> int:
    """Add, edit or rename one host under the hosts lock and print the reply."""
    hosts, data, info = usable_hosts(dfd)
    parsed = sshconfig.load(managed_path=hostfile.managed_path())
    if parsed["managedInclude"] != "active":
        raise Fail("not-included", "ssh does not read omassh.config first", include=parsed["managedInclude"], where=parsed["managedWhere"])
    if parsed["incomplete"]:
        raise Fail("incomplete", "part of your SSH config could not be read (a skipped Include or a size limit), so a name clash cannot be ruled out")
    original = request["original"]
    current = current_block(request, hosts, parsed)
    host, errors = normalized(request, hosts, parsed)
    if host is None:
        return invalid(errors)
    alias = host["alias"]
    running = tunnels_running(path)
    renamed = bool(original) and original != alias
    if renamed and original in running:
        raise Fail("tunnel-up", "stop the tunnel of %s before renaming it" % original)
    ssh = shutil.which("ssh")
    if not ssh:
        raise Fail("ssh-missing", "ssh was not found")
    updated = [host if entry is current else entry for entry in hosts] if current else [*hosts, host]
    check = hostfile.checker(ssh, os.path.realpath(hostfile.ssh_dir()), alias, host)
    write_or_fail(dfd, updated, data, info, check)
    if renamed:
        after = origins(sshconfig.load(managed_path=hostfile.managed_path()))
        if original not in after and alias in after:
            remember(path, lambda state: store.rename(state, original, alias))
    return reply({"ok": True, "alias": alias, "created": not original, "renamed": renamed, "tunnelUp": bool(original) and not renamed and alias in running}, 0)


def delete_locked(alias: str, expect: str, dfd: int, path: str) -> int:
    """Remove one managed host under the hosts lock, stopping its tunnel only when the plugin file alone defines the name and forgetting its pin once nothing defines it, and print the reply."""
    hosts, data, info = usable_hosts(dfd)
    current = next((host for host in hosts if host["alias"] == alias), None)
    if current is None:
        raise Fail("not-managed", "%s is not a host of the plugin file" % alias)
    if expect != hostform.block_hash(current):
        raise Fail("conflict", "the host changed since it was loaded")
    before = sshconfig.load(managed_path=hostfile.managed_path())
    own = origins(before).get(alias) == "managed" and not before["incomplete"]
    stopped = False
    if alias in tunnels_running(path) and own:
        try:
            outcome = tunnels.stop(alias, path)
        except OSError as exc:
            raise Fail("io", exc.strerror or "cannot stop the tunnel") from exc
        if outcome["state"] == "up":
            raise Fail("tunnel-running", "the tunnel of %s did not stop" % alias)
        stopped = outcome["stopped"]
    write_or_fail(dfd, [host for host in hosts if host is not current], data, info)
    after = sshconfig.load(managed_path=hostfile.managed_path())
    gone = alias not in origins(after) and not before["incomplete"] and not after["incomplete"]
    if gone:
        remember(path, lambda state: store.forget(state, alias))
    return reply({"ok": True, "alias": alias, "tunnelStopped": stopped, "forgotten": gone}, 0)


def locked(missing: str, action: Callable[[int, str], int]) -> int:
    """Run action(dfd, state path) with the hosts lock and the ssh directory held and print any Fail as its reply."""
    path = store.state_path()
    try:
        with store.hosts_lock(path):
            dfd = open_ssh_dir(missing)
            try:
                return action(dfd, path)
            finally:
                os.close(dfd)
    except Fail as exc:
        return failure(exc)
    except OSError as exc:
        return failure(Fail("io", exc.strerror or "cannot use the state directory"))


def request_or_fail() -> dict | int:
    """The request on stdin, or the printed usage reply as an exit status."""
    try:
        return read_request()
    except BadRequest as exc:
        return failure(Fail("usage", str(exc)))


def cmd_host_validate(args: argparse.Namespace) -> int:
    """Check the fields of a host request and print the field errors; nothing is written."""
    request = request_or_fail()
    if isinstance(request, int):
        return request
    hosts, _, _, state, _ = hostfile.peek()
    host, errors = normalized(request, hosts if state == "ok" else [], sshconfig.load(managed_path=hostfile.managed_path()))
    return reply({"ok": True, "alias": host["alias"]}, 0) if host else invalid(errors)


def cmd_host_save(args: argparse.Namespace) -> int:
    """Add, edit or rename a host of the plugin file from the request on stdin."""
    request = request_or_fail()
    if isinstance(request, int):
        return request
    return locked("not-included", lambda dfd, path: save_locked(request, dfd, path))


def cmd_host_delete(args: argparse.Namespace) -> int:
    """Remove a host from the plugin file."""
    if not sshconfig.is_valid_alias(args.alias):
        return failure(Fail("not-managed", "not a valid host alias"))
    return locked("not-managed", lambda dfd, path: delete_locked(args.alias, args.expect, dfd, path))


def cmd_include_status(args: argparse.Namespace) -> int:
    """Print how ssh reads the plugin file and the insertion that would fix it."""
    return reply(mainconfig.preview(), 0)


def cmd_include_apply(args: argparse.Namespace) -> int:
    """Insert the Include line into ~/.ssh/config when the preview the caller saw is still accurate."""
    try:
        with store.hosts_lock(store.state_path()):
            result = mainconfig.apply(args.expect)
    except OSError as exc:
        return failure(Fail("io", exc.strerror or "cannot use the state directory"))
    return reply(result, 0 if result["ok"] else EXIT_REFUSED)


def fingerprint(value: str) -> str:
    """The value when it is a 16 hex digit fingerprint, otherwise an argparse error."""
    if not EXPECT_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("expected 16 lowercase hex digits")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser of every subcommand."""
    parser = argparse.ArgumentParser(prog="omassh", description="Pick an SSH host from your ssh config.")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_config(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        """Add the --config option to a subparser."""
        p.add_argument("--config", help="absolute path of the SSH config (default: ~/.ssh/config)")
        return p

    with_config(sub.add_parser("list", help="print your hosts as JSON")).set_defaults(handler=cmd_list)

    p = with_config(sub.add_parser("probe", help="check which hosts accept a TCP connection"))
    p.add_argument("aliases", nargs="*", metavar="ALIAS")
    p.set_defaults(handler=cmd_probe)

    p = with_config(sub.add_parser("connect", help="open a terminal running ssh"))
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--sftp", action="store_true", help="run sftp instead of ssh")
    mode.add_argument("--tmux", action="store_true", help="attach to the remote tmux session omassh")
    mode.add_argument("--copy-id", action="store_true", help="run ssh-copy-id")
    mode.add_argument("--run", metavar="ID", help="run the saved command with this id")
    p.add_argument("alias", metavar="ALIAS")
    p.set_defaults(handler=cmd_connect)

    p = with_config(sub.add_parser("copy", help="copy the ssh command of a host to the clipboard"))
    p.add_argument("--target", action="store_true", help="copy user@host instead")
    p.add_argument("alias", metavar="ALIAS")
    p.set_defaults(handler=cmd_copy)

    p = sub.add_parser("code", help="open a host in VS Code")
    p.add_argument("alias", metavar="ALIAS")
    p.set_defaults(handler=cmd_code)

    p = sub.add_parser("command-text", help="print a saved command (used by the session script)")
    p.add_argument("--alias", help="the host the command will run on")
    p.add_argument("id", metavar="ID")
    p.set_defaults(handler=cmd_command_text)

    p = sub.add_parser("commands", help="manage the saved commands file")
    actions = p.add_subparsers(dest="action", required=True)
    actions.add_parser("edit", help="create the saved commands file if needed and open it in the editor").set_defaults(handler=cmd_commands_edit)

    p = sub.add_parser("tunnel", help="manage background tunnels")
    actions = p.add_subparsers(dest="action", required=True)
    q = with_config(actions.add_parser("start", help="start the tunnel of a host"))
    q.add_argument("alias", metavar="ALIAS")
    q.set_defaults(handler=cmd_tunnel_start)
    q = actions.add_parser("stop", help="stop the tunnel of a host, or all of them")
    q.add_argument("--all", action="store_true", help="stop every tunnel")
    q.add_argument("alias", metavar="ALIAS", nargs="?")
    q.set_defaults(handler=cmd_tunnel_stop)
    with_config(actions.add_parser("list", help="print the running tunnels as JSON")).set_defaults(handler=cmd_tunnel_list)

    p = with_config(sub.add_parser("pin", help="pin a host to the top"))
    p.add_argument("alias", metavar="ALIAS")
    p.set_defaults(handler=cmd_pin)

    p = sub.add_parser("unpin", help="unpin a host")
    p.add_argument("alias", metavar="ALIAS")
    p.set_defaults(handler=cmd_unpin)

    p = sub.add_parser("host", help="add, edit and remove hosts of the plugin file")
    actions = p.add_subparsers(dest="action", required=True)
    actions.add_parser("validate", help="check a host request read from stdin").set_defaults(handler=cmd_host_validate)
    actions.add_parser("save", help="add, edit or rename a host from a request read from stdin").set_defaults(handler=cmd_host_save)
    q = actions.add_parser("delete", help="remove a host of the plugin file")
    q.add_argument("--expect", required=True, type=fingerprint, metavar="HEX", help="fingerprint of the host block")
    q.add_argument("alias", metavar="ALIAS")
    q.set_defaults(handler=cmd_host_delete)

    p = sub.add_parser("include", help="make ssh read the plugin file")
    actions = p.add_subparsers(dest="action", required=True)
    actions.add_parser("status", help="print how ssh reads the plugin file and the line that would be inserted").set_defaults(handler=cmd_include_status)
    q = actions.add_parser("apply", help="insert the Include line into ~/.ssh/config")
    q.add_argument("--confirm", action="store_true", required=True, help="confirm the insertion")
    q.add_argument("--expect", required=True, type=fingerprint, metavar="HEX", help="token from include status")
    q.set_defaults(handler=cmd_include_apply)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return its exit status."""
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
