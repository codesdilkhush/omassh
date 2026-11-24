import io
import os
import re
import sys
import json
import time
import stat
import shutil
import signal
import socket
import hashlib
import tempfile
import unittest
import subprocess
import contextlib
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import cli
import support
import tunnels
import commands
import hostform

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OMASSH = os.path.join(ROOT, "omassh")
SESSION = os.path.realpath(os.path.join(ROOT, "scripts", "session.sh"))

CONFIG = """\
Host server
  HostName 192.0.2.10
  User admin
Host web
  HostName web.example.invalid
  Port 2222
Host viajump
  HostName 198.51.100.9
  ProxyJump server
Host -oProxyCommand=touch
Host a@b
"""


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.tmp.name, "home")
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(os.path.join(self.home, ".ssh"))
        os.makedirs(self.bin)
        for tool in ("bash", "python3", "dirname", "readlink"):
            os.symlink(shutil.which(tool), os.path.join(self.bin, tool))
        self.stub_ssh()
        self.config = os.path.join(self.home, ".ssh", "config")
        with open(self.config, "w") as fh:
            fh.write(CONFIG)
        self.record = os.path.join(self.tmp.name, "launch.argv")
        self.fakes = []
        self.fake("omarchy-launch-tui")

    def stub_ssh(self):
        path = os.path.join(self.bin, "ssh")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)

    def fake(self, name, record=None):
        """A launcher that records its argv, NUL-separated, and does nothing."""
        path = os.path.join(self.bin, name)
        with open(path, "w") as fh:
            fh.write('#!/bin/sh\nprintf "%%s\\0" "$@" > "%s"\n' % (record or self.record))
        os.chmod(path, 0o755)
        self.fakes.append(path.encode())

    def env(self, **extra):
        env = {
            "HOME": self.home,
            "XDG_STATE_HOME": os.path.join(self.tmp.name, "state"),
            "XDG_CONFIG_HOME": os.path.join(self.tmp.name, "xdg"),
            "PATH": self.bin,
            "LANG": "C.UTF-8",
        }
        env.update(extra)
        return env

    def run_cli(self, *args, **extra):
        return subprocess.run([OMASSH, *args], capture_output=True, text=True, env=self.env(**extra), timeout=30)

    def run_raw(self, *args, **extra):
        """Run the CLI and return the completed process with undecoded output."""
        return subprocess.run([OMASSH, *args], capture_output=True, env=self.env(**extra), timeout=30)

    def save_commands(self, entries, mode=0o600):
        """Write the saved commands file into the sandboxed config home."""
        directory = os.path.join(self.tmp.name, "xdg", "omassh")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "commands.json")
        with open(path, "w") as fh:
            json.dump({"commands": entries}, fh)
        os.chmod(path, mode)
        return path

    def command_id(self, name, command):
        """The id the CLI gives a saved command."""
        return hashlib.sha256((name + "\0" + command).encode()).hexdigest()[:16]

    def fakes_running(self):
        """True while any fake launcher this test installed is still executing."""
        for name in os.listdir("/proc"):
            if not name.isdecimal():
                continue
            try:
                with open("/proc/%s/cmdline" % name, "rb") as fh:
                    parts = fh.read().split(b"\0")
            except OSError:
                continue
            if any(part in self.fakes for part in parts):
                return True
        return False

    def launched(self, record=None):
        """The NUL-separated arguments a fake tool recorded, or None when it never ran; call it after the CLI has exited."""
        deadline = time.monotonic() + 10
        while self.fakes_running() and time.monotonic() < deadline:
            time.sleep(0.005)
        record = record or self.record
        if not os.path.exists(record):
            return None
        with open(record, "rb") as fh:
            return [a.decode() for a in fh.read().split(b"\0")[:-1]]

    def state(self):
        path = os.path.join(self.tmp.name, "state", "omassh", "state.json")
        if not os.path.exists(path):
            return None
        with open(path) as fh:
            return json.load(fh)


class ListTests(CliCase):
    def test_lists_only_valid_hosts(self):
        r = self.run_cli("list")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual([h["alias"] for h in data["hosts"]], ["server", "viajump", "web"])
        self.assertEqual(data["skipped"], 2)
        self.assertTrue(data["configFound"])
        self.assertTrue(data["sshFound"])

    def test_pinned_then_recent_then_alphabetical(self):
        self.run_cli("pin", "web")
        self.run_cli("connect", "viajump")
        data = json.loads(self.run_cli("list").stdout)
        self.assertEqual([h["alias"] for h in data["hosts"]], ["web", "viajump", "server"])
        self.assertTrue(data["hosts"][0]["pinned"])
        self.assertGreater(data["hosts"][1]["lastUsed"], 0)

    def test_missing_config(self):
        os.unlink(self.config)
        data = json.loads(self.run_cli("list").stdout)
        self.assertFalse(data["configFound"])
        self.assertEqual(data["hosts"], [])

    def test_config_flag(self):
        other = os.path.join(self.tmp.name, "other")
        with open(other, "w") as fh:
            fh.write("Host elsewhere\n")
        data = json.loads(self.run_cli("list", "--config", other).stdout)
        self.assertEqual([h["alias"] for h in data["hosts"]], ["elsewhere"])

    def test_relative_config_flag_is_refused(self):
        r = self.run_cli("list", "--config", "relative/path")
        self.assertEqual(r.returncode, 2)

    def test_config_flag_allows_only_shell_neutral_characters(self):
        base = os.path.join(self.tmp.name, "cfg")
        for suffix in (" x", ";id", "$(id)", "`id`", "'x", '"x', "|x", "&x", "*", "?", "~", "\\x", "\nx", "\x00x", "\u00e9"):
            for command in (["list"], ["probe"], ["connect", "server"]):
                try:
                    r = self.run_cli(command[0], "--config", base + suffix, *command[1:])
                except ValueError:
                    continue
                self.assertEqual(r.returncode, 2, (command, suffix))
                self.assertIn("--config must be", r.stderr)
        self.assertIsNone(self.launched())

    def test_config_flag_accepts_ordinary_paths(self):
        for name in ("config", "work.conf", "my-config_2", "a+b@c:d,e=f"):
            path = os.path.join(self.tmp.name, name)
            with open(path, "w") as fh:
                fh.write("Host ok\n")
            r = self.run_cli("list", "--config", path)
            self.assertEqual(r.returncode, 0, (name, r.stderr))


class ConnectTests(CliCase):
    def test_launches_terminal_with_exact_argv(self):
        r = self.run_cli("connect", "server")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            self.launched(),
            ["--app-id=omassh", SESSION, "ssh", "server"],
        )

    def test_custom_config_is_forwarded_to_the_session(self):
        other = os.path.join(self.tmp.name, "other_config")
        with open(other, "w") as fh:
            fh.write("Host elsewhere\n")
        self.assertEqual(self.run_cli("connect", "--config", other, "elsewhere").returncode, 0)
        self.assertEqual(self.launched(), ["--app-id=omassh", SESSION, "ssh", "elsewhere", "--config", other])

    def test_a_plugin_folder_that_is_not_shell_neutral_is_refused_and_nothing_launches(self):
        plugin = os.path.join(self.tmp.name, "my plugin")
        os.makedirs(plugin)
        for name in ("omassh", "backend", "scripts"):
            source = os.path.join(ROOT, name)
            target = os.path.join(plugin, name)
            if os.path.isdir(source):
                shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy(source, target)
        r = subprocess.run([os.path.join(plugin, "omassh"), "connect", "server"], capture_output=True, text=True, env=self.env(), timeout=30)
        self.assertEqual(r.returncode, 4)
        self.assertIn("plugin folder", r.stderr)
        self.assertIsNone(self.launched())
        self.assertIsNone(self.state())

    def test_default_config_is_not_forwarded(self):
        self.run_cli("connect", "server")
        self.assertEqual(len(self.launched()), 4)

    def test_sftp_mode(self):
        self.run_cli("connect", "--sftp", "web")
        self.assertEqual(self.launched()[-2:], ["sftp", "web"])

    def test_falls_back_to_xdg_terminal_exec(self):
        os.unlink(os.path.join(self.bin, "omarchy-launch-tui"))
        self.fake("xdg-terminal-exec")
        self.run_cli("connect", "server")
        self.assertEqual(self.launched(), ["--app-id=omassh", "-e", SESSION, "ssh", "server"])

    def test_no_terminal_launcher_fails_cleanly(self):
        os.unlink(os.path.join(self.bin, "omarchy-launch-tui"))
        r = self.run_cli("connect", "server")
        self.assertEqual(r.returncode, 4)

    def test_records_recent_use(self):
        self.run_cli("connect", "server")
        self.assertIn("server", self.state()["recent"])

    def test_unknown_host_is_refused_and_nothing_launches(self):
        r = self.run_cli("connect", "nothere")
        self.assertEqual(r.returncode, 3)
        self.assertIsNone(self.launched())

    def test_option_injection_is_refused(self):
        marker = os.path.join(self.tmp.name, "pwned")
        for hostile in ("-oProxyCommand=touch " + marker, "-J", "--help", "server -oX=y", "server;id", "a@b", "$(id)", "`id`", "server\nweb"):
            self.setUp()
            r = self.run_cli("connect", "--", hostile)
            self.assertIn(r.returncode, (2, 3), hostile)
            self.assertIsNone(self.launched(), hostile)
            self.assertFalse(os.path.exists(marker))

    def test_hostile_alias_is_rejected_by_the_whitelist_first(self):
        r = self.run_cli("connect", "--", "-oProxyCommand=touch /nonexistent/pwned")
        self.assertEqual(r.returncode, 3)
        self.assertIn("not a valid host alias", r.stderr)
        self.assertNotIn("no host", r.stderr)

    def test_pythonpath_cannot_hijack_the_interpreter(self):
        evil = os.path.join(self.tmp.name, "evil")
        os.makedirs(evil)
        marker = os.path.join(self.tmp.name, "hijacked")
        with open(os.path.join(evil, "json.py"), "w") as fh:
            fh.write("open(%r, 'w').close()\nraise SystemExit(99)\n" % marker)
        r = self.run_cli("list", PYTHONPATH=evil)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_alias_in_config_but_invalid_is_refused(self):
        for alias in ("-oProxyCommand=touch", "a@b"):
            r = self.run_cli("connect", "--", alias)
            self.assertEqual(r.returncode, 3, alias)
            self.assertIsNone(self.launched())

    def test_connect_works_even_if_state_dir_is_unwritable(self):
        state = os.path.join(self.tmp.name, "state")
        os.makedirs(state)
        os.chmod(state, 0o500)
        self.addCleanup(os.chmod, state, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory modes")
        r = self.run_cli("connect", "server")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNotNone(self.launched())

    def test_shell_metacharacters_in_home_path_do_not_matter(self):
        r = self.run_cli("connect", "server")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.launched()[-1], "server")


class OutputTests(CliCase):
    def test_non_ascii_hostnames_survive_any_locale(self):
        with open(self.config, "w", encoding="utf-8") as fh:
            fh.write("Host idn\n  HostName m\u00fcnchen.example\n  User j\u00f6rg\n")
        for lang in ("C", "POSIX", "C.UTF-8"):
            r = self.run_cli("list", LANG=lang, LC_ALL=lang)
            self.assertEqual(r.returncode, 0, "%s: %s" % (lang, r.stderr))
            host = json.loads(r.stdout)["hosts"][0]
            self.assertEqual((host["hostname"], host["user"]), ("m\u00fcnchen.example", "j\u00f6rg"))
            r.stdout.encode("ascii")


class PinTests(CliCase):
    def test_pin_and_unpin_accept_double_dash(self):
        self.assertEqual(self.run_cli("pin", "--", "server").returncode, 0)
        self.assertEqual(self.state()["pinned"], ["server"])
        self.assertEqual(self.run_cli("unpin", "--", "server").returncode, 0)
        self.assertEqual(self.state()["pinned"], [])

    def test_pin_with_config_and_double_dash(self):
        other = os.path.join(self.tmp.name, "other_config")
        with open(other, "w") as fh:
            fh.write("Host elsewhere\n")
        self.assertEqual(self.run_cli("pin", "--config", other, "--", "elsewhere").returncode, 0)
        self.assertEqual(self.state()["pinned"], ["elsewhere"])

    def test_pin_unpin(self):
        self.assertEqual(self.run_cli("pin", "server").returncode, 0)
        self.assertEqual(self.state()["pinned"], ["server"])
        self.assertEqual(self.run_cli("unpin", "server").returncode, 0)
        self.assertEqual(self.state()["pinned"], [])

    def test_pin_unknown_or_hostile(self):
        self.assertEqual(self.run_cli("pin", "ghost").returncode, 3)
        self.assertEqual(self.run_cli("pin", "--", "-oX=y").returncode, 3)
        self.assertIsNone(self.state())

    def test_unpin_works_for_host_removed_from_config(self):
        self.run_cli("pin", "server")
        with open(self.config, "w") as fh:
            fh.write("")
        self.assertEqual(self.run_cli("unpin", "server").returncode, 0)
        self.assertEqual(self.state()["pinned"], [])


class ProbeTests(CliCase):
    def probe(self, *aliases):
        r = self.run_cli("probe", *aliases)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)["results"]

    def test_up_down_and_unknown(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        up_port = listener.getsockname()[1]
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        down_port = closed.getsockname()[1]
        closed.close()
        with open(self.config, "w") as fh:
            fh.write(
                "Host up\n  HostName 127.0.0.1\n  Port %d\n"
                "Host down\n  HostName 127.0.0.1\n  Port %d\n"
                "Host jumped\n  HostName 127.0.0.1\n  Port %d\n  ProxyJump up\n"
                "Host tok\n  HostName %%unknown\n" % (up_port, down_port, up_port)
            )
        results = self.probe()
        self.assertEqual(results["up"]["state"], "up")
        self.assertEqual(results["down"]["state"], "down")
        self.assertEqual(results["jumped"]["state"], "unknown")
        self.assertEqual(results["tok"]["state"], "unknown")

    def test_jump_inherited_from_a_later_wildcard_block_is_never_probed_directly(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        cases = {
            "wildcard jump": "Host up\n  HostName 127.0.0.1\n  Port %d\nHost *\n  ProxyJump bastion\n",
            "pattern jump": "Host up\n  HostName 127.0.0.1\n  Port %d\nHost *.internal up\n  ProxyJump bastion\n",
            "wildcard proxycommand": "Host up\n  HostName 127.0.0.1\n  Port %d\nHost *\n  ProxyCommand nc %%h %%p\n",
            "global jump": "ProxyJump bastion\nHost up\n  HostName 127.0.0.1\n  Port %d\n",
            "jump via include": "Host up\n  HostName 127.0.0.1\n  Port %d\nInclude extra\n",
            "match may reroute": "Host up\n  HostName 127.0.0.1\n  Port %d\nMatch host up\n  ProxyJump bastion\n",
        }
        with open(os.path.join(self.home, ".ssh", "extra"), "w") as fh:
            fh.write("Host *\n  ProxyJump bastion\n")
        for name, text in cases.items():
            with open(self.config, "w") as fh:
                fh.write(text % port if "%d" in text else text)
            self.assertEqual(self.probe()["up"]["state"], "unknown", name)
        with open(self.config, "w") as fh:
            fh.write("Host up\n  HostName 127.0.0.1\n  Port %d\n" % port)
        self.assertEqual(self.probe()["up"]["state"], "up")

    def test_port_set_in_a_wildcard_block_is_used_for_probing(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        with open(self.config, "w") as fh:
            fh.write("Host up\n  HostName 127.0.0.1\nHost *\n  Port %d\n" % listener.getsockname()[1])
        self.assertEqual(self.probe()["up"]["state"], "up")

    def test_only_requested_aliases_are_probed(self):
        with open(self.config, "w") as fh:
            fh.write("Host a\n  HostName 127.0.0.1\n  Port 1\nHost b\n  HostName 127.0.0.1\n  Port 1\n")
        self.assertEqual(sorted(self.probe("a")), ["a"])

    def test_does_not_hang_forever_on_unroutable_host(self):
        with open(self.config, "w") as fh:
            fh.write("Host t\n  HostName 192.0.2.1\n")
        start = time.monotonic()
        results = self.probe()
        self.assertLess(time.monotonic() - start, 12)
        self.assertIn(results["t"]["state"], ("down", "up"))


class ListV2Tests(CliCase):
    def test_version_two_adds_tunnels_tools_and_commands(self):
        data = json.loads(self.run_cli("list").stdout)
        self.assertEqual(data["version"], 3)
        self.assertEqual(data["tunnels"], 0)
        self.assertEqual(data["tools"], {"wlCopy": False, "sshCopyId": False, "code": False})
        self.assertEqual((data["commands"], data["commandsError"], data["commandsSkipped"]), ([], "", 0))
        self.assertEqual(data["commandsPath"], os.path.join(self.tmp.name, "xdg", "omassh", "commands.json"))
        for host in data["hosts"]:
            self.assertIsNone(host["tunnel"])
            for key in ("forwards", "forwardsMore", "forwardsUncertain", "target"):
                self.assertIn(key, host)

    def test_tools_follow_the_path(self):
        for tool in ("wl-copy", "ssh-copy-id", "code"):
            self.fake(tool, os.path.join(self.tmp.name, "unused"))
        self.assertEqual(json.loads(self.run_cli("list").stdout)["tools"], {"wlCopy": True, "sshCopyId": True, "code": True})

    def test_the_copy_target_is_listed(self):
        hosts = {h["alias"]: h for h in json.loads(self.run_cli("list").stdout)["hosts"]}
        self.assertEqual(hosts["server"]["target"], "admin@192.0.2.10")
        self.assertEqual(hosts["web"]["target"], "")

    def test_commands_are_listed_without_their_text(self):
        self.save_commands([{"name": "Disk usage", "command": "df -h"}, {"name": "Journal", "command": "x" * 400, "hosts": ["server"]}])
        r = self.run_cli("list")
        data = json.loads(r.stdout)
        self.assertEqual(data["commands"][0], {"id": self.command_id("Disk usage", "df -h"), "name": "Disk usage", "preview": "df -h", "hosts": None})
        self.assertEqual(data["commands"][1]["hosts"], ["server"])
        self.assertEqual(len(data["commands"][1]["preview"]), 80)
        self.assertNotIn("x" * 81, r.stdout)
        self.assertNotIn('"command"', r.stdout)

    def test_a_remote_command_in_the_ssh_config_is_never_a_saved_command(self):
        with open(self.config, "a") as fh:
            fh.write("Host rc\n  RemoteCommand touch pwned\n")
        data = json.loads(self.run_cli("list").stdout)
        self.assertEqual((data["commands"], data["commandsError"]), ([], ""))

    def test_a_bad_commands_file_is_reported_not_fatal(self):
        self.save_commands([{"name": "n", "command": "ls"}], mode=0o666)
        data = json.loads(self.run_cli("list").stdout)
        self.assertEqual((data["commands"], data["commandsError"]), ([], "insecure"))
        self.save_commands([{"name": "n", "command": "ls"}, {"name": "bad", "command": "a\nb"}])
        data = json.loads(self.run_cli("list").stdout)
        self.assertEqual((len(data["commands"]), data["commandsError"], data["commandsSkipped"]), (1, "", 1))

    def test_an_unwritable_state_directory_does_not_break_list(self):
        state = os.path.join(self.tmp.name, "state")
        os.makedirs(state)
        os.chmod(state, 0o500)
        self.addCleanup(os.chmod, state, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory modes")
        self.assertEqual(self.run_cli("list").returncode, 0)

    def test_list_never_writes_the_state_file(self):
        self.run_cli("list")
        self.assertIsNone(self.state())

    def test_commands_path_follows_an_absolute_xdg_config_home_only(self):
        data = json.loads(self.run_cli("list", XDG_CONFIG_HOME="relative").stdout)
        self.assertEqual(data["commandsPath"], os.path.join(self.home, ".config", "omassh", "commands.json"))


class CommandTextTests(CliCase):
    def setUp(self):
        super().setUp()
        self.save_commands(
            [
                {"name": "Free", "command": "df -h  $(x) 'q' café "},
                {"name": "Only", "command": "uptime", "hosts": ["web"]},
            ]
        )
        self.free = self.command_id("Free", "df -h  $(x) 'q' café ")
        self.only = self.command_id("Only", "uptime")

    def test_prints_the_raw_text_without_a_newline_in_any_locale(self):
        for lang in ("C", "C.UTF-8"):
            r = self.run_raw("command-text", "--alias", "server", "--", self.free, LANG=lang, LC_ALL=lang)
            self.assertEqual((r.returncode, r.stdout), (0, "df -h  $(x) 'q' café ".encode()), lang)

    def test_the_alias_is_optional_for_unrestricted_commands_only(self):
        self.assertEqual(self.run_cli("command-text", "--", self.free).returncode, 0)
        r = self.run_cli("command-text", "--", self.only)
        self.assertEqual((r.returncode, r.stdout), (3, ""))

    def test_a_host_restriction_is_enforced(self):
        self.assertEqual(self.run_cli("command-text", "--alias", "web", "--", self.only).stdout, "uptime")
        for alias in ("server", "web2", "Web"):
            r = self.run_cli("command-text", "--alias", alias, "--", self.only)
            self.assertEqual((r.returncode, r.stdout), (3, ""), alias)

    def test_unknown_malformed_and_hostile_ids_print_nothing(self):
        for cid in ("0" * 16, "", self.free.upper(), self.free[:15], "$(id)", "../x", "-oX=y"):
            r = self.run_cli("command-text", "--alias", "web", "--", cid)
            self.assertNotEqual(r.returncode, 0, cid)
            self.assertEqual(r.stdout, "", cid)

    def test_a_hostile_alias_is_refused(self):
        for alias in ("-oX=y", "a b", "web;id", "a@b"):
            r = self.run_cli("command-text", "--alias=" + alias, "--", self.free)
            self.assertEqual((r.returncode, r.stdout), (3, ""), alias)

    def test_an_insecure_file_prints_nothing(self):
        self.save_commands([{"name": "Free", "command": "df -h  $(x) 'q' café "}], mode=0o662)
        r = self.run_cli("command-text", "--alias", "web", "--", self.free)
        self.assertEqual((r.returncode, r.stdout), (3, ""))
        self.assertIn("insecure", r.stderr)

    def test_an_edited_file_refuses_the_old_id(self):
        self.save_commands([{"name": "Free", "command": "rm -rf ~"}])
        r = self.run_cli("command-text", "--alias", "web", "--", self.free)
        self.assertEqual((r.returncode, r.stdout), (3, ""))

    def test_no_commands_file_prints_nothing(self):
        os.unlink(os.path.join(self.tmp.name, "xdg", "omassh", "commands.json"))
        self.assertEqual(self.run_cli("command-text", "--", self.free).returncode, 3)


class ConnectModeTests(CliCase):
    def setUp(self):
        super().setUp()
        self.save_commands([{"name": "Free", "command": "df -h"}, {"name": "Only", "command": "uptime", "hosts": ["web"]}])
        self.free = self.command_id("Free", "df -h")
        self.only = self.command_id("Only", "uptime")

    def test_tmux_mode(self):
        self.assertEqual(self.run_cli("connect", "--tmux", "server").returncode, 0)
        self.assertEqual(self.launched(), ["--app-id=omassh", SESSION, "tmux", "server"])

    def test_copy_id_mode_needs_ssh_copy_id(self):
        r = self.run_cli("connect", "--copy-id", "server")
        self.assertEqual(r.returncode, 4)
        self.assertIn("ssh-copy-id", r.stderr)
        self.assertIsNone(self.launched())
        self.fake("ssh-copy-id", os.path.join(self.tmp.name, "unused"))
        self.assertEqual(self.run_cli("connect", "--copy-id", "server").returncode, 0)
        self.assertEqual(self.launched(), ["--app-id=omassh", SESSION, "copy-id", "server"])

    def test_run_mode_passes_only_the_id(self):
        self.assertEqual(self.run_cli("connect", "--run", self.free, "server").returncode, 0)
        self.assertEqual(self.launched(), ["--app-id=omassh", SESSION, "run", "server", "--command", self.free])

    def test_options_come_in_a_fixed_order(self):
        other = os.path.join(self.tmp.name, "other_config")
        with open(other, "w") as fh:
            fh.write("Host elsewhere\n")
        self.run_cli("connect", "--config", other, "--run", self.free, "elsewhere")
        self.assertEqual(self.launched(), ["--app-id=omassh", SESSION, "run", "elsewhere", "--config", other, "--command", self.free])

    def test_a_run_id_for_another_host_is_refused_and_nothing_launches(self):
        r = self.run_cli("connect", "--run", self.only, "server")
        self.assertEqual(r.returncode, 3)
        self.assertIsNone(self.launched())
        self.assertEqual(self.run_cli("connect", "--run", self.only, "web").returncode, 0)
        self.assertEqual(self.launched()[-3:], ["web", "--command", self.only])

    def test_unknown_malformed_and_hostile_run_ids_are_refused(self):
        for cid in ("0" * 16, "", self.free.upper(), self.free[:15], "$(id)", "../x", self.free + ";id"):
            r = self.run_cli("connect", "--run", cid, "server")
            self.assertEqual(r.returncode, 3, cid)
        self.assertIsNone(self.launched())
        self.assertNotIn("server", self.state()["recent"] if self.state() else {})

    def test_an_insecure_or_missing_commands_file_refuses_run(self):
        self.save_commands([{"name": "Free", "command": "df -h"}], mode=0o666)
        self.assertEqual(self.run_cli("connect", "--run", self.free, "server").returncode, 3)
        os.unlink(os.path.join(self.tmp.name, "xdg", "omassh", "commands.json"))
        self.assertEqual(self.run_cli("connect", "--run", self.free, "server").returncode, 3)
        self.assertIsNone(self.launched())

    def test_modes_are_mutually_exclusive(self):
        for flags in (["--sftp", "--tmux"], ["--tmux", "--copy-id"], ["--sftp", "--run", self.free], ["--copy-id", "--run", self.free]):
            r = self.run_cli("connect", *flags, "server")
            self.assertEqual(r.returncode, 2, flags)
        self.assertIsNone(self.launched())

    def test_the_recent_host_is_recorded_for_every_mode(self):
        self.fake("ssh-copy-id", os.path.join(self.tmp.name, "unused"))
        for flags in (["--tmux"], ["--copy-id"], ["--run", self.free]):
            self.setUp()
            self.fake("ssh-copy-id", os.path.join(self.tmp.name, "unused"))
            self.save_commands([{"name": "Free", "command": "df -h"}])
            self.assertEqual(self.run_cli("connect", *flags, "server").returncode, 0, flags)
            self.assertIn("server", self.state()["recent"], flags)

    def test_hostile_aliases_are_refused_in_every_mode(self):
        for flags in (["--tmux"], ["--copy-id"], ["--run", self.free], ["--sftp"]):
            for hostile in ("-oProxyCommand=touch x", "a@b", "$(id)", "server;id"):
                r = self.run_cli("connect", *flags, "--", hostile)
                self.assertEqual(r.returncode, 3, (flags, hostile))
        self.assertIsNone(self.launched())


class TunnelCase(CliCase):
    FAKE_SSH = r"""#!/bin/sh
printf "%%s\0" "$@" > "%(argv)s"
case "${FAKE_SSH_MODE-}" in
  fail) echo "Permission denied (publickey)." >&2; exit 255 ;;
  vanish) exit 0 ;;
  slow) : > "%(marker)s"; sleep 2 ;;
  stubborn) ( trap "" TERM; while :; do sleep 1; done ) &
    exit 0 ;;
esac
( while :; do sleep 1; done ) &
exit 0
"""

    def setUp(self):
        super().setUp()
        self.addCleanup(support.reap, self.tmp.name)
        os.symlink(shutil.which("sleep"), os.path.join(self.bin, "sleep"))
        suffix = os.path.basename(self.tmp.name)[3:]
        self.alias = "omassh-t-" + suffix
        self.plain = "omassh-p-" + suffix
        self.cleared = "omassh-c-" + suffix
        self.argvfile = os.path.join(self.tmp.name, "ssh.argv")
        self.marker = os.path.join(self.tmp.name, "slow.marker")
        with open(self.config, "w") as fh:
            fh.write(
                "Host %s\n  HostName 192.0.2.10\n  LocalForward 8080 localhost:80\n  DynamicForward 1080\n"
                "Host %s\n  HostName 192.0.2.11\n"
                "Host %s\n  HostName 192.0.2.12\n  LocalForward 8081 localhost:80\n  ClearAllForwardings yes\n"
                % (self.alias, self.plain, self.cleared)
            )
        path = os.path.join(self.bin, "ssh")
        with open(path, "w") as fh:
            fh.write(self.FAKE_SSH % {"argv": self.argvfile, "marker": self.marker})
        os.chmod(path, 0o755)
        self.state_file = os.path.join(self.tmp.name, "state", "omassh", "state.json")

    def tunnel(self, *args, **extra):
        """Run an omassh tunnel subcommand and parse its JSON output."""
        r = self.run_cli("tunnel", *args, **extra)
        return r, (json.loads(r.stdout) if r.stdout.strip() else None)

    def start(self, alias=None, **extra):
        """Start the tunnel of the test alias."""
        return self.tunnel("start", "--", alias or self.alias, **extra)

    def recorded_argv(self):
        """The arguments the fake ssh recorded."""
        with open(self.argvfile, "rb") as fh:
            return [a.decode() for a in fh.read().split(b"\0")[:-1]]

    def alive(self, pid):
        """True while the process exists and is not a zombie."""
        info = tunnels.proc_info(pid)
        return info is not None and info["state"] not in ("Z", "X")

    def up(self):
        """Start the tunnel of the test alias and return its record."""
        r, out = self.start()
        self.assertEqual((r.returncode, out["state"]), (0, "up"), r.stderr)
        return self.state()["tunnels"][self.alias]


class TunnelStartTests(TunnelCase):
    def test_start_reports_up_runs_the_exact_argv_and_records_the_process(self):
        r, out = self.start()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(set(out), {"version", "alias", "state", "since", "already"})
        self.assertEqual((out["version"], out["alias"], out["state"], out["already"]), (1, self.alias, "up", False))
        self.assertEqual(self.recorded_argv(), tunnels.tunnel_args(self.alias, ""))
        rec = self.state()["tunnels"][self.alias]
        self.assertEqual(rec["since"], out["since"])
        with open("/proc/%d/cmdline" % rec["pid"], "rb") as fh:
            self.assertEqual(fh.read().split(b"\0")[2:-1], [a.encode() for a in tunnels.tunnel_args(self.alias, "")])
        self.assertTrue(tunnels.verify(rec, self.alias, tunnels.PROC, tunnels.boot_id(), os.getuid()))

    def test_start_shows_up_in_list_and_tunnel_list(self):
        rec = self.up()
        data = json.loads(self.run_cli("list").stdout)
        hosts = {h["alias"]: h for h in data["hosts"]}
        self.assertEqual(hosts[self.alias]["tunnel"], {"since": rec["since"]})
        self.assertIsNone(hosts[self.plain]["tunnel"])
        self.assertEqual(data["tunnels"], 1)
        r, out = self.tunnel("list")
        self.assertEqual(out, {"version": 1, "tunnels": [{"alias": self.alias, "since": rec["since"]}]})

    def test_a_second_start_reports_already_and_spawns_nothing(self):
        first = self.up()
        os.unlink(self.argvfile)
        r, out = self.start()
        self.assertEqual((r.returncode, out["state"], out["already"], out["since"]), (0, "up", True, first["since"]))
        self.assertFalse(os.path.exists(self.argvfile))

    def test_stop_ends_the_process_and_forgets_it(self):
        rec = self.up()
        r, out = self.tunnel("stop", "--", self.alias)
        self.assertEqual((r.returncode, out), (0, {"version": 1, "alias": self.alias, "state": "down", "stopped": True}))
        self.assertNotIn(self.alias, self.state()["tunnels"])
        self.assertFalse(self.alive(rec["pid"]))
        self.assertIsNone(json.loads(self.run_cli("list").stdout)["hosts"][0]["tunnel"])
        self.assertEqual(self.tunnel("list")[1], {"version": 1, "tunnels": []})

    def test_a_tunnel_that_ignores_the_signal_is_reported_as_still_up(self):
        r, out = self.start(FAKE_SSH_MODE="stubborn")
        self.assertEqual((r.returncode, out["state"]), (0, "up"))
        rec = self.state()["tunnels"][self.alias]
        r, out = self.tunnel("stop", "--", self.alias)
        self.assertEqual((r.returncode, out), (0, {"version": 1, "alias": self.alias, "state": "up", "stopped": False}))
        self.assertTrue(self.alive(rec["pid"]))
        self.assertEqual(self.state()["tunnels"][self.alias], rec)
        self.assertEqual(self.tunnel("stop", "--all")[1], {"version": 1, "stopped": []})
        self.assertTrue(self.alive(rec["pid"]))

    def test_stop_all(self):
        rec = self.up()
        r, out = self.tunnel("stop", "--all")
        self.assertEqual((r.returncode, out), (0, {"version": 1, "stopped": [self.alias]}))
        self.assertFalse(self.alive(rec["pid"]))
        self.assertEqual(self.state()["tunnels"], {})

    def test_stopping_something_that_is_not_running_is_harmless(self):
        r, out = self.tunnel("stop", "--", self.alias)
        self.assertEqual((r.returncode, out["stopped"], out["state"]), (0, False, "down"))
        self.assertEqual(self.tunnel("stop", "--all")[1], {"version": 1, "stopped": []})

    def test_stop_needs_exactly_one_target(self):
        for args in ((), ("--all", "--", self.alias)):
            self.assertEqual(self.run_cli("tunnel", "stop", *args).returncode, 2, args)

    def test_stop_refuses_a_hostile_alias(self):
        for alias in ("-oX=y", "a b", "a@b", "x;id"):
            r = self.run_cli("tunnel", "stop", "--", alias)
            self.assertEqual((r.returncode, r.stdout), (3, ""), alias)

    def test_a_failed_login_exits_five_with_the_message(self):
        r, out = self.start(FAKE_SSH_MODE="fail")
        self.assertEqual(r.returncode, 5)
        self.assertEqual(out, {"version": 1, "alias": self.alias, "state": "down", "reason": "failed", "message": "Permission denied (publickey)."})
        self.assertIsNone(self.state())

    def test_ssh_that_leaves_nothing_running_is_reported_as_vanished(self):
        r, out = self.start(FAKE_SSH_MODE="vanish")
        self.assertEqual((r.returncode, out["state"], out["reason"]), (5, "down", "vanished"))
        self.assertIsNone(self.state())

    def test_a_missing_ssh_is_reported(self):
        os.unlink(os.path.join(self.bin, "ssh"))
        r, out = self.start()
        self.assertEqual((r.returncode, out["state"], out["reason"]), (5, "down", "ssh-missing"))

    def test_a_host_without_forwards_is_refused_and_spawns_nothing(self):
        for alias in (self.plain, self.cleared):
            r, out = self.start(alias)
            self.assertEqual((r.returncode, out["state"], out["reason"], out["alias"]), (5, "down", "no-forwards", alias), alias)
            self.assertFalse(os.path.exists(self.argvfile), alias)

    def test_a_host_whose_forwards_depend_on_match_is_started_anyway(self):
        other = os.path.join(self.tmp.name, "match_config")
        with open(other, "w") as fh:
            fh.write("Host %s\n  HostName 192.0.2.13\nMatch all\n  LocalForward 8082 localhost:80\n" % self.plain)
        r, out = self.tunnel("start", "--config", other, "--", self.plain)
        self.assertEqual((r.returncode, out["state"]), (0, "up"), r.stderr)
        self.assertEqual(self.recorded_argv(), tunnels.tunnel_args(self.plain, other))

    def test_unknown_and_hostile_aliases_spawn_nothing(self):
        for alias in ("nothere", "-oProxyCommand=touch x", "a@b", "$(id)"):
            r, out = self.start(alias)
            self.assertEqual((r.returncode, out), (3, None), alias)
        self.assertFalse(os.path.exists(self.argvfile))

    def test_a_custom_config_reaches_ssh_and_the_record(self):
        other = os.path.join(self.tmp.name, "other_config")
        with open(other, "w") as fh:
            fh.write("Host %s\n  LocalForward 9 localhost:9\n" % self.alias)
        r, out = self.tunnel("start", "--config", other, "--", self.alias)
        self.assertEqual((r.returncode, out["state"]), (0, "up"), r.stderr)
        self.assertEqual(self.recorded_argv(), tunnels.tunnel_args(self.alias, other))
        self.assertEqual(self.state()["tunnels"][self.alias]["config"], other)

    def test_hostile_forward_text_never_reaches_argv(self):
        with open(self.config, "a") as fh:
            fh.write("Host %s\n  LocalForward 8080 $(touch pwned):80\n  LocalForward 9 -oProxyCommand=x:1\n" % self.alias)
        self.assertEqual(self.start()[1]["state"], "up")
        argv = self.recorded_argv()
        self.assertEqual(argv, tunnels.tunnel_args(self.alias, ""))
        self.assertFalse([a for a in argv if "pwned" in a or "ProxyCommand" in a])

    def test_the_state_lock_is_not_held_while_ssh_connects(self):
        proc = subprocess.Popen([OMASSH, "tunnel", "start", "--", self.alias], stdout=subprocess.PIPE, text=True, env=self.env(FAKE_SSH_MODE="slow"))
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        for _ in range(250):
            if os.path.exists(self.marker):
                break
            time.sleep(0.02)
        self.assertTrue(os.path.exists(self.marker))
        began = time.monotonic()
        self.assertEqual(self.run_cli("pin", "--", self.plain).returncode, 0)
        self.assertLess(time.monotonic() - began, 1.5)
        self.assertIsNone(proc.poll())
        self.assertEqual(json.loads(proc.communicate(timeout=30)[0])["state"], "up")
        self.assertEqual(self.state()["pinned"], [self.plain])

    def test_a_tunnel_killed_behind_our_back_is_pruned(self):
        rec = self.up()
        os.kill(rec["pid"], signal.SIGKILL)
        deadline = time.monotonic() + 5
        while self.alive(rec["pid"]) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(json.loads(self.run_cli("list").stdout)["tunnels"], 0)
        self.assertIn(self.alias, self.state()["tunnels"])
        self.assertEqual(self.tunnel("list")[1], {"version": 1, "tunnels": []})
        self.assertEqual(self.state()["tunnels"], {})

    def test_a_tampered_state_file_never_signals_an_unrelated_process(self):
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], stdin=subprocess.DEVNULL)
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        info = tunnels.proc_info(other.pid)
        for start in (info["start"], info["start"] + 1):
            rec = {"pid": other.pid, "start": start, "boot": tunnels.boot_id(), "since": 1_764_000_000, "config": ""}
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, "w") as fh:
                json.dump({"version": 2, "pinned": [], "recent": {}, "tunnels": {self.alias: rec}}, fh)
            self.assertEqual(json.loads(self.run_cli("list").stdout)["tunnels"], 0)
            r, out = self.tunnel("stop", "--", self.alias)
            self.assertEqual((r.returncode, out["stopped"]), (0, False))
            self.assertIsNone(other.poll())
            self.assertEqual(self.state()["tunnels"], {})
            with open(self.state_file, "w") as fh:
                json.dump({"version": 2, "pinned": [], "recent": {}, "tunnels": {self.alias: rec}}, fh)
            self.assertEqual(self.tunnel("stop", "--all")[1], {"version": 1, "stopped": []})
            self.assertIsNone(other.poll())


class TunnelConnectTests(TunnelCase):
    TOKEN = re.compile(r"^[A-Za-z0-9._+@:,=/-]+$")

    def setUp(self):
        super().setUp()
        self.save_commands([{"name": "Free", "command": "df -h"}])
        self.free = self.command_id("Free", "df -h")
        self.fake("ssh-copy-id", os.path.join(self.tmp.name, "unused"))

    def connect(self, *flags):
        """Run connect for the test alias and return the terminal argv."""
        if os.path.exists(self.record):
            os.unlink(self.record)
        self.assertEqual(self.run_cli("connect", *flags, self.alias).returncode, 0)
        return self.launched()

    def test_no_forwards_is_added_for_every_mode_but_sftp_while_a_tunnel_is_up(self):
        self.up()
        for flags, kind in (((), "ssh"), (("--tmux",), "tmux"), (("--copy-id",), "copy-id"), (("--run", self.free), "run")):
            argv = self.connect(*flags)
            self.assertEqual(argv[-1], "--no-forwards", flags)
            self.assertEqual(argv[2], kind)
        self.assertEqual(self.connect("--run", self.free)[-3:], ["--command", self.free, "--no-forwards"])

    def test_sftp_is_left_alone(self):
        self.up()
        self.assertNotIn("--no-forwards", self.connect("--sftp"))

    def test_no_forwards_is_absent_without_a_tunnel(self):
        for flags in ((), ("--tmux",), ("--copy-id",), ("--run", self.free), ("--sftp",)):
            self.assertNotIn("--no-forwards", self.connect(*flags), flags)

    def test_another_hosts_tunnel_does_not_matter(self):
        self.up()
        self.assertEqual(self.run_cli("connect", "--", self.plain).returncode, 0)
        self.assertNotIn("--no-forwards", self.launched())

    def test_a_dead_tunnel_no_longer_adds_the_flag(self):
        rec = self.up()
        self.tunnel("stop", "--", self.alias)
        self.assertFalse(self.alive(rec["pid"]))
        self.assertNotIn("--no-forwards", self.connect())

    def test_every_token_of_every_terminal_argv_is_shell_neutral(self):
        other = os.path.join(self.tmp.name, "other_config")
        shutil.copy(self.config, other)
        self.up()
        for flags in ((), ("--sftp",), ("--tmux",), ("--copy-id",), ("--run", self.free)):
            for config in ((), ("--config", other)):
                argv = self.connect(*config, *flags)
                self.assertTrue(argv, (flags, config))
                for token in argv:
                    self.assertRegex(token, self.TOKEN, (flags, config))
        self.tunnel("stop", "--all")
        for flags in ((), ("--sftp",), ("--tmux",), ("--copy-id",), ("--run", self.free)):
            for token in self.connect(*flags):
                self.assertRegex(token, self.TOKEN, flags)

    def test_the_command_text_never_appears_on_the_terminal_argv(self):
        self.save_commands([{"name": "Secret name", "command": "echo hunter2 $(id)"}])
        cid = self.command_id("Secret name", "echo hunter2 $(id)")
        argv = self.connect("--run", cid)
        self.assertNotIn("hunter2", " ".join(argv))
        self.assertNotIn("Secret", " ".join(argv))
        self.assertEqual(argv[-2:], ["--command", cid])


class CopyTests(CliCase):
    def setUp(self):
        super().setUp()
        self.copied = os.path.join(self.tmp.name, "copied.argv")
        self.fake("wl-copy", self.copied)

    def test_copies_the_ssh_command(self):
        self.assertEqual(self.run_cli("copy", "--", "server").returncode, 0)
        self.assertEqual(self.launched(self.copied), ["--", "ssh server"])

    def test_copies_the_ssh_command_with_a_custom_config(self):
        other = os.path.join(self.tmp.name, "other_config")
        with open(other, "w") as fh:
            fh.write("Host elsewhere\n")
        self.assertEqual(self.run_cli("copy", "--config", other, "--", "elsewhere").returncode, 0)
        self.assertEqual(self.launched(self.copied), ["--", "ssh -F %s elsewhere" % other])

    def test_target_copies_user_at_host(self):
        self.assertEqual(self.run_cli("copy", "--target", "--", "server").returncode, 0)
        self.assertEqual(self.launched(self.copied), ["--", "admin@192.0.2.10"])

    def test_target_is_refused_when_it_is_not_copyable(self):
        for alias in ("web", "viajump"):
            r = self.run_cli("copy", "--target", "--", alias)
            self.assertEqual(r.returncode, 3, alias)
        with open(self.config, "w") as fh:
            fh.write("Host odd\n  User admin\n  HostName $(id)\nHost pct\n  User %r\n  HostName h\n")
        self.assertEqual(self.run_cli("copy", "--target", "--", "odd").returncode, 3)
        self.assertEqual(self.run_cli("copy", "--target", "--", "pct").returncode, 3)
        self.assertIsNone(self.launched(self.copied))

    def test_unknown_and_hostile_aliases_copy_nothing(self):
        for alias in ("nothere", "-oX=y", "a@b", "$(id)", "server;id"):
            self.assertEqual(self.run_cli("copy", "--", alias).returncode, 3, alias)
            self.assertEqual(self.run_cli("copy", "--target", "--", alias).returncode, 3, alias)
        self.assertIsNone(self.launched(self.copied))

    def test_a_missing_wl_copy_exits_four(self):
        os.unlink(os.path.join(self.bin, "wl-copy"))
        r = self.run_cli("copy", "--", "server")
        self.assertEqual(r.returncode, 4)
        self.assertIn("wl-copy", r.stderr)

    def test_a_failing_wl_copy_exits_four(self):
        with open(os.path.join(self.bin, "wl-copy"), "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        self.assertEqual(self.run_cli("copy", "--", "server").returncode, 4)

    def test_a_wl_copy_that_times_out_is_a_failure(self):
        for waited, code in ((None, 4), (0, 0), (1, 4)):
            stderr = io.StringIO()
            with (
                mock.patch.object(cli.shutil, "which", return_value="/usr/bin/wl-copy"),
                mock.patch.object(cli.launch, "spawn"),
                mock.patch.object(cli.launch, "wait", return_value=waited),
                mock.patch.dict(os.environ, {"HOME": self.home}),
                contextlib.redirect_stderr(stderr),
            ):
                try:
                    status = cli.main(["copy", "--", "server"])
                except SystemExit as exc:
                    status = exc.code
            self.assertEqual(status, code, waited)
            if waited is None:
                self.assertIn("did not finish", stderr.getvalue())

    def test_copy_does_not_record_a_recent_host(self):
        self.run_cli("copy", "--", "server")
        self.assertIsNone(self.state())


class CodeTests(CliCase):
    def setUp(self):
        super().setUp()
        self.uwsm = os.path.join(self.tmp.name, "uwsm.argv")
        self.code = os.path.join(self.tmp.name, "code.argv")
        self.fake("code", self.code)
        self.fake("uwsm-app", self.uwsm)

    def test_launches_through_uwsm_app_when_present(self):
        self.assertEqual(self.run_cli("code", "--", "server").returncode, 0)
        self.assertEqual(self.launched(self.uwsm), ["--", "code", "--remote", "ssh-remote+server"])
        self.assertIsNone(self.launched(self.code))

    def test_falls_back_to_code_directly(self):
        os.unlink(os.path.join(self.bin, "uwsm-app"))
        self.assertEqual(self.run_cli("code", "--", "web").returncode, 0)
        self.assertEqual(self.launched(self.code), ["--remote", "ssh-remote+web"])

    def test_a_missing_code_exits_four(self):
        os.unlink(os.path.join(self.bin, "code"))
        r = self.run_cli("code", "--", "server")
        self.assertEqual(r.returncode, 4)
        self.assertIsNone(self.launched(self.uwsm))

    def test_unknown_and_hostile_aliases_launch_nothing(self):
        for alias in ("nothere", "-oX=y", "a@b", "$(id)", "server;id", "a b"):
            self.assertEqual(self.run_cli("code", "--", alias).returncode, 3, alias)
        self.assertIsNone(self.launched(self.uwsm))
        self.assertIsNone(self.launched(self.code))


class CommandsEditTests(CliCase):
    def setUp(self):
        super().setUp()
        self.editor = os.path.join(self.tmp.name, "editor.argv")
        self.fake("omarchy", self.editor)
        self.directory = os.path.join(self.tmp.name, "xdg", "omassh")
        self.path = os.path.join(self.directory, "commands.json")

    def mode(self, path):
        """The permission bits of a path, without following a symlink."""
        return stat.S_IMODE(os.lstat(path).st_mode)

    def test_creates_the_directory_and_file_and_opens_the_editor(self):
        r = self.run_cli("commands", "edit")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        self.assertEqual(self.launched(self.editor), ["launch", "editor", self.path])
        self.assertEqual((self.mode(self.directory), self.mode(self.path)), (0o700, 0o600))
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b'{"commands": []}\n')

    def test_the_file_it_creates_is_accepted_by_the_loader(self):
        self.assertEqual(self.run_cli("commands", "edit").returncode, 0)
        loaded = commands.load(self.path)
        self.assertEqual((loaded["error"], loaded["commands"], loaded["skipped"]), ("", [], 0))
        listing = json.loads(self.run_cli("list").stdout)
        self.assertEqual((listing["commandsError"], listing["commands"], listing["commandsPath"]), ("", [], self.path))

    def test_a_second_run_leaves_an_existing_file_alone(self):
        self.save_commands([{"name": "Disk usage", "command": "df -h"}], mode=0o640)
        before = os.stat(self.path)
        with open(self.path, "rb") as fh:
            body = fh.read()
        self.assertEqual(self.run_cli("commands", "edit").returncode, 0)
        after = os.stat(self.path)
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), body)
        self.assertEqual((after.st_ino, after.st_mtime_ns, stat.S_IMODE(after.st_mode)), (before.st_ino, before.st_mtime_ns, 0o640))
        self.assertEqual(self.launched(self.editor), ["launch", "editor", self.path])

    def test_an_existing_directory_keeps_its_mode(self):
        os.makedirs(self.directory, mode=0o755)
        os.chmod(self.directory, 0o755)
        self.assertEqual(self.run_cli("commands", "edit").returncode, 0)
        self.assertEqual((self.mode(self.directory), self.mode(self.path)), (0o755, 0o600))

    def test_a_symlink_to_a_regular_file_of_ours_is_followed_and_untouched(self):
        os.makedirs(self.directory)
        target = os.path.join(self.tmp.name, "target.json")
        with open(target, "w") as fh:
            fh.write("keep")
        os.symlink(target, self.path)
        r = self.run_cli("commands", "edit")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.launched(self.editor), ["launch", "editor", self.path])
        with open(target) as fh:
            self.assertEqual(fh.read(), "keep")
        self.assertEqual(os.readlink(self.path), target)

    def test_a_symlink_to_a_directory_is_refused(self):
        os.makedirs(self.directory)
        target = os.path.join(self.tmp.name, "target-dir")
        os.mkdir(target)
        os.symlink(target, self.path)
        r = self.run_cli("commands", "edit")
        self.assertEqual(r.returncode, 3)
        self.assertIn("not a regular file", r.stderr)
        self.assertIsNone(self.launched(self.editor))

    def test_a_dangling_symlink_is_not_followed_to_create_its_target(self):
        os.makedirs(self.directory)
        target = os.path.join(self.tmp.name, "created.json")
        os.symlink(target, self.path)
        self.assertEqual(self.run_cli("commands", "edit").returncode, 3)
        self.assertFalse(os.path.exists(target))
        self.assertIsNone(self.launched(self.editor))

    def test_a_directory_at_the_path_is_refused(self):
        os.makedirs(self.path)
        r = self.run_cli("commands", "edit")
        self.assertEqual(r.returncode, 3)
        self.assertTrue(os.path.isdir(self.path))
        self.assertIsNone(self.launched(self.editor))

    def test_a_file_where_the_directory_belongs_is_refused(self):
        os.makedirs(os.path.dirname(self.directory))
        with open(self.directory, "w") as fh:
            fh.write("x")
        self.assertEqual(self.run_cli("commands", "edit").returncode, 3)
        self.assertIsNone(self.launched(self.editor))
        with open(self.directory) as fh:
            self.assertEqual(fh.read(), "x")

    def test_a_missing_launcher_exits_four_and_creates_nothing(self):
        os.unlink(os.path.join(self.bin, "omarchy"))
        r = self.run_cli("commands", "edit")
        self.assertEqual(r.returncode, 4)
        self.assertFalse(os.path.exists(self.directory))

    def test_a_relative_home_is_refused(self):
        r = self.run_cli("commands", "edit", XDG_CONFIG_HOME="", HOME="relative")
        self.assertEqual(r.returncode, 3)
        self.assertIsNone(self.launched(self.editor))

    def test_it_follows_an_absolute_xdg_config_home(self):
        custom = os.path.join(self.tmp.name, "custom")
        self.assertEqual(self.run_cli("commands", "edit", XDG_CONFIG_HOME=custom).returncode, 0)
        expected = os.path.join(custom, "omassh", "commands.json")
        self.assertEqual(self.launched(self.editor), ["launch", "editor", expected])
        self.assertTrue(os.path.isfile(expected))

    def test_a_subcommand_is_required_and_nothing_runs_on_a_usage_error(self):
        for args in (("commands",), ("commands", "edit", "extra"), ("commands", "nope")):
            self.assertEqual(self.run_cli(*args).returncode, 2, args)
        self.assertIsNone(self.launched(self.editor))
        self.assertFalse(os.path.exists(self.directory))


SSH = shutil.which("ssh")


class EditorCase(CliCase):
    def setUp(self):
        super().setUp()
        self.ssh_dir = os.path.join(self.home, ".ssh")
        os.chmod(self.ssh_dir, 0o700)
        self.managed = os.path.join(self.ssh_dir, "omassh.config")
        self.suffix = os.path.basename(self.tmp.name)[3:]

    def name(self, prefix):
        """An alias that no other test uses."""
        return "omassh-%s-%s" % (prefix, self.suffix)

    def activate(self, text=CONFIG):
        """Make the main config read the host file first."""
        with open(self.config, "w") as fh:
            fh.write("Include ~/.ssh/omassh.config\n" + text)

    def managed_hosts(self, *rows):
        """Write a canonical host file from (alias, fields) rows."""
        hosts = []
        for alias, fields in rows:
            host, errors = hostform.normalize({"alias": alias, **fields}, support.anything_exists)
            self.assertEqual(errors, [])
            hosts.append(host)
        with open(self.managed, "w") as fh:
            fh.write(hostform.render(hosts))
        os.chmod(self.managed, 0o600)
        return hosts

    def read_managed(self):
        """The text of the host file, or None when it is missing."""
        try:
            with open(self.managed, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def snapshot(self):
        """Names, bytes, modes and modification times of everything in the ssh directory."""
        out = {}
        for name in sorted(os.listdir(self.ssh_dir)):
            path = os.path.join(self.ssh_dir, name)
            info = os.lstat(path)
            data = None
            if stat.S_ISREG(info.st_mode):
                with open(path, "rb") as fh:
                    data = fh.read()
            out[name] = (data, info.st_mode, info.st_mtime_ns)
        return out

    def request(self, alias, original="", expect="", **fields):
        """A well-formed host request."""
        host = {"alias": alias, "hostname": "", "user": "", "port": "", "proxyJump": "", "identityFile": "", "forwards": []}
        host.update(fields)
        return {"version": 1, "original": original, "expect": expect, "host": host}

    def send(self, args, data, **extra):
        """Run the CLI with data on stdin and return the completed process with undecoded output."""
        if not isinstance(data, bytes):
            data = (json.dumps(data) + "\n").encode()
        return subprocess.run([OMASSH, *args], input=data, capture_output=True, env=self.env(**extra), timeout=30)

    def reply(self, r):
        """The JSON reply of a finished host or include command, after checking it is one ASCII line."""
        self.assertTrue(r.stdout.isascii(), r.stdout)
        self.assertEqual(r.stdout.count(b"\n"), 1, r.stdout)
        out = json.loads(r.stdout)
        self.assertEqual(out["version"], 1)
        return out

    def post(self, command, data, **extra):
        """Run host save or validate and return its exit status and reply."""
        r = self.send(["host", command], data, **extra)
        return r.returncode, self.reply(r)

    def save(self, *args, **kwargs):
        """Run host save for a request built from the arguments."""
        return self.post("save", self.request(*args, **kwargs))

    def delete(self, alias, expect, **extra):
        """Run host delete and return its exit status and reply."""
        r = self.run_cli("host", "delete", "--expect", expect, "--", alias, **extra)
        return r.returncode, self.reply(subprocess.CompletedProcess(r.args, r.returncode, r.stdout.encode(), r.stderr.encode()))

    def real_g(self, alias):
        """The first value of every option ssh -G prints for alias from the main config, with HOME in the temp home; None when ssh rejects the config."""
        r = subprocess.run([SSH, "-G", "-F", self.config, "--", alias], capture_output=True, text=True, env={"HOME": self.home, "PATH": self.bin}, timeout=30)
        if r.returncode != 0:
            return None
        out = {}
        for line in r.stdout.splitlines():
            key, _, value = line.partition(" ")
            out.setdefault(key, value)
        return out

    def listing(self, *args):
        """The parsed list reply."""
        r = self.run_cli("list", *args)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def expect_of(self, alias):
        """The fingerprint the list reply gives for a managed host."""
        return next(h["expect"] for h in self.listing()["editor"]["hosts"] if h["alias"] == alias)


class RealSshCase(EditorCase):
    def setUp(self):
        if not SSH:
            self.skipTest("ssh is not installed")
        super().setUp()
        os.unlink(os.path.join(self.bin, "ssh"))
        os.symlink(SSH, os.path.join(self.bin, "ssh"))
        with open(os.path.join(self.ssh_dir, "id_x"), "w") as fh:
            fh.write("key")
        self.activate()


class ListV3Tests(EditorCase):
    TOP = {"version", "configPath", "configFound", "hosts", "skipped", "errors", "files", "sshFound", "tunnels", "tools", "commands", "commandsPath", "commandsError", "commandsSkipped", "editor"}

    def test_the_shape_is_explicit_and_leaks_no_internal_key(self):
        data = self.listing()
        self.assertEqual((data["version"], set(data)), (3, self.TOP))
        for host in data["hosts"]:
            self.assertEqual((host["origin"], host["editable"]), ("config", False))

    def test_a_config_without_the_include_is_waiting_to_be_set_up(self):
        editor = self.listing()["editor"]
        self.assertEqual(editor, {"enabled": True, "file": "missing", "fileReason": "", "include": "missing", "where": None, "incomplete": False, "path": self.managed, "count": 0, "hosts": []})

    def test_managed_both_and_config_hosts_are_told_apart(self):
        managed, both = self.name("m"), self.name("b")
        self.activate(CONFIG + "Host %s\n  HostName 192.0.2.40\n" % both)
        self.managed_hosts((managed, {"hostname": "192.0.2.41", "forwards": ["L 8080 localhost:80"]}), (both, {"hostname": "192.0.2.42"}))
        data = self.listing()
        by = {h["alias"]: h for h in data["hosts"]}
        self.assertEqual((by[managed]["origin"], by[managed]["editable"]), ("managed", True))
        self.assertEqual((by[both]["origin"], by[both]["editable"]), ("both", False))
        self.assertEqual((by["server"]["origin"], by["server"]["editable"]), ("config", False))
        editor = data["editor"]
        self.assertEqual((editor["file"], editor["include"], editor["where"], editor["count"]), ("ok", "active", {"file": "config", "line": 1}, 2))
        self.assertEqual([h["alias"] for h in editor["hosts"]], [managed, both])
        self.assertEqual(editor["hosts"][0]["forwards"], ["L 8080 localhost:80"])
        self.assertRegex(editor["hosts"][0]["expect"], r"\A[0-9a-f]{16}\Z")

    def test_a_late_or_scoped_include_makes_nothing_editable(self):
        alias = self.name("m")
        self.managed_hosts((alias, {}))
        for text, state in (("User x\nInclude ~/.ssh/omassh.config\n", "late"), ("Host zz\n  Include ~/.ssh/omassh.config\n", "scoped")):
            with open(self.config, "w") as fh:
                fh.write(text)
            data = self.listing()
            self.assertEqual(data["editor"]["include"], state)
            self.assertEqual([h["editable"] for h in data["hosts"] if h["alias"] == alias], [False])

    def test_a_hand_edited_file_is_foreign_and_read_only(self):
        alias = self.name("m")
        self.activate()
        self.managed_hosts((alias, {}))
        with open(self.managed, "a") as fh:
            fh.write("# edited by hand\n")
        data = self.listing()
        self.assertEqual((data["editor"]["file"], data["editor"]["count"], data["editor"]["hosts"]), ("foreign", 0, []))
        host = next(h for h in data["hosts"] if h["alias"] == alias)
        self.assertEqual((host["origin"], host["editable"]), ("managed", False))

    def test_an_unsafe_file_reports_why(self):
        self.activate()
        self.managed_hosts((self.name("m"), {}))
        os.chmod(self.managed, 0o664)
        editor = self.listing()["editor"]
        self.assertEqual((editor["file"], editor["fileReason"], editor["hosts"]), ("unsafe", "mode", []))

    def test_an_ssh_directory_others_can_write_is_unsafe(self):
        os.chmod(self.ssh_dir, 0o777)
        editor = self.listing()["editor"]
        self.assertEqual((editor["file"], editor["fileReason"]), ("unsafe", "dir"))

    def test_a_custom_config_switches_the_editor_off(self):
        self.activate()
        self.managed_hosts((self.name("m"), {}))
        other = os.path.join(self.tmp.name, "other")
        with open(other, "w") as fh:
            fh.write("Host elsewhere\n")
        data = self.listing("--config", other)
        self.assertEqual(data["editor"], {"enabled": False})
        self.assertEqual([(h["alias"], h["origin"], h["editable"]) for h in data["hosts"]], [("elsewhere", "config", False)])
        self.assertEqual(set(data), self.TOP)

    def test_listing_writes_nothing(self):
        self.activate()
        self.managed_hosts((self.name("m"), {}))
        before = self.snapshot()
        self.listing()
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.state())


class RequestTests(EditorCase):
    def refused(self, data, command="save"):
        """Send data and assert it is a usage error that wrote nothing."""
        self.activate()
        before = self.snapshot()
        r = self.send(["host", command], data)
        out = self.reply(r)
        self.assertEqual((r.returncode, out["ok"], out["reason"]), (2, False, "usage"), repr(data)[:80])
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.state())

    def test_malformed_requests_exit_two_and_write_nothing(self):
        good = self.request("web")
        line = json.dumps(good).encode()
        cases = [
            b"",
            b"\n",
            line,
            line + b"\n" + line + b"\n",
            line + b"\nextra",
            b"x" * 70000 + b"\n",
            b"x" * 70000,
            line.replace(b"web", b"w\xff"),
            b"\xef\xbb\xbf" + line + b"\n",
            b"not json\n",
            b"[]\n",
            b"null\n",
            b'{"version":1,"original":"","expect":"","host":' + b'{"alias":"a","alias":"b"}}\n',
            line[:-1] + b',"extra":1}\n',
            b"NaN\n",
            b"[" * 100000 + b"\n",
        ]
        for data in cases:
            self.refused(data)
            self.refused(data, "validate")

    def test_wrong_keys_and_types_exit_two(self):
        def make(change):
            """A request with one change applied."""
            request = self.request("web")
            change(request)
            return request

        cases = [
            make(lambda r: r.pop("expect")),
            make(lambda r: r.update(extra="x")),
            make(lambda r: r["host"].pop("port")),
            make(lambda r: r["host"].update(extra="x")),
            make(lambda r: r.update(version=2)),
            make(lambda r: r.update(version=True)),
            make(lambda r: r.update(version="1")),
            make(lambda r: r.update(original=None)),
            make(lambda r: r.update(expect=5)),
            make(lambda r: r.update(host=None)),
            make(lambda r: r["host"].update(port=22)),
            make(lambda r: r["host"].update(alias=None)),
            make(lambda r: r["host"].update(forwards="L 1 a:2")),
            make(lambda r: r["host"].update(forwards=[1])),
            make(lambda r: r["host"].update(forwards=[["L"]])),
            make(lambda r: r.update(original="-oProxyCommand=x")),
            make(lambda r: r.update(original="a b")),
            make(lambda r: r.update(expect="XYZ")),
            make(lambda r: r.update(expect="0123456789ABCDEF")),
            make(lambda r: r.update(expect="0123456789abcdef0")),
        ]
        for request in cases:
            self.refused(request)

    def test_hostile_values_exit_three_and_write_nothing(self):
        self.activate()
        alias = self.name("h")
        hostile = ["a\nProxyCommand x", "a\rb", "a\x00b", "a\x0bb", "a\x85b", "a b", "a‮b", "a​b", "﻿a", "%h", "${HOME}", "~root/x", "-oProxyCommand=x", "a;b", "a b", '"a"', "a#b", "a\\b", "a=b", "web\n"]
        for field in ("alias", "hostname", "user", "port", "proxyJump", "identityFile"):
            for value in hostile:
                before = self.snapshot()
                code, out = self.save(value) if field == "alias" else self.save(alias, **{field: value})
                if field != "alias" or value:
                    self.assertEqual((code, out["ok"], out["reason"]), (3, False, "invalid"), (field, value))
                self.assertIn(field, {e["field"] for e in out["errors"]}, (field, value))
                self.assertEqual(self.snapshot(), before)
        for row in ("L 8080 localhost:80\nProxyCommand x", "L *:8080 localhost:80", "L 0.0.0.0:8080 localhost:80", "L /tmp/s localhost:80", "L 8080", "D 1 2", "X 1", "L 1 a:2\r", "R 1 2 3 4"):
            code, out = self.save(alias, forwards=[row])
            self.assertEqual((code, out["errors"]), (3, [{"field": "forwards", "index": 0, "code": "forward"}]), row)
        self.assertIsNone(self.read_managed())

    def test_field_errors_are_collected_with_their_codes(self):
        self.activate()
        code, out = self.save("", port="0", user="-x", forwards=["L 1 a:2", "bad", "L 1 a:2"])
        self.assertEqual(code, 3)
        self.assertEqual(out["reason"], "invalid")
        self.assertEqual(
            out["errors"],
            [
                {"field": "alias", "code": "required"},
                {"field": "user", "code": "invalid"},
                {"field": "port", "code": "port"},
                {"field": "forwards", "index": 1, "code": "forward"},
                {"field": "forwards", "index": 2, "code": "duplicate"},
            ],
        )
        self.assertNotIn("message", out)

    def test_request_reader_reads_one_line_and_ignores_what_never_comes(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        line = json.dumps(self.request("web")).encode() + b"\n"
        os.write(write, line)
        self.assertEqual(cli.read_request(read, 5, 65536)["host"]["alias"], "web")
        os.write(write, line[:10])
        start = time.monotonic()
        with self.assertRaises(cli.BadRequest):
            cli.read_request(read, 0.3, 65536)
        self.assertLess(time.monotonic() - start, 3)
        os.close(write)

    def test_request_reader_joins_chunks_and_stops_at_the_newline(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        line = json.dumps(self.request("web")).encode() + b"\n"
        for start in range(0, len(line), 7):
            os.write(write, line[start : start + 7])
        os.close(write)
        self.assertEqual(cli.read_request(read, 5, 65536)["host"]["alias"], "web")

    def test_request_reader_limit_is_on_the_line_without_its_newline(self):
        request = self.request("web")
        request["host"]["forwards"] = [""]
        padding = 65536 - len(json.dumps(request).encode())
        for size, ok in ((65536, True), (65537, False)):
            request["host"]["forwards"] = ["x" * (padding + size - 65536)]
            data = json.dumps(request).encode()
            self.assertEqual(len(data), size)
            path = os.path.join(self.tmp.name, "request")
            with open(path, "wb") as fh:
                fh.write(data + b"\n")
            read = os.open(path, os.O_RDONLY)
            try:
                if ok:
                    self.assertEqual(cli.read_request(read, 5, 65536)["host"]["alias"], "web")
                else:
                    with self.assertRaises(cli.BadRequest):
                        cli.read_request(read, 5, 65536)
            finally:
                os.close(read)


class ArgvTests(EditorCase):
    def test_usage_errors_exit_two_and_change_nothing(self):
        self.activate()
        before = (self.snapshot(), self.state())
        alias = self.name("a")
        cases = [
            ("host",),
            ("host", "nope"),
            ("host", "save", "extra"),
            ("host", "save", "--config", self.config),
            ("host", "validate", "x"),
            ("host", "delete", alias),
            ("host", "delete", "--expect", "0123456789abcdef"),
            ("host", "delete", "--expect", "XYZ", alias),
            ("host", "delete", "--expect", "0123456789ABCDEF", alias),
            ("host", "delete", "--expect", "0123456789abcdef0", alias),
            ("include",),
            ("include", "status", "x"),
            ("include", "apply"),
            ("include", "apply", "--confirm"),
            ("include", "apply", "--expect", "0123456789abcdef"),
            ("include", "apply", "--confirm", "--expect", "nothex"),
        ]
        for args in cases:
            r = self.run_cli(*args)
            self.assertEqual(r.returncode, 2, args)
            self.assertEqual(r.stdout, "")
        self.assertEqual((self.snapshot(), self.state()), before)

    def test_a_hostile_alias_to_delete_exits_three(self):
        self.activate()
        before = self.snapshot()
        for alias in ("-oProxyCommand=x", "a b", "a;b", "$(id)", "../x", "a@b"):
            r = self.run_cli("host", "delete", "--expect", "0123456789abcdef", "--", alias)
            self.assertEqual(r.returncode, 3, alias)
            self.assertEqual(json.loads(r.stdout)["reason"], "not-managed")
        self.assertEqual(self.snapshot(), before)


class IncludeCliTests(EditorCase):
    def status(self):
        """The status reply."""
        r = self.run_cli("include", "status")
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def apply(self, expect):
        """Run include apply and return its exit status and reply."""
        r = self.run_cli("include", "apply", "--confirm", "--expect", expect)
        return r.returncode, json.loads(r.stdout)

    def test_status_describes_the_insertion(self):
        shown = self.status()
        self.assertEqual((shown["version"], shown["include"], shown["path"], shown["target"], shown["create"]), (1, "missing", self.config, "", False))
        self.assertEqual((shown["line"], shown["insert"], shown["before"], shown["refusal"]), (1, "Include ~/.ssh/omassh.config", [], ""))
        self.assertEqual(shown["after"], ["Host server", "  HostName 192.0.2.10", "  User admin"])

    def test_apply_inserts_once_backs_up_and_is_idempotent(self):
        shown = self.status()
        code, out = self.apply(shown["expect"])
        self.assertEqual((code, out["ok"], out["changed"], out["include"]), (0, True, True, "active"))
        with open(self.config) as fh:
            self.assertEqual(fh.read(), "Include ~/.ssh/omassh.config\n" + CONFIG)
        with open(out["backup"]) as fh:
            self.assertEqual(fh.read(), CONFIG)
        before = self.snapshot()
        code, again = self.apply(shown["expect"])
        self.assertEqual((code, again), (0, {"version": 1, "ok": True, "changed": False, "backup": "", "include": "active"}))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.status()["include"], "active")

    def test_a_stale_expectation_exits_six_and_changes_nothing(self):
        expect = self.status()["expect"]
        with open(self.config, "a") as fh:
            fh.write("Host more\n")
        before = self.snapshot()
        code, out = self.apply(expect)
        self.assertEqual((code, out["ok"], out["reason"], out["insert"]), (6, False, "conflict", "Include ~/.ssh/omassh.config"))
        self.assertEqual(self.snapshot(), before)

    def test_a_refusal_exits_six_with_the_manual_line(self):
        os.chmod(self.config, 0o664)
        shown = self.status()
        self.assertEqual((shown["refusal"], shown["expect"]), ("mode", ""))
        before = self.snapshot()
        code, out = self.apply("0123456789abcdef")
        self.assertEqual((code, out["reason"], out["refusal"], out["insert"]), (6, "unsafe", "mode", "Include ~/.ssh/omassh.config"))
        self.assertEqual(self.snapshot(), before)

    def test_a_missing_config_is_created_with_only_the_line(self):
        os.unlink(self.config)
        shown = self.status()
        self.assertEqual((shown["create"], shown["line"]), (True, 1))
        code, out = self.apply(shown["expect"])
        self.assertEqual((code, out["backup"]), (0, ""))
        with open(self.config) as fh:
            self.assertEqual(fh.read(), "Include ~/.ssh/omassh.config\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.config).st_mode), 0o600)

    def test_a_symlinked_config_is_followed_and_shown(self):
        target = os.path.join(self.home, "dotfiles", "config")
        os.makedirs(os.path.dirname(target), mode=0o700)
        os.replace(self.config, target)
        os.symlink(target, self.config)
        shown = self.status()
        self.assertEqual((shown["path"], shown["target"]), (self.config, target))
        code, out = self.apply(shown["expect"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.islink(self.config))
        with open(target) as fh:
            self.assertTrue(fh.read().startswith("Include ~/.ssh/omassh.config\n"))
        self.assertEqual(os.path.dirname(out["backup"]), self.ssh_dir)


class IncludeForeignTests(RealSshCase):
    def test_a_broken_host_file_is_never_included_and_the_cli_says_so(self):
        with open(self.config, "w") as fh:
            fh.write("Host other\n  HostName 192.0.2.9\n")
        with open(self.managed, "w") as fh:
            fh.write("Host x\n    Bogus yes\n")
        os.chmod(self.managed, 0o600)
        self.assertEqual(self.real_g("other")["hostname"], "192.0.2.9")
        shown = json.loads(self.run_cli("include", "status").stdout)
        self.assertEqual((shown["refusal"], shown["expect"]), ("managed-foreign", ""))
        before = self.snapshot()
        r = self.run_cli("include", "apply", "--confirm", "--expect", "0123456789abcdef")
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out["ok"], out["reason"], out["refusal"]), (6, False, "unsafe", "managed-foreign"))
        self.assertEqual(self.snapshot(), before)
        with open(self.config, "w") as fh:
            fh.write("Include ~/.ssh/omassh.config\nHost other\n  HostName 192.0.2.9\n")
        self.assertIsNone(self.real_g("other"))

    def test_a_host_file_broken_after_the_preview_is_caught_when_applying(self):
        with open(self.config, "w") as fh:
            fh.write("Host other\n  HostName 192.0.2.9\n")
        expect = json.loads(self.run_cli("include", "status").stdout)["expect"]
        self.assertRegex(expect, r"\A[0-9a-f]{16}\Z")
        with open(self.managed, "w") as fh:
            fh.write("Host x\n    Bogus yes\n")
        os.chmod(self.managed, 0o600)
        before = self.snapshot()
        r = self.run_cli("include", "apply", "--confirm", "--expect", expect)
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out["reason"], out["refusal"]), (6, "unsafe", "managed-foreign"))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.real_g("other")["hostname"], "192.0.2.9")

    def test_a_missing_or_canonical_host_file_is_included(self):
        with open(self.config, "w") as fh:
            fh.write("Host other\n  HostName 192.0.2.9\n")
        shown = json.loads(self.run_cli("include", "status").stdout)
        self.assertEqual(shown["refusal"], "")
        self.managed_hosts((self.name("m"), {"hostname": "192.0.2.51"}))
        shown = json.loads(self.run_cli("include", "status").stdout)
        self.assertEqual(shown["refusal"], "")
        r = self.run_cli("include", "apply", "--confirm", "--expect", shown["expect"])
        self.assertEqual((r.returncode, json.loads(r.stdout)["include"]), (0, "active"))
        self.assertEqual(self.real_g(self.name("m"))["hostname"], "192.0.2.51")


class SaveRealSshTests(RealSshCase):
    def test_saving_before_the_include_exists_is_refused_with_the_status(self):
        for text, state in (("Host zz\n", "missing"), ("User x\nInclude ~/.ssh/omassh.config\n", "late"), ("Host zz\n  Include ~/.ssh/omassh.config\n", "scoped")):
            with open(self.config, "w") as fh:
                fh.write(text)
            before = self.snapshot()
            code, out = self.save(self.name("a"), hostname="192.0.2.50")
            self.assertEqual((code, out["ok"], out["reason"], out["include"]), (6, False, "not-included", state))
            self.assertIn("where", out)
            self.assertEqual(self.snapshot(), before)

    def test_the_whole_setup_and_the_first_save(self):
        with open(self.config, "w") as fh:
            fh.write(CONFIG)
        shown = json.loads(self.run_cli("include", "status").stdout)
        self.assertEqual(shown["include"], "missing")
        code, out = IncludeCliTests.apply(self, shown["expect"])
        self.assertEqual(code, 0)
        alias = self.name("w")
        code, out = self.save(alias, hostname="Web.Example.COM", user="admin", port="2222", forwards=["l 8080 localhost:80"])
        self.assertEqual((code, out), (0, {"version": 1, "ok": True, "alias": alias, "created": True, "renamed": False, "tunnelUp": False}))
        with open(self.managed) as fh:
            self.assertEqual(
                fh.read(),
                hostform.HEADER + "\n\nHost %s\n    HostName web.example.com\n    User admin\n    Port 2222\n    LocalForward 8080 localhost:80\n" % alias,
            )
        self.assertEqual(stat.S_IMODE(os.stat(self.managed).st_mode), 0o600)
        data = self.listing()
        host = next(h for h in data["hosts"] if h["alias"] == alias)
        self.assertEqual((host["origin"], host["editable"], host["hostname"], host["port"]), ("managed", True, "web.example.com", 2222))
        self.assertEqual(data["editor"]["count"], 1)
        self.assertEqual([n for n in os.listdir(self.ssh_dir) if n.startswith(".")], [])

    def test_add_edit_and_the_backup(self):
        first, second = self.name("a"), self.name("b")
        self.assertEqual(self.save(first, hostname="192.0.2.51")[0], 0)
        old = self.read_managed()
        self.assertFalse(os.path.exists(self.managed + ".bak"))
        self.assertEqual(self.save(second, hostname="192.0.2.52", identityFile="~/.ssh/id_x")[0], 0)
        with open(self.managed + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), old)
        code, out = self.save(first, original=first, expect=self.expect_of(first), hostname="192.0.2.53", user="admin")
        self.assertEqual((code, out["created"], out["renamed"], out["tunnelUp"]), (0, False, False, False))
        hosts = hostform.parse(self.read_managed())
        self.assertEqual([(h["alias"], h["hostname"], h["user"]) for h in hosts], [(first, "192.0.2.53", "admin"), (second, "192.0.2.52", "")])
        self.assertEqual(hosts[1]["identityFile"], "~/.ssh/id_x")

    def test_rename_moves_the_pin_and_the_recent_entry_and_keeps_their_order(self):
        old, new = self.name("a"), self.name("b")
        self.assertEqual(self.save(old, hostname="192.0.2.51")[0], 0)
        for alias in ("server", old, "viajump"):
            self.assertEqual(self.run_cli("pin", "--", alias).returncode, 0)
        self.assertEqual(self.run_cli("connect", "--", old).returncode, 0)
        code, out = self.save(new, original=old, expect=self.expect_of(old), hostname="192.0.2.51")
        self.assertEqual((code, out["renamed"], out["created"]), (0, True, False))
        state = self.state()
        self.assertEqual(state["pinned"], ["server", new, "viajump"])
        self.assertIn(new, state["recent"])
        self.assertNotIn(old, state["recent"])

    def test_an_alias_defined_in_another_file_is_taken(self):
        alias = self.name("a")
        self.activate(CONFIG + "Host %s\n  HostName 192.0.2.60\n" % alias)
        before = self.snapshot()
        for target in (alias, "server"):
            code, out = self.save(target)
            self.assertEqual((code, out["reason"], out["errors"]), (3, "invalid", [{"field": "alias", "code": "taken"}]), target)
        code, out = self.post("validate", self.request(alias))
        self.assertEqual((code, out["errors"]), (3, [{"field": "alias", "code": "taken"}]))
        self.assertEqual(self.snapshot(), before)

    def test_an_alias_already_in_the_host_file_is_taken_for_a_new_host_and_a_rename(self):
        first, second = self.name("a"), self.name("b")
        self.save(first, hostname="192.0.2.51")
        self.save(second, hostname="192.0.2.52")
        before = self.snapshot()
        self.assertEqual(self.save(first)[1]["errors"], [{"field": "alias", "code": "taken"}])
        code, out = self.save(first, original=second, expect=self.expect_of(second))
        self.assertEqual((code, out["errors"]), (3, [{"field": "alias", "code": "taken"}]))
        self.assertEqual(self.snapshot(), before)

    def test_a_changed_block_is_a_conflict(self):
        alias = self.name("a")
        self.save(alias, hostname="192.0.2.51")
        stale = self.expect_of(alias)
        self.assertEqual(self.save(alias, original=alias, expect=stale, hostname="192.0.2.52")[0], 0)
        before = self.snapshot()
        code, out = self.save(alias, original=alias, expect=stale, hostname="192.0.2.53")
        self.assertEqual((code, out["ok"], out["reason"]), (6, False, "conflict"))
        self.assertEqual(self.snapshot(), before)

    def test_editing_a_host_the_plugin_does_not_own_is_not_managed(self):
        alias, both = self.name("a"), self.name("b")
        self.activate(CONFIG + "Host %s\n  HostName 192.0.2.70\n" % both)
        self.managed_hosts((alias, {"hostname": "192.0.2.51"}), (both, {"hostname": "192.0.2.52"}))
        before = self.snapshot()
        expect = hostform.block_hash(hostform.parse(self.read_managed())[1])
        for original in ("server", both, self.name("missing")):
            code, out = self.save(self.name("c"), original=original, expect=expect)
            self.assertEqual((code, out["ok"], out["reason"]), (3, False, "not-managed"), original)
        self.assertEqual(self.snapshot(), before)

    def test_an_edit_and_a_new_host_need_the_right_fingerprint_fields(self):
        alias = self.name("a")
        self.save(alias, hostname="192.0.2.51")
        before = self.snapshot()
        self.assertEqual(self.save(self.name("b"), expect="0123456789abcdef")[1]["reason"], "usage")
        self.assertEqual(self.save(alias, original=alias)[1]["reason"], "usage")
        self.assertEqual(self.snapshot(), before)

    def test_a_foreign_or_unsafe_host_file_refuses_every_save(self):
        alias = self.name("a")
        self.save(alias, hostname="192.0.2.51")
        expect = self.expect_of(alias)
        with open(self.managed, "a") as fh:
            fh.write("# by hand\n")
        before = self.snapshot()
        for args in ((self.name("b"), "", ""), (alias, alias, expect)):
            code, out = self.save(args[0], original=args[1], expect=args[2])
            self.assertEqual((code, out["reason"]), (6, "foreign"))
        self.assertEqual(self.snapshot(), before)
        with open(self.managed, "rb") as fh:
            clean = fh.read().replace(b"# by hand\n", b"")
        with open(self.managed, "wb") as fh:
            fh.write(clean)
        os.chmod(self.managed, 0o664)
        before = self.snapshot()
        code, out = self.save(self.name("b"))
        self.assertEqual((code, out["reason"]), (6, "unsafe"))
        self.assertEqual(self.snapshot(), before)
        os.chmod(self.managed, 0o600)
        os.rename(self.managed, self.managed + ".real")
        os.symlink(self.managed + ".real", self.managed)
        before = self.snapshot()
        self.assertEqual(self.save(self.name("b"))[1]["reason"], "unsafe")
        self.assertEqual(self.snapshot(), before)

    def test_the_identity_file_must_exist_and_is_written_as_typed(self):
        alias = self.name("a")
        code, out = self.save(alias, identityFile="~/.ssh/missing")
        self.assertEqual((code, out["errors"]), (3, [{"field": "identityFile", "code": "not-found"}]))
        self.assertIsNone(self.read_managed())
        self.assertEqual(self.save(alias, identityFile="~/.ssh/id_x")[0], 0)
        self.assertIn(b"    IdentityFile ~/.ssh/id_x\n", self.read_managed())
        self.assertNotIn(self.home.encode(), self.read_managed())
        absolute = os.path.join(self.ssh_dir, "id_x")
        if re.fullmatch(r"(?:/[A-Za-z0-9._+@-]+)+", absolute):
            self.assertEqual(self.save(self.name("b"), identityFile=absolute)[0], 0)
        os.mkdir(os.path.join(self.ssh_dir, "adir"))
        self.assertEqual(self.save(self.name("c"), identityFile="~/.ssh/adir")[1]["errors"], [{"field": "identityFile", "code": "not-found"}])

    def test_validate_checks_fields_and_writes_nothing(self):
        self.activate("Host zz\n")
        before = self.snapshot()
        self.assertEqual(self.post("validate", self.request(self.name("a"), hostname="192.0.2.51")), (0, {"version": 1, "ok": True, "alias": self.name("a")}))
        code, out = self.post("validate", self.request(self.name("a"), port="0"))
        self.assertEqual((code, out["errors"]), (3, [{"field": "port", "code": "port"}]))
        self.assertEqual(self.snapshot(), before)

    def test_every_reply_is_ascii_even_for_hostile_unicode(self):
        r = self.send(["host", "save"], self.request("café‮", hostname=" "))
        self.assertEqual(r.returncode, 3)
        self.assertTrue(r.stdout.isascii())

    def test_the_candidate_is_checked_on_its_own_file_with_the_pinned_argv(self):
        argv = os.path.join(self.tmp.name, "g.argv")
        copy = os.path.join(self.tmp.name, "g.copy")
        script = '#!/bin/sh\nprintf "%%s\\0" "$@" > "%s"\ncat "$3" > "%s"\nexec "%s" "$@"\n' % (argv, copy, SSH)
        path = os.path.join(self.bin, "ssh")
        os.unlink(path)
        with open(path, "w") as fh:
            fh.write(script)
        os.chmod(path, 0o755)
        os.symlink(shutil.which("cat"), os.path.join(self.bin, "cat"))
        alias = self.name("a")
        self.assertEqual(self.save(alias, hostname="192.0.2.51")[0], 0)
        with open(argv, "rb") as fh:
            args = [a.decode() for a in fh.read().split(b"\0")[:-1]]
        self.assertEqual((args[:2], args[3:]), (["-G", "-F"], ["--", alias]))
        self.assertEqual(os.path.dirname(args[2]), os.path.realpath(self.ssh_dir))
        self.assertRegex(os.path.basename(args[2]), r"\A\.omassh\.config\.[0-9a-f]{16}\.tmp\Z")
        with open(copy) as fh:
            self.assertEqual(fh.read(), hostform.render(hostform.parse(self.read_managed())))
        self.assertFalse(os.path.exists(args[2]))

    def test_the_main_config_is_never_given_to_ssh_g(self):
        argv = os.path.join(self.tmp.name, "g.argv")
        script = '#!/bin/sh\nprintf "%%s\\0" "$@" >> "%s"\nexec "%s" "$@"\n' % (argv, SSH)
        path = os.path.join(self.bin, "ssh")
        os.unlink(path)
        with open(path, "w") as fh:
            fh.write(script)
        os.chmod(path, 0o755)
        self.activate("Match exec \"touch %s\"\nHost zz\n" % os.path.join(self.tmp.name, "pwned"))
        self.assertEqual(self.save(self.name("a"), hostname="192.0.2.51")[0], 0)
        self.save(self.name("b"), hostname="192.0.2.52")
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "pwned")))
        with open(argv, "rb") as fh:
            self.assertNotIn(self.config.encode(), fh.read())


class IncompleteParseTests(RealSshCase):
    def hidden(self, name="web"):
        """The text of a hand-written host the plugin cannot see."""
        return "Host %s\n  HostName real-prod.example.com\n  User deploy\n" % name

    def refuse_and_show_the_takeover(self, alias):
        """Saving alias is refused with nothing changed, the list says why, and writing the same block by hand shows what ssh would have done."""
        before = self.snapshot()
        code, out = self.save(alias, hostname="192.0.2.50")
        self.assertEqual((code, out["ok"], out["reason"]), (6, False, "incomplete"))
        self.assertLessEqual(len(out["message"]), 200)
        self.assertEqual(self.snapshot(), before)
        data = self.listing()
        self.assertTrue(data["editor"]["incomplete"])
        self.assertTrue(data["hosts"])
        for host in data["hosts"]:
            self.assertEqual((host["editable"], host["noProbe"]), (False, True), host["alias"])
        self.assertEqual(self.real_g(alias)["hostname"], "real-prod.example.com")
        self.managed_hosts((alias, {"hostname": "192.0.2.50"}))
        taken = self.real_g(alias)
        self.assertEqual((taken["hostname"], taken["user"]), ("192.0.2.50", "deploy"))

    def test_an_include_with_a_variable_hides_a_host_and_the_save_is_refused(self):
        alias = self.name("w")
        os.mkdir(os.path.join(self.ssh_dir, "extra"))
        with open(os.path.join(self.ssh_dir, "extra", "a"), "w") as fh:
            fh.write(self.hidden(alias))
        self.activate("Include ${HOME}/.ssh/extra/*\n" + CONFIG)
        self.refuse_and_show_the_takeover(alias)

    def test_an_include_chain_deeper_than_the_limit_hides_a_host_and_the_save_is_refused(self):
        alias = self.name("w")
        os.mkdir(os.path.join(self.ssh_dir, "extra"))
        depth = 6
        for number in range(1, depth + 1):
            body = "Include ~/.ssh/extra/c%d\n" % (number + 1) if number < depth else self.hidden(alias)
            with open(os.path.join(self.ssh_dir, "extra", "c%d" % number), "w") as fh:
                fh.write(body)
        self.activate("Include ~/.ssh/extra/c1\n" + CONFIG)
        self.refuse_and_show_the_takeover(alias)

    def test_more_hosts_than_the_cap_hide_a_host_and_the_save_is_refused(self):
        alias = self.name("w")
        self.activate("".join("Host cap%d\n" % number for number in range(2000)) + self.hidden(alias))
        self.refuse_and_show_the_takeover(alias)

    def test_a_file_over_the_size_limit_hides_a_host_and_the_save_is_refused(self):
        alias = self.name("w")
        os.mkdir(os.path.join(self.ssh_dir, "extra"))
        with open(os.path.join(self.ssh_dir, "extra", "big"), "w") as fh:
            fh.write("# " + "x" * (1 << 20) + "\n" + self.hidden(alias))
        self.activate("Include ~/.ssh/extra/big\n" + CONFIG)
        self.refuse_and_show_the_takeover(alias)

    def test_an_edit_of_a_managed_host_is_refused_too_and_nothing_is_editable(self):
        alias = self.name("m")
        self.activate("Include ${HOME}/.ssh/nothing/*\n" + CONFIG)
        self.managed_hosts((alias, {"hostname": "192.0.2.51"}))
        data = self.listing()
        self.assertEqual([(h["origin"], h["editable"]) for h in data["hosts"] if h["alias"] == alias], [("managed", False)])
        before = self.snapshot()
        code, out = self.save(alias, original=alias, expect=self.expect_of(alias), hostname="192.0.2.52")
        self.assertEqual((code, out["reason"]), (6, "incomplete"))
        self.assertEqual(self.snapshot(), before)

    def test_a_complete_parse_with_skipped_names_and_a_missing_include_is_not_incomplete(self):
        self.activate("Include ~/.ssh/nothing/*\n" + CONFIG)
        data = self.listing()
        self.assertFalse(data["editor"]["incomplete"])
        self.assertGreater(data["skipped"], 0)
        self.assertEqual(self.save(self.name("a"), hostname="192.0.2.50")[0], 0)

    def test_the_include_refusal_comes_before_the_incomplete_one(self):
        with open(self.config, "w") as fh:
            fh.write("User x\nInclude ~/.ssh/omassh.config\nInclude ${HOME}/.ssh/nothing/*\n")
        code, out = self.save(self.name("a"), hostname="192.0.2.50")
        self.assertEqual((code, out["reason"], out["include"]), (6, "not-included", "late"))


class JumpCycleTests(RealSshCase):
    CYCLE = [{"field": "proxyJump", "code": "cycle"}]

    def test_a_host_that_would_close_a_loop_is_rejected_and_nothing_is_written(self):
        first, second = self.name("a"), self.name("b")
        self.managed_hosts((first, {"hostname": "192.0.2.51", "proxyJump": second}))
        before = self.snapshot()
        code, out = self.save(second, hostname="192.0.2.52", proxyJump=first)
        self.assertEqual((code, out["reason"], out["errors"]), (3, "invalid", self.CYCLE))
        code, out = self.post("validate", self.request(second, proxyJump="admin@%s:2200" % first))
        self.assertEqual((code, out["errors"]), (3, self.CYCLE))
        self.assertEqual(self.snapshot(), before)

    def test_a_loop_through_a_hand_written_host_is_found(self):
        first, middle, last = self.name("a"), self.name("m"), self.name("z")
        self.activate(CONFIG + "Host %s\n  HostName 192.0.2.60\n  ProxyJump u@%s\n" % (middle, first))
        self.managed_hosts((first, {"hostname": "192.0.2.51", "proxyJump": "%s:22" % last}))
        before = self.snapshot()
        code, out = self.save(last, hostname="192.0.2.52", proxyJump="server,%s" % middle)
        self.assertEqual((code, out["errors"]), (3, self.CYCLE))
        self.assertEqual(self.snapshot(), before)

    def test_editing_a_host_into_a_loop_is_rejected(self):
        first, second = self.name("a"), self.name("b")
        self.managed_hosts((first, {"hostname": "192.0.2.51"}), (second, {"hostname": "192.0.2.52", "proxyJump": first}))
        before = self.snapshot()
        code, out = self.save(first, original=first, expect=self.expect_of(first), hostname="192.0.2.51", proxyJump=second)
        self.assertEqual((code, out["errors"]), (3, self.CYCLE))
        self.assertEqual(self.snapshot(), before)

    def test_a_chain_without_a_loop_and_a_rename_away_from_one_are_accepted(self):
        first, second, third, renamed = self.name("a"), self.name("b"), self.name("c"), self.name("r")
        self.managed_hosts((first, {"hostname": "192.0.2.51", "proxyJump": second}), (second, {"hostname": "192.0.2.52"}))
        self.assertEqual(self.save(third, hostname="192.0.2.53", proxyJump=first)[0], 0)
        code, out = self.save(renamed, original=first, expect=self.expect_of(first), hostname="192.0.2.51", proxyJump=second)
        self.assertEqual((code, out["renamed"]), (0, True))
        self.assertEqual(self.save(second, original=second, expect=self.expect_of(second), hostname="192.0.2.52", proxyJump=renamed)[1]["errors"], self.CYCLE)

    def test_a_jump_through_none_or_an_unknown_host_is_not_a_loop(self):
        first = self.name("a")
        self.assertEqual(self.save(first, hostname="192.0.2.51", proxyJump="unknown.example.com")[0], 0)
        self.assertEqual(self.save(self.name("b"), hostname="192.0.2.52", proxyJump=first)[0], 0)


class ClosedInputTests(EditorCase):
    def test_a_closed_stdin_is_a_usage_reply_not_a_traceback(self):
        for command in ("save", "validate"):
            r = subprocess.run([OMASSH, "host", command], capture_output=True, env=self.env(), timeout=30, preexec_fn=lambda: os.close(0))
            self.assertEqual(r.returncode, 2, (command, r.stderr))
            out = self.reply(r)
            self.assertEqual((out["ok"], out["reason"]), (False, "usage"))
            self.assertNotIn(b"Traceback", r.stderr)

    def test_an_unusable_descriptor_is_a_bad_request(self):
        read, write = os.pipe()
        os.close(read)
        os.close(write)
        with self.assertRaises(cli.BadRequest):
            cli.read_request(read, 1, 65536)
        with self.assertRaises(cli.BadRequest):
            cli.read_request(-1, 1, 65536)


class SaveFakeSshTests(EditorCase):
    def script(self, body):
        """Replace the stub ssh with a script."""
        path = os.path.join(self.bin, "ssh")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)

    def refused(self, reason, message=None, code=6):
        """Save a host and assert the reply and that nothing changed."""
        self.activate()
        self.managed_hosts((self.name("keep"), {"hostname": "192.0.2.80"}))
        before = self.snapshot()
        status, out = self.save(self.name("a"), hostname="192.0.2.51")
        self.assertEqual((status, out["ok"], out["reason"]), (code, False, reason), out)
        if message is not None:
            self.assertEqual(out["message"], message)
        self.assertEqual(self.snapshot(), before)
        return out

    def test_an_exit_of_255_is_a_rejection_that_carries_ssh_message(self):
        self.script('echo "line 3: Bad configuration option: x" >&2\nexit 255\n')
        out = self.refused("ssh-rejected")
        self.assertIn("Bad configuration option", out["message"])
        self.assertLessEqual(len(out["message"]), 200)

    def test_non_ascii_text_from_ssh_still_gives_an_ascii_reply(self):
        self.script("printf 'caf\\303\\251 \\342\\202\\254\\n' >&2\nexit 255\n")
        out = self.refused("ssh-rejected")
        self.assertEqual(out["message"], "caf\u00e9 \u20ac")

    def test_a_wrong_hostname_fails_the_check(self):
        self.script("echo hostname wrong.example.com\necho port 22\necho clearallforwardings no\n")
        self.refused("check-failed", "ssh reports a different hostname")

    def test_silence_with_exit_zero_fails_the_check(self):
        self.refused("check-failed", "ssh printed nothing")

    def test_a_missing_ssh_exits_four_and_changes_nothing(self):
        os.unlink(os.path.join(self.bin, "ssh"))
        out = self.refused("ssh-missing", code=4)
        self.assertEqual(out["message"], "ssh was not found")

    def test_an_ssh_that_hangs_is_given_up_on(self):
        self.script("exec sleep 30\n")
        os.symlink(shutil.which("sleep"), os.path.join(self.bin, "sleep"))
        self.addCleanup(support.reap, self.tmp.name)
        with mock.patch("hostfile.CHECK_TIMEOUT", 0.3):
            self.activate()
            before = self.snapshot()
            r = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys; sys.path.insert(0, %r); import hostfile; hostfile.CHECK_TIMEOUT = 0.3; import cli; sys.exit(cli.main(['host', 'save']))" % os.path.join(ROOT, "backend")], input=(json.dumps(self.request(self.name("a"), hostname="192.0.2.51")) + "\n").encode(), capture_output=True, env=self.env(), timeout=30)
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out["reason"], out["message"]), (6, "check-failed", "ssh did not answer in time"))
        self.assertEqual(self.snapshot(), before)

    def test_delete_does_not_need_ssh(self):
        alias = self.name("a")
        self.activate()
        self.managed_hosts((alias, {"hostname": "192.0.2.51"}))
        os.unlink(os.path.join(self.bin, "ssh"))
        code, out = self.delete(alias, self.expect_of(alias))
        self.assertEqual((code, out["ok"]), (0, True))
        self.assertEqual(hostform.parse(self.read_managed()), [])


class EditorTunnelCase(TunnelCase):
    def setUp(self):
        super().setUp()
        self.ssh_dir = os.path.join(self.home, ".ssh")
        os.chmod(self.ssh_dir, 0o700)
        self.managed = os.path.join(self.ssh_dir, "omassh.config")
        self.both = "omassh-b-" + os.path.basename(self.tmp.name)[3:]
        with open(self.config, "w") as fh:
            fh.write("Include ~/.ssh/omassh.config\nHost %s\n  HostName 192.0.2.13\n  LocalForward 8082 localhost:80\n" % self.both)
        rows = [
            (self.alias, {"hostname": "192.0.2.10", "forwards": ["L 8080 localhost:80", "D 1080"]}),
            (self.plain, {"hostname": "192.0.2.11"}),
            (self.both, {"hostname": "192.0.2.14", "forwards": ["L 9090 localhost:80"]}),
        ]
        hosts = []
        for alias, fields in rows:
            host, errors = hostform.normalize({"alias": alias, **fields}, support.anything_exists)
            self.assertEqual(errors, [])
            hosts.append(host)
        with open(self.managed, "w") as fh:
            fh.write(hostform.render(hosts))
        os.chmod(self.managed, 0o600)
        if SSH:
            path = os.path.join(self.bin, "ssh")
            with open(path) as fh:
                body = fh.read()
            with open(path, "w") as fh:
                fh.write(body.replace("#!/bin/sh\n", '#!/bin/sh\nif [ "$1" = "-G" ]; then exec "%s" "$@"; fi\n' % SSH, 1))

    def expect_of(self, alias):
        """The fingerprint of a managed host."""
        return next(h["expect"] for h in json.loads(self.run_cli("list").stdout)["editor"]["hosts"] if h["alias"] == alias)

    def read_managed(self):
        """The bytes of the host file."""
        with open(self.managed, "rb") as fh:
            return fh.read()

    def delete(self, alias, expect, **extra):
        """Run host delete and return its exit status and reply."""
        r = self.run_cli("host", "delete", "--expect", expect, "--", alias, **extra)
        return r.returncode, json.loads(r.stdout)

    def save(self, alias, original="", expect="", **fields):
        """Run host save and return its exit status and reply."""
        host = {"alias": alias, "hostname": "", "user": "", "port": "", "proxyJump": "", "identityFile": "", "forwards": []}
        host.update(fields)
        r = subprocess.run([OMASSH, "host", "save"], input=(json.dumps({"version": 1, "original": original, "expect": expect, "host": host}) + "\n").encode(), capture_output=True, env=self.env(), timeout=30)
        return r.returncode, json.loads(r.stdout)


class DeleteTunnelTests(EditorTunnelCase):
    def test_deleting_a_host_stops_its_live_tunnel_and_forgets_its_pin_and_recent_entry(self):
        rec = self.up()
        self.assertEqual(self.run_cli("pin", "--", self.alias).returncode, 0)
        self.assertEqual(self.run_cli("connect", "--", self.alias).returncode, 0)
        old = self.read_managed()
        code, out = self.delete(self.alias, self.expect_of(self.alias))
        self.assertEqual((code, out), (0, {"version": 1, "ok": True, "alias": self.alias, "tunnelStopped": True, "forgotten": True}))
        self.assertFalse(self.alive(rec["pid"]))
        state = self.state()
        self.assertEqual((state["pinned"], state["tunnels"], list(state["recent"])), ([], {}, []))
        self.assertEqual([h["alias"] for h in hostform.parse(self.read_managed())], [self.plain, self.both])
        with open(self.managed + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), old)
        self.assertNotIn(self.alias, [h["alias"] for h in json.loads(self.run_cli("list").stdout)["hosts"]])

    def test_deleting_a_host_without_a_tunnel_reports_none_stopped(self):
        self.assertEqual(self.run_cli("pin", "--", self.plain).returncode, 0)
        code, out = self.delete(self.plain, self.expect_of(self.plain))
        self.assertEqual((code, out["tunnelStopped"], out["forgotten"]), (0, False, True))
        self.assertEqual(self.state()["pinned"], [])

    def test_a_tunnel_that_will_not_stop_blocks_the_delete(self):
        r, out = self.start(FAKE_SSH_MODE="stubborn")
        self.assertEqual(out["state"], "up")
        rec = self.state()["tunnels"][self.alias]
        self.assertEqual(self.run_cli("pin", "--", self.alias).returncode, 0)
        before = self.read_managed()
        code, out = self.delete(self.alias, self.expect_of(self.alias))
        self.assertEqual((code, out["ok"], out["reason"]), (6, False, "tunnel-running"))
        self.assertEqual(self.read_managed(), before)
        self.assertEqual(self.state()["pinned"], [self.alias])
        self.assertTrue(self.alive(rec["pid"]))
        self.assertEqual(self.state()["tunnels"][self.alias], rec)

    def test_a_host_defined_in_both_files_loses_only_its_managed_block_and_keeps_pins_and_tunnel(self):
        r, out = self.start(self.both)
        self.assertEqual(out["state"], "up")
        rec = self.state()["tunnels"][self.both]
        self.assertEqual(self.run_cli("pin", "--", self.both).returncode, 0)
        self.assertEqual(self.run_cli("connect", "--", self.both).returncode, 0)
        code, out = self.delete(self.both, self.expect_of(self.both))
        self.assertEqual((code, out), (0, {"version": 1, "ok": True, "alias": self.both, "tunnelStopped": False, "forgotten": False}))
        self.assertTrue(self.alive(rec["pid"]))
        state = self.state()
        self.assertEqual((state["pinned"], state["tunnels"][self.both], self.both in state["recent"]), ([self.both], rec, True))
        self.assertNotIn(self.both, [h["alias"] for h in hostform.parse(self.read_managed())])
        listed = {h["alias"]: h for h in json.loads(self.run_cli("list").stdout)["hosts"]}
        self.assertEqual((listed[self.both]["origin"], listed[self.both]["editable"]), ("config", False))
        self.assertIsNotNone(listed[self.both]["tunnel"])

    def test_a_hand_written_host_keeps_its_tunnel_pin_and_recent_entry_while_the_include_is_missing(self):
        with open(self.config, "w") as fh:
            fh.write("Host %s\n  HostName 192.0.2.13\n  LocalForward 8082 localhost:80\n" % self.both)
        r, out = self.start(self.both)
        self.assertEqual(out["state"], "up")
        rec = self.state()["tunnels"][self.both]
        self.assertEqual(self.run_cli("pin", "--", self.both).returncode, 0)
        self.assertEqual(self.run_cli("connect", "--", self.both).returncode, 0)
        code, out = self.delete(self.both, self.expect_of(self.both))
        self.assertEqual((code, out), (0, {"version": 1, "ok": True, "alias": self.both, "tunnelStopped": False, "forgotten": False}))
        self.assertTrue(self.alive(rec["pid"]))
        state = self.state()
        self.assertEqual((state["pinned"], state["tunnels"][self.both], self.both in state["recent"]), ([self.both], rec, True))
        self.assertNotIn(self.both, [h["alias"] for h in hostform.parse(self.read_managed())])

    def test_an_incomplete_parse_keeps_the_tunnel_pin_and_recent_entry_of_a_deleted_host(self):
        with open(self.config, "w") as fh:
            fh.write("Include ~/.ssh/omassh.config\nInclude ${HOME}/.ssh/nothing/*\n")
        rec = self.up()
        self.assertEqual(self.run_cli("pin", "--", self.alias).returncode, 0)
        self.assertEqual(self.run_cli("connect", "--", self.alias).returncode, 0)
        code, out = self.delete(self.alias, self.expect_of(self.alias))
        self.assertEqual((code, out), (0, {"version": 1, "ok": True, "alias": self.alias, "tunnelStopped": False, "forgotten": False}))
        self.assertTrue(self.alive(rec["pid"]))
        state = self.state()
        self.assertEqual((state["pinned"], state["tunnels"][self.alias], self.alias in state["recent"]), ([self.alias], rec, True))
        self.assertNotIn(self.alias, [h["alias"] for h in hostform.parse(self.read_managed())])

    def test_a_config_only_alias_is_not_managed_and_nothing_changes(self):
        with open(self.config, "a") as fh:
            fh.write("Host omassh-only-%s\n  HostName 192.0.2.15\n" % self.alias[9:])
        before = self.read_managed()
        code, out = self.delete("omassh-only-" + self.alias[9:], "0123456789abcdef")
        self.assertEqual((code, out["ok"], out["reason"]), (3, False, "not-managed"))
        self.assertEqual(self.read_managed(), before)

    def test_a_stale_fingerprint_is_a_conflict(self):
        before = self.read_managed()
        code, out = self.delete(self.alias, "0123456789abcdef")
        self.assertEqual((code, out["reason"]), (6, "conflict"))
        self.assertEqual(self.read_managed(), before)

    def test_a_missing_or_foreign_host_file(self):
        expect = self.expect_of(self.plain)
        with open(self.managed, "a") as fh:
            fh.write("# by hand\n")
        code, out = self.delete(self.plain, expect)
        self.assertEqual((code, out["reason"]), (6, "foreign"))
        os.unlink(self.managed)
        code, out = self.delete(self.plain, expect)
        self.assertEqual((code, out["reason"]), (3, "not-managed"))

    @unittest.skipUnless(SSH, "ssh is not installed")
    def test_renaming_is_refused_while_the_old_alias_has_a_tunnel_up(self):
        rec = self.up()
        self.assertEqual(self.run_cli("pin", "--", self.alias).returncode, 0)
        before = self.read_managed()
        code, out = self.save(self.alias + "-new", original=self.alias, expect=self.expect_of(self.alias), hostname="192.0.2.10")
        self.assertEqual((code, out["ok"], out["reason"]), (6, False, "tunnel-up"))
        self.assertEqual((self.read_managed(), self.state()["pinned"], self.state()["tunnels"][self.alias]), (before, [self.alias], rec))
        self.assertTrue(self.alive(rec["pid"]))

    @unittest.skipUnless(SSH, "ssh is not installed")
    def test_editing_with_a_tunnel_up_is_allowed_and_reported(self):
        rec = self.up()
        code, out = self.save(self.alias, original=self.alias, expect=self.expect_of(self.alias), hostname="192.0.2.10", forwards=["L 8080 localhost:81"])
        self.assertEqual((code, out), (0, {"version": 1, "ok": True, "alias": self.alias, "created": False, "renamed": False, "tunnelUp": True}))
        self.assertTrue(self.alive(rec["pid"]))
        self.assertIn(b"LocalForward 8080 localhost:81", self.read_managed())

    @unittest.skipUnless(SSH, "ssh is not installed")
    def test_a_host_defined_in_both_files_cannot_be_edited_or_renamed(self):
        before = self.read_managed()
        for alias in (self.both, self.both + "-new"):
            code, out = self.save(alias, original=self.both, expect=self.expect_of(self.both), hostname="192.0.2.14")
            self.assertEqual((code, out["reason"]), (3, "not-managed"))
        self.assertEqual(self.read_managed(), before)

    @unittest.skipUnless(SSH, "ssh is not installed")
    def test_renaming_a_host_without_a_tunnel_moves_its_pin(self):
        self.assertEqual(self.run_cli("pin", "--", self.plain).returncode, 0)
        code, out = self.save(self.plain + "-new", original=self.plain, expect=self.expect_of(self.plain), hostname="192.0.2.11")
        self.assertEqual((code, out["renamed"]), (0, True))
        self.assertEqual(self.state()["pinned"], [self.plain + "-new"])


if __name__ == "__main__":
    unittest.main()
