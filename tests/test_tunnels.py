import os
import sys
import time
import shutil
import signal
import socket
import tempfile
import unittest
import threading
import subprocess
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import store
import support
import tunnels
from sshconfig import is_valid_alias

BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
OTHER_BOOT = "ffffffff-4b5a-6978-8796-a5b4c3d2e1f0"
SH = shutil.which("sh")
UID = os.getuid()


def make_proc(root, pid, *, comm="ssh", state="S", start=1000, uid=1000, euid=None, cmdline=()):
    """Write a fake /proc/<pid> entry."""
    base = os.path.join(root, str(pid))
    os.makedirs(base, exist_ok=True)
    fields = [state] + ["1", "1", "1", "0", "-1", "0"] + ["0"] * 4 + ["0"] * 4 + ["20", "0", "1", "0", str(start), "0", "0"]
    with open(os.path.join(base, "stat"), "w") as fh:
        fh.write("%d (%s) %s\n" % (pid, comm, " ".join(fields)))
    with open(os.path.join(base, "status"), "w") as fh:
        fh.write("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\nGid:\t1\t1\t1\t1\n" % (comm, uid, uid if euid is None else euid, uid, uid))
    with open(os.path.join(base, "cmdline"), "wb") as fh:
        fh.write(b"".join(part.encode() + b"\0" for part in cmdline))


def record(**changes):
    """A tunnel record with valid defaults."""
    rec = {"pid": 4242, "start": 1000, "boot": BOOT, "since": 1_764_000_000, "config": ""}
    rec.update(changes)
    return rec


def wait_until(predicate, timeout=5.0):
    """Poll predicate until it is true or the timeout passes; returns the last value."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() > deadline:
            return value
        time.sleep(0.02)


class FakeProcCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = os.path.join(self.tmp.name, "proc")
        os.makedirs(self.proc)
        self.args = tunnels.tunnel_args("web", "")

    def add(self, pid=4242, **kwargs):
        """Add a fake process that looks like the tunnel of web unless told otherwise."""
        kwargs.setdefault("cmdline", ["/usr/bin/ssh", *self.args])
        make_proc(self.proc, pid, **kwargs)

    def verify(self, rec=None, alias="web", boot=BOOT, uid=1000):
        """Run tunnels.verify against the fake /proc tree."""
        return tunnels.verify(rec or record(), alias, self.proc, boot, uid)


class ArgsTests(unittest.TestCase):
    def test_exact_argument_list(self):
        self.assertEqual(
            tunnels.tunnel_args("web", ""),
            [
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
                "--",
                "web",
            ],
        )

    def test_config_goes_before_the_double_dash(self):
        args = tunnels.tunnel_args("web", "/etc/omassh/config")
        self.assertEqual(args[-4:], ["-F", "/etc/omassh/config", "--", "web"])
        self.assertEqual(args[:-4], tunnels.tunnel_args("web", "")[:-2])

    def test_no_forward_option_ever_reaches_the_list(self):
        for config in ("", "/etc/omassh/config"):
            args = tunnels.tunnel_args("web", config)
            for flag in ("-L", "-R", "-D"):
                self.assertFalse([a for a in args if a.startswith(flag)], flag)
            self.assertFalse([a for a in args if "forward" in a.lower() and "ExitOnForwardFailure" not in a])


class BootIdTests(unittest.TestCase):
    def test_reads_and_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "boot_id")
            with open(path, "w") as fh:
                fh.write(BOOT + "\n")
            self.assertEqual(tunnels.boot_id(path), BOOT)
            with open(path, "w") as fh:
                fh.write("not-a-boot-id\n")
            self.assertEqual(tunnels.boot_id(path), "")
            self.assertEqual(tunnels.boot_id(os.path.join(tmp, "missing")), "")

    def test_the_real_boot_id_is_readable(self):
        self.assertRegex(tunnels.boot_id(), r"^[0-9a-f-]{36}$")


class ProcInfoTests(FakeProcCase):
    def test_reads_every_field(self):
        self.add(start=777, uid=1000, euid=1001)
        info = tunnels.proc_info(4242, self.proc)
        self.assertEqual(info["start"], 777)
        self.assertEqual((info["uid_real"], info["uid_eff"]), (1000, 1001))
        self.assertEqual(info["state"], "S")
        self.assertEqual(info["cmdline"], ["/usr/bin/ssh", *self.args])

    def test_a_process_name_with_spaces_and_parentheses_cannot_move_the_fields(self):
        self.add(comm=") (S 1 2 3) 1 (", state="R", start=555)
        info = tunnels.proc_info(4242, self.proc)
        self.assertEqual((info["start"], info["state"]), (555, "R"))

    def test_missing_or_broken_entries_are_none(self):
        self.assertIsNone(tunnels.proc_info(999, self.proc))
        self.add()
        with open(os.path.join(self.proc, "4242", "stat"), "w") as fh:
            fh.write("4242 (ssh) S 1 2\n")
        self.assertIsNone(tunnels.proc_info(4242, self.proc))
        self.add(pid=4243)
        os.unlink(os.path.join(self.proc, "4243", "status"))
        self.assertIsNone(tunnels.proc_info(4243, self.proc))
        self.add(pid=4244)
        with open(os.path.join(self.proc, "4244", "status"), "w") as fh:
            fh.write("Name:\tssh\nUid:\tx\ty\n")
        self.assertIsNone(tunnels.proc_info(4244, self.proc))

    def test_hostile_pids_are_refused(self):
        for pid in (0, -1, "1", "../4242", None, True, 1.5):
            self.assertIsNone(tunnels.proc_info(pid, self.proc), pid)

    def test_an_oversized_command_line_is_refused(self):
        self.add(cmdline=["x" * (tunnels.MAX_CMDLINE + 10)])
        self.assertIsNone(tunnels.proc_info(4242, self.proc))

    def test_an_empty_command_line_reads_as_empty(self):
        self.add(cmdline=[])
        self.assertEqual(tunnels.proc_info(4242, self.proc)["cmdline"], [])

    def test_a_real_process_can_be_read(self):
        info = tunnels.proc_info(os.getpid())
        self.assertEqual((info["uid_real"], info["uid_eff"]), (UID, UID))
        self.assertIn("python", os.path.basename(info["cmdline"][0]))


class VerifyTests(FakeProcCase):
    def test_a_matching_record_passes(self):
        self.add()
        self.assertTrue(self.verify())

    def test_an_interpreter_prefixed_command_line_passes(self):
        self.add(cmdline=["/bin/sh", "/tmp/fake/ssh", *self.args])
        self.assertTrue(self.verify())

    def test_multi_word_wrapper_prefix_is_rejected(self):
        self.add(cmdline=["timeout", "5", "/usr/bin/ssh", *self.args])
        self.assertFalse(self.verify())

    def test_a_relative_ssh_name_passes(self):
        self.add(cmdline=["ssh", *self.args])
        self.assertTrue(self.verify())

    def test_the_boot_must_match(self):
        self.add()
        self.assertFalse(self.verify(boot=OTHER_BOOT))
        self.assertFalse(self.verify(record(boot=OTHER_BOOT)))
        self.assertFalse(self.verify(boot=""))
        self.assertFalse(self.verify(record(boot=""), boot=""))

    def test_the_start_time_must_match(self):
        self.add()
        self.assertFalse(self.verify(record(start=1001)))
        self.assertFalse(self.verify(record(start=999)))

    def test_the_owner_must_be_us_for_both_ids(self):
        self.add(uid=1001)
        self.assertFalse(self.verify())
        self.add(uid=1000, euid=0)
        self.assertFalse(self.verify())
        self.add(uid=0, euid=1000)
        self.assertFalse(self.verify())

    def test_zombies_and_dead_processes_fail(self):
        for state in ("Z", "X"):
            self.add(state=state)
            self.assertFalse(self.verify(), state)

    def test_the_command_line_must_end_with_exactly_the_expected_arguments(self):
        for cmdline in (
            ["/usr/bin/ssh", *self.args[:-1]],
            ["/usr/bin/ssh", *self.args[1:]],
            ["/usr/bin/ssh", *self.args, "extra"],
            ["/usr/bin/ssh", "-L", "1:h:1", *self.args],
            ["/usr/bin/ssh", *self.args[:-1], "other"],
            ["/usr/bin/ssh", *tunnels.tunnel_args("web", "/etc/omassh/config")],
            ["/usr/bin/sshd", *self.args],
            ["/usr/bin/ssh-agent", *self.args],
            ["/usr/bin/scp", *self.args],
            [*self.args],
            [],
        ):
            self.add(cmdline=cmdline)
            self.assertFalse(self.verify(), cmdline)

    def test_the_configured_path_is_part_of_the_match(self):
        self.add(cmdline=["/usr/bin/ssh", *tunnels.tunnel_args("web", "/etc/omassh/config")])
        self.assertTrue(self.verify(record(config="/etc/omassh/config")))
        self.assertFalse(self.verify(record(config="/etc/omassh/other")))
        self.assertFalse(self.verify(record(config="")))

    def test_the_alias_is_part_of_the_match(self):
        self.add()
        self.assertFalse(self.verify(alias="db"))
        self.assertFalse(self.verify(alias="-oProxyCommand=x"))

    def test_an_unsafe_stored_config_never_verifies(self):
        self.add(cmdline=["/usr/bin/ssh", *tunnels.tunnel_args("web", "relative")])
        self.assertFalse(self.verify(record(config="relative")))

    def test_a_missing_process_fails(self):
        self.assertFalse(self.verify())

    def test_stored_argv_is_never_trusted(self):
        self.add(cmdline=["/usr/bin/ssh", "-oProxyCommand=x", "--", "web"])
        rec = record()
        rec["argv"] = ["/usr/bin/ssh", "-oProxyCommand=x", "--", "web"]
        self.assertFalse(self.verify(rec))


class ScanTests(FakeProcCase):
    def test_a_single_match_is_found_with_its_start(self):
        self.add(pid=10, start=500)
        self.add(pid=11, start=500, cmdline=["/usr/bin/ssh", "-N", "--", "web"])
        self.add(pid=12, start=500, cmdline=["/bin/sh", "-c", "sleep 1"])
        self.assertEqual(tunnels.scan(self.args, 0, self.proc, 1000), [(10, 500)])

    def test_none_and_several(self):
        self.assertEqual(tunnels.scan(self.args, 0, self.proc, 1000), [])
        self.add(pid=10, start=500)
        self.add(pid=11, start=600)
        self.assertEqual(sorted(tunnels.scan(self.args, 0, self.proc, 1000)), [(10, 500), (11, 600)])

    def test_older_processes_and_other_owners_are_ignored(self):
        self.add(pid=10, start=500)
        self.add(pid=11, start=600)
        self.add(pid=12, start=700, uid=1001)
        self.add(pid=13, start=700, state="Z")
        self.assertEqual(tunnels.scan(self.args, 600, self.proc, 1000), [(11, 600)])

    def test_non_numeric_entries_are_skipped(self):
        self.add(pid=10, start=500)
        os.makedirs(os.path.join(self.proc, "self"))
        with open(os.path.join(self.proc, "uptime"), "w") as fh:
            fh.write("1 1\n")
        self.assertEqual(tunnels.scan(self.args, 0, self.proc, 1000), [(10, 500)])


class LiveAndPruneTests(FakeProcCase):
    def setUp(self):
        super().setUp()
        self.boot_file = os.path.join(self.tmp.name, "boot_id")
        with open(self.boot_file, "w") as fh:
            fh.write(BOOT + "\n")
        self.path = os.path.join(self.tmp.name, "state", "omassh", "state.json")

    def test_live_keeps_only_verified_records(self):
        self.add(pid=10, start=500)
        state = store.empty()
        state["tunnels"] = {"web": record(pid=10, start=500), "gone": record(pid=11), "old": record(pid=10, start=499)}
        self.assertEqual(list(tunnels.live(state, self.proc, self.boot_file, 1000)), ["web"])

    def test_a_new_boot_invalidates_everything(self):
        self.add(pid=10, start=500)
        state = store.empty()
        state["tunnels"] = {"web": record(pid=10, start=500, boot=OTHER_BOOT)}
        self.assertEqual(tunnels.live(state, self.proc, self.boot_file, 1000), {})

    def test_prune_removes_stale_records_and_reports_them(self):
        self.add(pid=10, start=500)
        store.modify(
            self.path,
            lambda s: s["tunnels"].update({"web": record(pid=10, start=500), "gone": record(pid=11), "old": record(pid=10, start=499)}),
        )
        self.assertEqual(sorted(tunnels.prune(self.path, self.proc, self.boot_file, 1000)), ["gone", "old"])
        self.assertEqual(list(store.load(self.path)["tunnels"]), ["web"])
        self.assertEqual(tunnels.prune(self.path, self.proc, self.boot_file, 1000), [])

    def test_prune_without_a_state_file_does_nothing(self):
        self.assertEqual(tunnels.prune(self.path, self.proc, self.boot_file, 1000), [])
        self.assertFalse(os.path.exists(self.path))

    def test_prune_after_a_reboot_drops_all_records(self):
        self.add(pid=10, start=500)
        store.modify(self.path, lambda s: s["tunnels"].update({"web": record(pid=10, start=500, boot=OTHER_BOOT)}))
        self.assertEqual(tunnels.prune(self.path, self.proc, self.boot_file, 1000), ["web"])


class TunnelEnvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sock_path = os.path.join(self.tmp.name, "ssh-agent.socket")
        self.listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(self.listener.close)
        self.listener.bind(self.sock_path)

    def env(self, **extra):
        """The environment of a session whose runtime directory holds the agent socket."""
        env = {"XDG_RUNTIME_DIR": self.tmp.name, "PATH": "/usr/bin"}
        env.update(extra)
        return env

    def test_the_socket_is_used_when_nothing_is_set(self):
        out = tunnels.tunnel_env(self.env())
        self.assertEqual(out["SSH_AUTH_SOCK"], self.sock_path)
        self.assertEqual(out["PATH"], "/usr/bin")

    def test_askpass_is_never_allowed(self):
        for extra in ({}, {"SSH_AUTH_SOCK": "/elsewhere/agent"}, {"SSH_ASKPASS": "/usr/bin/askpass", "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":0"}):
            self.assertEqual(tunnels.tunnel_env(self.env(**extra))["SSH_ASKPASS_REQUIRE"], "never", extra)
        self.assertEqual(tunnels.tunnel_env({})["SSH_ASKPASS_REQUIRE"], "never")

    def test_an_existing_value_is_never_replaced(self):
        out = tunnels.tunnel_env(self.env(SSH_AUTH_SOCK="/elsewhere/agent"))
        self.assertEqual(out["SSH_AUTH_SOCK"], "/elsewhere/agent")

    def test_an_empty_value_counts_as_unset(self):
        self.assertEqual(tunnels.tunnel_env(self.env(SSH_AUTH_SOCK=""))["SSH_AUTH_SOCK"], self.sock_path)

    def test_the_input_is_not_modified(self):
        env = self.env()
        tunnels.tunnel_env(env)
        self.assertNotIn("SSH_AUTH_SOCK", env)

    def test_a_relative_or_missing_runtime_dir_is_ignored(self):
        for value in ("relative/dir", "", "/nonexistent/dir\x00x"):
            self.assertNotIn("SSH_AUTH_SOCK", tunnels.tunnel_env(self.env(XDG_RUNTIME_DIR=value)), repr(value))
        env = self.env()
        del env["XDG_RUNTIME_DIR"]
        self.assertNotIn("SSH_AUTH_SOCK", tunnels.tunnel_env(env))

    def test_something_that_is_not_a_socket_is_ignored(self):
        self.listener.close()
        os.unlink(self.sock_path)
        open(self.sock_path, "w").close()
        self.assertNotIn("SSH_AUTH_SOCK", tunnels.tunnel_env(self.env()))

    def test_a_symlink_to_a_socket_is_ignored(self):
        os.unlink(self.sock_path)
        real = os.path.join(self.tmp.name, "real.sock")
        other = socket.socket(socket.AF_UNIX)
        self.addCleanup(other.close)
        other.bind(real)
        os.symlink(real, self.sock_path)
        self.assertNotIn("SSH_AUTH_SOCK", tunnels.tunnel_env(self.env()))

    def test_a_socket_owned_by_someone_else_is_ignored(self):
        self.assertIn("SSH_AUTH_SOCK", tunnels.tunnel_env(self.env(), uid=UID))
        self.assertNotIn("SSH_AUTH_SOCK", tunnels.tunnel_env(self.env(), uid=UID + 1))

    def test_a_missing_socket_is_ignored(self):
        self.listener.close()
        os.unlink(self.sock_path)
        self.assertNotIn("SSH_AUTH_SOCK", tunnels.tunnel_env(self.env()))


class RealProcessCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="omassh-t-")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.reap)
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.bin)
        self.path = os.path.join(self.tmp.name, "state", "omassh", "state.json")
        self.pidfile = os.path.join(self.tmp.name, "pids")
        self.argvfile = os.path.join(self.tmp.name, "argv")
        self.envfile = os.path.join(self.tmp.name, "env")
        self.marker = os.path.join(self.tmp.name, "started")
        self.alias = "omassh-test-" + os.path.basename(self.tmp.name).removeprefix("omassh-t-")
        self.assertTrue(is_valid_alias(self.alias))

    def reap(self):
        """Kill every process left in this test's private directory."""
        support.reap(self.tmp.name)

    def fake_ssh(self, body):
        """Install an executable fake ssh made of a shell script body."""
        path = os.path.join(self.bin, "ssh")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return path

    def dummy(self, args, name="ssh", body="import time\ntime.sleep(120)\n"):
        """Start a python process running body whose command line is [python, <private dir>/<name>, *args]."""
        script = os.path.join(tempfile.mkdtemp(dir=self.tmp.name), name)
        with open(script, "w") as fh:
            fh.write(body)
        proc = subprocess.Popen([sys.executable, script, *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        return proc

    def track(self, alias, proc, **changes):
        """Store a record for a process we started, reading its real start time."""
        info = tunnels.proc_info(proc.pid)
        rec = record(pid=proc.pid, start=info["start"], boot=tunnels.boot_id())
        rec.update(changes)
        store.modify(self.path, lambda s: store.set_tunnel(s, alias, rec))
        return rec

    def alive(self, pid):
        """True while the process exists and is not a zombie."""
        info = tunnels.proc_info(pid)
        return info is not None and info["state"] not in ("Z", "X")

    def recorded_argv(self):
        """The arguments the fake ssh recorded."""
        with open(self.argvfile, "rb") as fh:
            return [a.decode() for a in fh.read().split(b"\0")[:-1]]


class StopTests(RealProcessCase):
    def test_stop_signals_the_verified_process_and_forgets_it(self):
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""))
        self.track(self.alias, proc)
        with open("/proc/%d/cmdline" % proc.pid, "rb") as fh:
            self.assertEqual(fh.read().split(b"\0")[2:-1], [a.encode() for a in tunnels.tunnel_args(self.alias, "")])
        result = tunnels.stop(self.alias, self.path)
        self.assertEqual(result, {"version": 1, "alias": self.alias, "state": "down", "stopped": True})
        self.assertEqual(proc.wait(10), -signal.SIGTERM)
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_wrong_start_time_refuses_and_drops_the_record(self):
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""))
        rec = self.track(self.alias, proc)
        self.track(self.alias, proc, start=rec["start"] + 1)
        result = tunnels.stop(self.alias, self.path)
        self.assertEqual(result, {"version": 1, "alias": self.alias, "state": "down", "stopped": False})
        self.assertIsNone(proc.poll())
        self.assertTrue(self.alive(proc.pid))
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_wrong_boot_refuses(self):
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""))
        self.track(self.alias, proc, boot=OTHER_BOOT)
        self.assertFalse(tunnels.stop(self.alias, self.path)["stopped"])
        self.assertIsNone(proc.poll())

    def test_an_unrelated_process_with_a_forged_record_is_never_signalled(self):
        proc = subprocess.Popen([SH, "-c", "sleep 120", os.path.join(self.tmp.name, "unrelated")], stdin=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        self.track(self.alias, proc)
        self.assertFalse(tunnels.stop(self.alias, self.path)["stopped"])
        self.assertIsNone(proc.poll())
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_process_with_the_wrong_alias_is_never_signalled(self):
        proc = self.dummy(tunnels.tunnel_args("db", ""))
        self.track(self.alias, proc)
        self.assertFalse(tunnels.stop(self.alias, self.path)["stopped"])
        self.assertIsNone(proc.poll())

    def test_a_program_not_called_ssh_is_never_signalled(self):
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""), name="sshd")
        self.track(self.alias, proc)
        self.assertFalse(tunnels.stop(self.alias, self.path)["stopped"])
        self.assertIsNone(proc.poll())

    def test_an_exited_process_is_dropped_without_error(self):
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""))
        self.track(self.alias, proc)
        proc.kill()
        proc.wait()
        self.assertFalse(tunnels.stop(self.alias, self.path)["stopped"])
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_stopping_an_unknown_alias_is_a_no_op(self):
        self.assertEqual(tunnels.stop("ghost", self.path), {"version": 1, "alias": "ghost", "state": "down", "stopped": False})

    def test_stop_all_stops_only_the_verified_ones(self):
        good = self.dummy(tunnels.tunnel_args("a", ""))
        other = self.dummy(tunnels.tunnel_args("b", ""))
        forged = self.dummy(tunnels.tunnel_args("c", ""))
        self.track("a", good)
        self.track("b", other)
        self.track("c", forged, start=1)
        self.assertEqual(tunnels.stop_all(self.path), {"version": 1, "stopped": ["a", "b"]})
        self.assertEqual(good.wait(10), -signal.SIGTERM)
        self.assertEqual(other.wait(10), -signal.SIGTERM)
        self.assertIsNone(forged.poll())
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_process_that_ignores_sigterm_keeps_its_record(self):
        body = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nopen(%r, 'w').close()\ntime.sleep(120)\n" % self.marker
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""), body=body)
        self.assertTrue(wait_until(lambda: os.path.exists(self.marker)))
        self.track(self.alias, proc)
        with mock.patch.object(tunnels, "STOP_WAIT", 0.2):
            result = tunnels.stop(self.alias, self.path)
        self.assertEqual(result, {"version": 1, "alias": self.alias, "state": "up", "stopped": False})
        self.assertIsNone(proc.poll())
        self.assertIn(self.alias, store.load(self.path)["tunnels"])

    def test_stop_and_stop_all_respect_config_filter(self):
        other_cfg = "/etc/omassh/other"
        default_proc = self.dummy(tunnels.tunnel_args("a", ""))
        other_proc = self.dummy(tunnels.tunnel_args("b", other_cfg))
        self.track("a", default_proc, config="")
        self.track("b", other_proc, config=other_cfg)
        self.assertEqual(list(tunnels.live(store.load(self.path), config="")), ["a"])
        self.assertEqual(list(tunnels.live(store.load(self.path), config=other_cfg)), ["b"])
        self.assertEqual(tunnels.stop("b", self.path, ""), {"version": 1, "alias": "b", "state": "down", "stopped": False})
        self.assertIsNone(other_proc.poll())
        self.assertIn("b", store.load(self.path)["tunnels"])
        self.assertEqual(tunnels.stop_all(self.path, ""), {"version": 1, "stopped": ["a"]})
        self.assertEqual(default_proc.wait(10), -signal.SIGTERM)
        self.assertIsNone(other_proc.poll())
        self.assertEqual(list(store.load(self.path)["tunnels"]), ["b"])
        self.assertEqual(tunnels.stop("b", self.path, other_cfg), {"version": 1, "alias": "b", "state": "down", "stopped": True})
        self.assertEqual(other_proc.wait(10), -signal.SIGTERM)
        self.assertEqual(store.load(self.path)["tunnels"], {})


class StartTests(RealProcessCase):
    UP = 'printf "%%s\\0" "$@" > "%(argv)s"\nprintf "%%s" "${SSH_AUTH_SOCK-unset}" > "%(env)s"\n( while :; do sleep 1; done ) &\nexit 0\n'

    def up(self):
        """Install a fake ssh that records its arguments and backgrounds a long-lived subshell."""
        return self.fake_ssh(self.UP % {"argv": self.argvfile, "env": self.envfile})

    def start(self, alias=None, config="", ssh=None, timeout=10.0):
        """Run tunnels.start against the fake ssh and make sure no tunnel outlives the test."""
        alias = alias or self.alias
        self.addCleanup(tunnels.stop_all, self.path)
        return tunnels.start(alias, config, ssh or os.path.join(self.bin, "ssh"), self.path, timeout)

    def test_success_records_the_tunnel_and_runs_the_exact_argv(self):
        self.up()
        result = self.start()
        self.assertEqual(set(result), {"version", "alias", "state", "since", "already"})
        self.assertEqual((result["state"], result["alias"], result["already"]), ("up", self.alias, False))
        self.assertEqual(self.recorded_argv(), tunnels.tunnel_args(self.alias, ""))
        rec = store.load(self.path)["tunnels"][self.alias]
        self.assertEqual(rec["since"], result["since"])
        self.assertEqual(rec["boot"], tunnels.boot_id())
        with open("/proc/%d/cmdline" % rec["pid"], "rb") as fh:
            self.assertEqual(fh.read().split(b"\0")[2:-1], [a.encode() for a in tunnels.tunnel_args(self.alias, "")])
        self.assertTrue(tunnels.verify(rec, self.alias, tunnels.PROC, tunnels.boot_id(), UID))

    def test_the_config_path_reaches_ssh(self):
        self.up()
        config = os.path.join(self.tmp.name, "config")
        self.assertEqual(self.start(config=config)["state"], "up")
        self.assertEqual(self.recorded_argv(), tunnels.tunnel_args(self.alias, config))
        self.assertEqual(store.load(self.path)["tunnels"][self.alias]["config"], config)

    def test_a_hostile_forward_in_the_ssh_config_never_reaches_argv(self):
        self.up()
        config = os.path.join(self.tmp.name, "config")
        with open(config, "w") as fh:
            fh.write("Host web\n  LocalForward 8080 $(touch pwned):80\n  LocalForward 9 -oProxyCommand=x:1\n")
        self.assertEqual(self.start(config=config)["state"], "up")
        argv = self.recorded_argv()
        self.assertEqual(argv, tunnels.tunnel_args(self.alias, config))
        self.assertFalse([a for a in argv if "pwned" in a or "ProxyCommand" in a])

    def test_a_second_start_reports_already_and_spawns_nothing(self):
        self.up()
        first = self.start()
        os.unlink(self.argvfile)
        second = self.start()
        self.assertEqual((second["state"], second["already"], second["since"]), ("up", True, first["since"]))
        self.assertFalse(os.path.exists(self.argvfile))

    def test_an_untracked_identical_tunnel_is_adopted(self):
        self.up()
        proc = self.dummy(tunnels.tunnel_args(self.alias, ""))
        result = self.start()
        self.assertEqual((result["state"], result["already"]), ("up", True))
        self.assertEqual(store.load(self.path)["tunnels"][self.alias]["pid"], proc.pid)
        self.assertFalse(os.path.exists(self.argvfile))

    def test_several_untracked_identical_tunnels_are_refused(self):
        self.up()
        self.dummy(tunnels.tunnel_args(self.alias, ""))
        self.dummy(tunnels.tunnel_args(self.alias, ""))
        self.assertTrue(wait_until(lambda: len(tunnels.scan(tunnels.tunnel_args(self.alias, ""), 0, tunnels.PROC, UID)) >= 2))
        result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("down", "ambiguous"))
        self.assertFalse(os.path.exists(self.argvfile))
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_stale_record_is_replaced(self):
        self.up()
        store.modify(self.path, lambda s: store.set_tunnel(s, self.alias, record(pid=999999, boot=tunnels.boot_id())))
        result = self.start()
        self.assertEqual((result["state"], result["already"]), ("up", False))
        self.assertNotEqual(store.load(self.path)["tunnels"][self.alias]["pid"], 999999)

    def test_a_failure_reports_ssh_s_message_and_exits_without_a_record(self):
        self.fake_ssh('echo "Permission denied (publickey)." >&2\nexit 255\n')
        result = self.start()
        self.assertEqual(result, {"version": 1, "alias": self.alias, "state": "down", "reason": "failed", "message": "Permission denied (publickey)."})
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_the_message_is_the_last_lines_cleaned_and_capped(self):
        self.fake_ssh("printf 'one\\ntwo\\n\\nthree\\n\\033[31mfour\\342\\200\\256e\\n' >&2\nexit 255\n")
        self.assertEqual(self.start()["message"], "two three [31mfoure")
        self.fake_ssh("i=0\nwhile [ $i -lt 100 ]; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >&2; i=$((i+1)); done\nexit 255\n")
        message = self.start()["message"]
        self.assertEqual(len(message), tunnels.MAX_MESSAGE)
        self.assertEqual(set(message), {"x", " "})

    def test_ssh_that_exits_cleanly_without_a_tunnel_is_vanished(self):
        self.fake_ssh("exit 0\n")
        result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("down", "vanished"))
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_missing_ssh_is_reported(self):
        self.assertEqual(tunnels.start(self.alias, "", None, self.path)["reason"], "ssh-missing")
        result = tunnels.start(self.alias, "", os.path.join(self.bin, "nothere"), self.path)
        self.assertEqual((result["state"], result["reason"]), ("down", "failed"))

    def test_unsafe_input_is_refused_before_anything_runs(self):
        self.up()
        for alias, config in (("-oProxyCommand=x", ""), ("a b", ""), (self.alias, "relative"), (self.alias, "/a b"), (self.alias, "/a;id")):
            result = self.start(alias, config)
            self.assertEqual((result["state"], result["reason"]), ("down", "failed"), (alias, config))
        self.assertFalse(os.path.exists(self.argvfile))

    def test_a_timeout_kills_the_whole_process_group(self):
        self.fake_ssh('echo $$ > "%s"\n( while :; do sleep 1; done ) &\necho $! >> "%s"\nwait\n' % (self.pidfile, self.pidfile))
        started = time.monotonic()
        result = self.start(timeout=1.0)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual((result["state"], result["reason"]), ("down", "timeout"))
        with open(self.pidfile) as fh:
            pids = [int(line) for line in fh.read().split()]
        self.assertEqual(len(pids), 2)
        for pid in pids:
            self.assertTrue(wait_until(lambda p=pid: not self.alive(p)), pid)
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_a_group_that_ignores_sigterm_is_killed(self):
        self.fake_ssh('trap "" TERM\necho $$ > "%s"\nwhile :; do sleep 1; done\n' % self.pidfile)
        result = self.start(timeout=1.0)
        self.assertEqual(result["reason"], "timeout")
        with open(self.pidfile) as fh:
            pid = int(fh.read())
        self.assertTrue(wait_until(lambda: not self.alive(pid)))

    def test_ssh_is_started_with_askpass_disabled(self):
        self.fake_ssh('printf "%%s" "${SSH_ASKPASS_REQUIRE-unset}" > "%s"\n( while :; do sleep 1; done ) &\nexit 0\n' % self.envfile)
        with mock.patch.dict(os.environ, {"SSH_ASKPASS": "/usr/bin/askpass", "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":0"}):
            self.assertEqual(self.start()["state"], "up")
        with open(self.envfile) as fh:
            self.assertEqual(fh.read(), "never")

    def test_a_group_member_that_ignores_sigterm_is_killed_too(self):
        self.fake_ssh("sh -c 'trap \"\" TERM; echo $$ > \"%s\"; while :; do sleep 1; done' &\nwait\n" % self.pidfile)
        result = self.start(timeout=1.0)
        self.assertEqual(result["reason"], "timeout")
        with open(self.pidfile) as fh:
            pid = int(fh.read())
        self.assertTrue(wait_until(lambda: not self.alive(pid)))

    def test_the_limit_refuses_a_new_tunnel_but_not_a_known_one(self):
        self.up()
        recs = {"t%d" % i: record(pid=2 + i, boot=tunnels.boot_id()) for i in range(store.MAX_TUNNELS)}
        store.modify(self.path, lambda s: s["tunnels"].update(recs))
        result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("down", "limit"))
        self.assertFalse(os.path.exists(self.argvfile))
        self.assertEqual(sorted(store.load(self.path)["tunnels"]), sorted(recs))
        store.modify(self.path, lambda s: s["tunnels"].update({self.alias: record(pid=999999, boot=tunnels.boot_id())}))
        store.modify(self.path, lambda s: s["tunnels"].pop("t0"))
        self.assertEqual(self.start()["state"], "up")

    def test_the_agent_socket_is_offered_only_when_nothing_is_set(self):
        self.up()
        runtime = self.tmp.name
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(os.path.join(runtime, "ssh-agent.socket"))
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime}):
            os.environ.pop("SSH_AUTH_SOCK", None)
            self.start()
        with open(self.envfile) as fh:
            self.assertEqual(fh.read(), os.path.join(runtime, "ssh-agent.socket"))
        tunnels.stop_all(self.path)
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime, "SSH_AUTH_SOCK": "/elsewhere/agent"}):
            self.start()
        with open(self.envfile) as fh:
            self.assertEqual(fh.read(), "/elsewhere/agent")

    def test_the_state_lock_is_not_held_while_ssh_connects(self):
        self.fake_ssh('echo go > "%s"\nsleep 2\n( while :; do sleep 1; done ) &\nexit 0\n' % self.marker)
        results = []
        self.addCleanup(tunnels.stop_all, self.path)
        thread = threading.Thread(target=lambda: results.append(tunnels.start(self.alias, "", os.path.join(self.bin, "ssh"), self.path, 15.0)))
        thread.start()
        self.addCleanup(thread.join)
        self.assertTrue(wait_until(lambda: os.path.exists(self.marker)))
        started = time.monotonic()
        store.modify(self.path, lambda s: store.set_pinned(s, self.alias, True))
        self.assertLess(time.monotonic() - started, 1.0)
        thread.join(20)
        self.assertEqual(results[0]["state"], "up")
        state = store.load(self.path)
        self.assertEqual(state["pinned"], [self.alias])
        self.assertIn(self.alias, state["tunnels"])

    def test_the_log_file_is_anonymous(self):
        self.up()
        self.start()
        leftovers = [n for n in os.listdir(os.path.dirname(self.path)) if not n.endswith(".lock") and n != "state.json"]
        self.assertEqual(leftovers, [])

    def test_a_tunnel_survives_the_command_that_started_it(self):
        self.up()
        self.start()
        rec = store.load(self.path)["tunnels"][self.alias]
        self.assertTrue(self.alive(rec["pid"]))
        self.assertNotEqual(os.getsid(rec["pid"]), os.getsid(0))

    def test_stop_ends_what_start_began(self):
        self.up()
        self.start()
        rec = store.load(self.path)["tunnels"][self.alias]
        self.assertTrue(tunnels.stop(self.alias, self.path)["stopped"])
        self.assertTrue(wait_until(lambda: not self.alive(rec["pid"])))
        self.assertEqual(store.load(self.path)["tunnels"], {})


if __name__ == "__main__":
    unittest.main()
