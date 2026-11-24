import os
import sys
import stat
import shutil
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import support
import hostform
import hostfile
import safefile

SSH = shutil.which("ssh")


def host(**fields):
    """A canonical host named web with the given fields."""
    value, errors = hostform.normalize({"alias": "web", **fields}, support.anything_exists)
    assert not errors, errors
    return value


def ssh_output(alias, value):
    """The text ssh -G prints for value, built from what the plugin expects."""
    expected = hostform.dash_g(alias, value)
    lines = ["%s %s" % pair for pair in expected["equal"].items()]
    lines += ["identityfile " + path for path in expected["among"].values()]
    for name, rows in expected["ordered"].items():
        lines += ["%s %s" % (name, row) for row in rows]
    return "\n".join(lines) + "\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.ssh = support.private_home(self)
        self.dfd = safefile.open_dir(self.ssh)
        self.addCleanup(os.close, self.dfd)
        self.path = os.path.join(self.ssh, hostfile.NAME)

    def write(self, data, mode=0o600, name=hostfile.NAME):
        """Create name inside the ssh directory."""
        with open(os.path.join(self.ssh, name), "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(os.path.join(self.ssh, name), mode)

    def read(self, name=hostfile.NAME):
        """The bytes of name inside the ssh directory."""
        with open(os.path.join(self.ssh, name), "rb") as fh:
            return fh.read()

    def names(self):
        """The sorted names inside the ssh directory."""
        return sorted(os.listdir(self.ssh))


class PathTests(Base):
    def test_the_paths_follow_home(self):
        self.assertEqual(hostfile.ssh_dir(), self.ssh)
        self.assertEqual(hostfile.managed_path(), self.path)


class LoadManagedTests(Base):
    def test_missing(self):
        self.assertEqual(hostfile.load_managed(self.dfd), ([], None, None, "missing", ""))

    def test_a_canonical_file_is_ok_and_keeps_its_bytes_and_status(self):
        hosts = [host(hostname="h.example.com", forwards=["L 8080 localhost:80"]), host(alias="db")]
        self.write(hostform.render(hosts))
        loaded, data, info, state, reason = hostfile.load_managed(self.dfd)
        self.assertEqual((loaded, state, reason), (hosts, "ok", ""))
        self.assertEqual(data, hostform.render(hosts).encode())
        self.assertEqual(info.st_size, len(data))

    def test_an_empty_host_list_is_ok(self):
        self.write(hostform.render([]))
        self.assertEqual(hostfile.load_managed(self.dfd)[0::3], ([], "ok"))

    def test_hand_edits_make_the_file_foreign(self):
        good = hostform.render([host()])
        edits = [good + "# note\n", good.replace("HostName", "hostname") if "HostName" in good else good + "hostname x\n", good + "\n", good.replace("Host web", "Host  web"), good[:-1], "Host web\n"]
        edits.append(good + "Host web\n")
        edits.append(good.replace("\n", "\r\n"))
        for text in edits:
            self.write(text)
            loaded, data, _, state, reason = hostfile.load_managed(self.dfd)
            self.assertEqual((loaded, state, reason), (None, "foreign", ""), text)
            self.assertEqual(data, text.encode())

    def test_non_ascii_makes_the_file_foreign(self):
        self.write(hostform.render([host()]) + "# café\n")
        self.assertEqual(hostfile.load_managed(self.dfd)[3], "foreign")

    def test_a_symlink_is_unsafe_and_never_followed(self):
        self.write(hostform.render([host()]), name="real")
        os.symlink("real", self.path)
        self.assertEqual(hostfile.load_managed(self.dfd), (None, None, None, "unsafe", "symlink"))

    def test_a_directory_and_a_fifo_are_unsafe(self):
        os.mkdir(self.path)
        self.assertEqual(hostfile.load_managed(self.dfd)[3:], ("unsafe", "not-regular"))
        os.rmdir(self.path)
        os.mkfifo(self.path)
        self.assertEqual(hostfile.load_managed(self.dfd)[3:], ("unsafe", "not-regular"))

    def test_a_group_or_world_writable_file_is_unsafe(self):
        for mode in (0o664, 0o606, 0o666):
            self.write(hostform.render([host()]), mode=mode)
            self.assertEqual(hostfile.load_managed(self.dfd)[3:], ("unsafe", "mode"), oct(mode))

    def test_a_file_over_the_limit_is_unsafe(self):
        self.write(b"#" * (hostform.MAX_BYTES + 1))
        self.assertEqual(hostfile.load_managed(self.dfd)[3:], ("unsafe", "too-large"))

    def test_a_file_at_the_limit_is_foreign_not_unsafe(self):
        self.write(b"#" * hostform.MAX_BYTES)
        self.assertEqual(hostfile.load_managed(self.dfd)[3:], ("foreign", ""))


class PeekTests(Base):
    def test_a_missing_ssh_directory_reads_as_missing_and_is_not_created(self):
        os.rmdir(self.ssh)
        self.assertEqual(hostfile.peek(), ([], None, None, "missing", ""))
        self.assertFalse(os.path.exists(self.ssh))

    def test_a_directory_others_can_write_is_unsafe(self):
        os.chmod(self.ssh, 0o777)
        self.assertEqual(hostfile.peek(), (None, None, None, "unsafe", "dir"))

    def test_a_good_directory_loads_the_file(self):
        self.write(hostform.render([host()]))
        self.assertEqual(hostfile.peek()[3], "ok")

    def test_it_never_leaves_a_descriptor_open(self):
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(5):
            hostfile.peek()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


class EditorStateTests(Base):
    def parsed(self, include="active", where=None):
        """A minimal parsed config with the given inclusion state."""
        return {"managedInclude": include, "managedWhere": where, "incomplete": False}

    def test_a_disabled_editor_is_just_a_flag(self):
        self.assertEqual(hostfile.editor_state(self.parsed(), None), {"enabled": False})

    def test_an_ok_file_lists_the_form_values_and_fingerprints(self):
        hosts = [host(hostname="h.example.com", user="admin", port="2222", forwards=["L 8080 localhost:80", "D 1080"]), host(alias="db")]
        state = hostfile.editor_state(self.parsed("active", {"file": "config", "line": 3}), (hosts, b"", None, "ok", ""))
        self.assertEqual(
            {k: v for k, v in state.items() if k != "hosts"},
            {"enabled": True, "file": "ok", "fileReason": "", "include": "active", "where": {"file": "config", "line": 3}, "incomplete": False, "path": self.path, "count": 2},
        )
        self.assertEqual(state["hosts"], [hostform.to_form(h) for h in hosts])
        self.assertEqual(set(state["hosts"][0]), {"alias", "hostname", "user", "port", "proxyJump", "identityFile", "forwards", "expect"})
        self.assertRegex(state["hosts"][0]["expect"], r"\A[0-9a-f]{16}\Z")

    def test_an_incomplete_parse_is_reported_and_blocks_every_edit(self):
        loaded = ([host()], b"", None, "ok", "")
        parsed = {**self.parsed(), "incomplete": True}
        state = hostfile.editor_state(parsed, loaded)
        self.assertTrue(state["incomplete"])
        self.assertFalse(hostfile.is_editable({"origin": "managed"}, state))
        self.assertTrue(hostfile.is_editable({"origin": "managed"}, hostfile.editor_state(self.parsed(), loaded)))

    def test_a_foreign_or_unsafe_or_missing_file_lists_nothing(self):
        for loaded in (([], None, None, "missing", ""), (None, b"x", None, "foreign", ""), (None, None, None, "unsafe", "mode")):
            state = hostfile.editor_state(self.parsed("missing"), loaded)
            self.assertEqual((state["file"], state["fileReason"], state["count"], state["hosts"]), (loaded[3], loaded[4], 0, []))
            self.assertIsNone(state["where"])

    def test_only_a_managed_host_in_a_good_active_file_is_editable(self):
        editor = {"enabled": True, "file": "ok", "include": "active", "incomplete": False}
        for origin, expected in (("managed", True), ("both", False), ("config", False)):
            self.assertEqual(hostfile.is_editable({"origin": origin}, editor), expected, origin)
        for change in ({"file": "foreign"}, {"file": "unsafe"}, {"file": "missing"}, {"include": "late"}, {"include": "scoped"}, {"include": "missing"}, {"incomplete": True}, {"enabled": False}):
            self.assertFalse(hostfile.is_editable({"origin": "managed"}, {**editor, **change}), change)
        self.assertFalse(hostfile.is_editable({"origin": "managed"}, {"enabled": False}))


class CycleTests(unittest.TestCase):
    def entries(self, **jumps):
        """Parsed hosts that jump through the given value each."""
        return [{"alias": alias, "jump": jump} for alias, jump in jumps.items()]

    def test_hops_reads_every_spelling_leniently(self):
        self.assertEqual(hostfile.hops("a,Admin@B:2200, [2001:db8::1]:22,u@[::1],ssh://c@d:9"), ["a", "b", "2001:db8::1", "::1", "d"])
        for value in ("", "none", "NONE", " , "):
            self.assertEqual(hostfile.hops(value), [], value)

    def test_a_two_host_loop_is_found(self):
        parsed = self.entries(loopa="loopb")
        self.assertTrue(hostfile.has_cycle("loopb", "", host(alias="loopb", proxyJump="loopa"), parsed))
        self.assertFalse(hostfile.has_cycle("loopb", "", host(alias="loopb", proxyJump="elsewhere"), parsed))

    def test_a_long_chain_through_hand_written_hosts_is_found(self):
        parsed = self.entries(a="b", b="c", c="u@D:22,x", d="web")
        self.assertTrue(hostfile.has_cycle("web", "", host(alias="web", proxyJump="a"), parsed))
        self.assertFalse(hostfile.has_cycle("web", "", host(alias="web", proxyJump="x"), parsed))

    def test_a_chain_that_ends_or_repeats_without_reaching_the_host_is_fine(self):
        parsed = self.entries(a="b", b="a", c="", d="none")
        self.assertFalse(hostfile.has_cycle("web", "", host(alias="web", proxyJump="a,c,d"), parsed))

    def test_the_old_and_the_new_name_use_the_new_chain_not_the_stored_one(self):
        parsed = self.entries(old="loopb", other="old")
        self.assertFalse(hostfile.has_cycle("new", "old", host(alias="new", proxyJump="loopb"), parsed))
        self.assertTrue(hostfile.has_cycle("new", "old", host(alias="new", proxyJump="other"), self.entries(old="loopb", other="new")))

    def test_the_comparison_ignores_case(self):
        self.assertTrue(hostfile.has_cycle("Web", "", host(alias="Web", proxyJump="a"), self.entries(a="WEB")))


class CheckWithSshTests(Base):
    ARGV = ["/bin/ssh", "-G", "-F", "/d/.omassh.config.x.tmp", "--", "web"]

    def check(self, result, value=None, alias="web"):
        """Run the check hook or the helper under test."""
        value = value or host(hostname="h.example.com", user="admin", port="2222", proxyJump="bastion", identityFile="~/.ssh/id_x", forwards=["L 8080 localhost:80", "R 9000", "D 1080"])
        with mock.patch("hostfile.launch.capture", return_value=result) as capture:
            return hostfile.check_with_ssh("/bin/ssh", "/d", ".omassh.config.x.tmp", alias, value), capture

    def good(self, value=None):
        """The text ssh prints for a fully specified host."""
        value = value or host(hostname="h.example.com", user="admin", port="2222", proxyJump="bastion", identityFile="~/.ssh/id_x", forwards=["L 8080 localhost:80", "R 9000", "D 1080"])
        return ssh_output("web", value).encode()

    def test_the_argv_is_exactly_the_pinned_shape(self):
        outcome, capture = self.check((0, self.good(), b""))
        self.assertEqual(outcome, ("", ""))
        capture.assert_called_once_with(self.ARGV, hostfile.CHECK_TIMEOUT, hostfile.CHECK_LIMIT)

    def test_agreement_is_silent_for_a_bare_host_too(self):
        value = host()
        self.assertEqual(self.check((0, ssh_output("web", value).encode(), b""), value)[0], ("", ""))

    def test_empty_output_is_a_failure_even_with_exit_zero(self):
        self.assertEqual(self.check((0, b"", b""))[0], ("check-failed", "ssh printed nothing"))

    def test_a_different_hostname_is_a_failure(self):
        out = self.good().replace(b"hostname h.example.com", b"hostname other.example.com")
        self.assertEqual(self.check((0, out, b""))[0], ("check-failed", "ssh reports a different hostname"))

    def test_a_missing_forward_is_a_failure(self):
        out = self.good().replace(b"localforward 8080 [localhost]:80\n", b"")
        self.assertEqual(self.check((0, out, b""))[0], ("check-failed", "ssh reports a different localforward"))

    def test_an_unexpected_jump_is_a_failure(self):
        value = host()
        out = ssh_output("web", value).encode() + b"proxyjump evil\n"
        self.assertEqual(self.check((0, out, b""), value)[0], ("check-failed", "ssh reports a different proxyjump"))

    def test_a_missing_identity_file_is_a_failure(self):
        out = b"".join(line + b"\n" for line in self.good().splitlines() if not line.startswith(b"identityfile"))
        self.assertEqual(self.check((0, out, b""))[0][0], "check-failed")

    def test_ssh_rejecting_the_file_reports_a_cleaned_short_message(self):
        noise = b"/d/x line 3: Bad port '0'.\x1b[31m\n" + b"x" * 500 + b"\n"
        code, message = self.check((255, b"", noise))[0]
        self.assertEqual(code, "ssh-rejected")
        self.assertLessEqual(len(message), hostfile.MAX_MESSAGE)
        self.assertNotIn("\x1b", message)
        self.assertTrue(message.startswith("/d/x line 3: Bad port '0'."))

    def test_even_good_looking_output_is_ignored_when_the_exit_status_is_not_zero(self):
        self.assertEqual(self.check((1, self.good(), b"boom"))[0], ("ssh-rejected", "boom"))

    def test_a_timeout_is_a_failure(self):
        self.assertEqual(self.check((None, b"", b""))[0], ("check-failed", "ssh did not answer in time"))

    def test_a_program_that_cannot_run_is_reported_as_missing(self):
        with mock.patch("hostfile.launch.capture", side_effect=FileNotFoundError(2, "No such file or directory")):
            self.assertEqual(hostfile.check_with_ssh("/nope", "/d", "x", "web", host()), ("ssh-missing", "No such file or directory"))

    def test_the_hook_raises_the_code_and_message(self):
        with mock.patch("hostfile.launch.capture", return_value=(255, b"", b"nope\n")):
            check = hostfile.checker("/bin/ssh", "/d", "web", host())
            with self.assertRaises(safefile.Refused) as ctx:
                check("x")
        self.assertEqual((ctx.exception.code, ctx.exception.detail), ("ssh-rejected", "nope"))

    def test_the_hook_is_silent_when_ssh_agrees(self):
        value = host()
        with mock.patch("hostfile.launch.capture", return_value=(0, ssh_output("web", value).encode(), b"")):
            self.assertIsNone(hostfile.checker("/bin/ssh", "/d", "web", value)("x"))


class WriteHostsTests(Base):
    def umask_zero(self):
        """Clear the umask for the rest of the test."""
        old = os.umask(0)
        self.addCleanup(os.umask, old)

    def start(self, hosts):
        """Write hosts as the first version and return what write_hosts needs to replace it."""
        self.write(hostform.render(hosts))
        _, data, info, _, _ = hostfile.load_managed(self.dfd)
        return data, info

    def test_a_new_file_is_created_with_mode_0600_and_no_backup(self):
        self.umask_zero()
        hostfile.write_hosts(self.dfd, [host()], None, None)
        self.assertEqual(self.read(), hostform.render([host()]).encode())
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(self.names(), [hostfile.NAME])

    def test_the_backup_holds_exactly_the_old_bytes(self):
        self.umask_zero()
        data, info = self.start([host()])
        hostfile.write_hosts(self.dfd, [host(), host(alias="db")], data, info)
        self.assertEqual(self.read(hostfile.BACKUP), data)
        self.assertEqual(hostform.parse(self.read()), [host(), host(alias="db")])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.ssh, hostfile.BACKUP)).st_mode), 0o600)
        self.assertEqual(self.names(), [hostfile.NAME, hostfile.BACKUP])

    def test_the_file_is_narrowed_to_0600_even_when_it_was_wider(self):
        self.umask_zero()
        self.write(hostform.render([host()]), mode=0o644)
        _, data, info, _, _ = hostfile.load_managed(self.dfd)
        hostfile.write_hosts(self.dfd, [], data, info)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_a_symlinked_backup_is_replaced_and_its_target_is_untouched(self):
        decoy = os.path.join(self.ssh, "decoy")
        with open(decoy, "w") as fh:
            fh.write("keep me")
        os.symlink(decoy, os.path.join(self.ssh, hostfile.BACKUP))
        data, info = self.start([host()])
        hostfile.write_hosts(self.dfd, [], data, info)
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "keep me")
        self.assertFalse(os.path.islink(os.path.join(self.ssh, hostfile.BACKUP)))
        self.assertEqual(self.read(hostfile.BACKUP), data)

    def test_a_directory_at_the_backup_name_aborts_the_save(self):
        os.mkdir(os.path.join(self.ssh, hostfile.BACKUP))
        data, info = self.start([host()])
        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [], data, info)
        self.assertEqual(ctx.exception.code, "io")
        self.assertEqual(self.read(), data)
        self.assertEqual(self.names(), [hostfile.NAME, hostfile.BACKUP])

    def test_a_refusing_check_leaves_the_file_unchanged_and_no_leftovers(self):
        data, info = self.start([host()])

        def check(name):
            """Run the check hook or the helper under test."""
            self.assertEqual(self.read(name), hostform.render([]).encode())
            raise safefile.Refused("ssh-rejected", "no")

        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [], data, info, check)
        self.assertEqual(ctx.exception.code, "ssh-rejected")
        self.assertEqual((self.read(), self.names()), (data, [hostfile.NAME]))

    def test_a_change_between_the_read_and_the_rename_is_a_conflict(self):
        data, info = self.start([host()])

        def tamper(name):
            """Change the file after it was read."""
            with open(self.path, "ab") as fh:
                fh.write(b"# edited elsewhere\n")

        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [], data, info, tamper)
        self.assertEqual(ctx.exception.code, "conflict")
        self.assertEqual(self.read(), data + b"# edited elsewhere\n")
        self.assertEqual(self.names(), [hostfile.NAME])

    def test_a_refused_save_leaves_the_previous_backup_alone(self):
        data, info = self.start([host()])
        self.write(b"older backup\n", name=hostfile.BACKUP)

        def tamper(name):
            """Change the file after it was read."""
            with open(self.path, "ab") as fh:
                fh.write(b"# edited elsewhere\n")

        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [], data, info, tamper)
        self.assertEqual(ctx.exception.code, "conflict")
        self.assertEqual(self.read(hostfile.BACKUP), b"older backup\n")

    def test_a_file_created_since_the_read_is_a_conflict(self):
        def appear(name):
            """Create the file after it was found missing."""
            self.write(hostform.render([host()]))

        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [], None, None, appear)
        self.assertEqual(ctx.exception.code, "conflict")

    def test_more_hosts_than_the_limit_are_refused(self):
        hosts = [host(alias="h%d" % i) for i in range(hostform.MAX_HOSTS + 1)]
        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, hosts, None, None)
        self.assertEqual(ctx.exception.code, "limit")
        self.assertEqual(self.names(), [])

    def test_a_file_over_the_size_limit_is_refused(self):
        jumps = ",".join("j%d%s" % (n, "a" * 110) for n in range(8))
        hosts = []
        for index in range(hostform.MAX_HOSTS):
            rows = ["L %d %s.example:80" % (port, "b" * 200) for port in range(1, 17)]
            hosts.append(host(alias="h%d" % index, hostname="x" * 200 + ".example.com", proxyJump=jumps, forwards=rows))
        self.assertGreater(len(hostform.render(hosts)), hostform.MAX_BYTES)
        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, hosts, None, None)
        self.assertEqual(ctx.exception.code, "limit")
        self.assertEqual(self.names(), [])

    def test_hosts_that_do_not_read_back_the_same_are_refused(self):
        unsorted = host(forwards=["L 1 a:2", "R 3"])
        unsorted["forwards"] = ["R 3", "L 1 a:2"]
        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [unsorted], None, None)
        self.assertEqual(ctx.exception.code, "check-failed")
        self.assertEqual(self.names(), [])

    def test_a_symlink_at_the_file_name_is_replaced_not_followed(self):
        decoy = os.path.join(self.ssh, "decoy")
        with open(decoy, "w") as fh:
            fh.write("keep me")
        os.symlink(decoy, self.path)
        hostfile.write_hosts(self.dfd, [host()], None, os.stat(self.path, follow_symlinks=False))
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "keep me")
        self.assertFalse(os.path.islink(self.path))
        self.assertEqual(hostform.parse(self.read()), [host()])


@unittest.skipUnless(SSH and shutil.which("false"), "ssh is not installed")
class RealSshTests(Base):
    def setUp(self):
        super().setUp()
        self.directory = os.path.realpath(self.ssh)
        with open(os.path.join(self.ssh, "id_x"), "w") as fh:
            fh.write("key")

    def write_with_ssh(self, written, checked, old=None, before=None):
        """Write a host with the real ssh checking it against the intended one."""
        hostfile.write_hosts(self.dfd, [written], old, before, hostfile.checker(SSH, self.directory, "web", checked))

    def test_a_host_that_ssh_reads_as_intended_is_written(self):
        value = host(hostname="Web.Example.com", user="admin", port="2222", proxyJump="bastion,u@[2001:db8::1]:22", identityFile="~/.ssh/id_x", forwards=["L 8080 localhost:80", "R 9000", "D 1080", "L [::1]:8081 [::1]:80"])
        self.write_with_ssh(value, value)
        self.assertEqual(hostform.parse(self.read()), [value])
        self.assertEqual(self.names(), ["id_x", hostfile.NAME])

    def test_a_mismatch_between_what_is_written_and_what_was_intended_is_refused(self):
        written, intended = host(hostname="a.example.com"), host(hostname="b.example.com")
        with self.assertRaises(safefile.Refused) as ctx:
            self.write_with_ssh(written, intended)
        self.assertEqual((ctx.exception.code, ctx.exception.detail), ("check-failed", "ssh reports a different hostname"))
        self.assertEqual(self.names(), ["id_x"])

    def test_a_program_that_exits_with_an_error_is_a_rejection_and_nothing_is_written(self):
        value = host()
        with self.assertRaises(safefile.Refused) as ctx:
            hostfile.write_hosts(self.dfd, [value], None, None, hostfile.checker(shutil.which("false"), self.directory, "web", value))
        self.assertEqual(ctx.exception.code, "ssh-rejected")
        self.assertEqual(self.names(), ["id_x"])

    def test_the_candidate_is_never_read_through_the_main_config(self):
        with open(os.path.join(self.ssh, "config"), "w") as fh:
            fh.write("Match exec \"touch %s\"\n" % os.path.join(self.ssh, "pwned"))
        value = host()
        self.write_with_ssh(value, value)
        self.assertNotIn("pwned", self.names())


if __name__ == "__main__":
    unittest.main()
