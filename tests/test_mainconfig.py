import os
import sys
import stat
import shutil
import unittest
import subprocess
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import support
import hostform
import mainconfig

LINE = b"Include ~/.ssh/omassh.config"
HOST = {"alias": "web", "hostname": "web.example.com", "user": "", "port": "", "proxyJump": "", "identityFile": "", "forwards": []}


class InsertPointTests(unittest.TestCase):
    def test_the_matrix(self):
        cases = [
            (b"", (0, 1)),
            (b"# a\n# b\n", (8, 3)),
            (b"# a", (3, 2)),
            (b"\n\n", (2, 3)),
            (b"# c\n\nUser x\nHost a\n", (5, 3)),
            (b"Host a\n  User x\n", (0, 1)),
            (b"# c\r\nHost a\r\n", (5, 2)),
            (b"  \n\t\nHost a\n", (5, 3)),
            (b"# c\nInclude other\nHost a\n", (4, 2)),
            (b"Match all\n", (0, 1)),
            (b"# caf\xc3\xa9\nHost a\n", (8, 2)),
            (b"# \xff\xfe\nHost a\n", (5, 2)),
            (b"# a\x0bHost x\n", (11, 2)),
            (b"# a\rHost x\n", (11, 2)),
            (b"# a\x0c\x85User x\nHost a\n", (12, 2)),
            (b"\x0b\nHost a\n", (2, 2)),
            (b"   # indented comment\nUser x\n", (22, 2)),
            (b"Host a", (0, 1)),
        ]
        for data, expected in cases:
            self.assertEqual(mainconfig.insert_point(data), expected, data)

    def test_a_line_separator_other_than_newline_never_splits_a_comment(self):
        for data in (b"# note\x0bUser x\nHost a\n", b"# note\rUser x\nHost a\n", b"# note\x0c\x1c\x85User x\nHost a\n"):
            offset, line = mainconfig.insert_point(data)
            self.assertEqual((data[offset:], line), (b"Host a\n", 2), data)

    def test_the_point_is_always_a_line_start_or_the_end(self):
        data = b"# one\n\n  # two\r\nUser x\nHost a\n"
        offset, line = mainconfig.insert_point(data)
        self.assertEqual((data[:offset].count(b"\n"), data[offset:].startswith(b"User")), (3, True))
        self.assertEqual(line, 4)


class Base(unittest.TestCase):
    def setUp(self):
        self.ssh = support.private_home(self)
        self.home = os.path.dirname(self.ssh)
        self.config = os.path.join(self.ssh, "config")
        self.managed = os.path.join(self.ssh, "omassh.config")

    def write(self, data, path=None, mode=0o600):
        """Create the main config, or path, with data and mode."""
        path = path or self.config
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        os.chmod(path, mode)

    def read(self, path=None):
        """The bytes of the main config, or path."""
        with open(path or self.config, "rb") as fh:
            return fh.read()

    def apply(self, data=None, **kwargs):
        """Preview and then apply with the token the preview gave, returning both replies."""
        if data is not None:
            self.write(data, **kwargs)
        shown = mainconfig.preview()
        return shown, mainconfig.apply(shown["expect"])

    def backups(self):
        """The backup files of the main config inside the ssh directory."""
        return sorted(name for name in os.listdir(self.ssh) if name.startswith("config.omassh-"))

    def mode(self, path=None):
        """The permission bits of the main config, or path."""
        return stat.S_IMODE(os.stat(path or self.config).st_mode)

    def snapshot(self):
        """Names, bytes, modes and modification times of everything in the ssh directory."""
        out = {}
        for name in os.listdir(self.ssh):
            info = os.lstat(os.path.join(self.ssh, name))
            out[name] = (self.read(os.path.join(self.ssh, name)) if stat.S_ISREG(info.st_mode) else None, info.st_mode, info.st_mtime_ns)
        return out


class PreviewTests(Base):
    def test_a_missing_file_is_created_with_just_the_line(self):
        shown = mainconfig.preview()
        self.assertEqual(set(shown), {"include", "where", "path", "target", "create", "line", "insert", "before", "after", "expect", "refusal", "acl"})
        self.assertEqual((shown["include"], shown["where"], shown["path"], shown["target"]), ("missing", None, self.config, ""))
        self.assertEqual((shown["create"], shown["line"], shown["insert"], shown["before"], shown["after"], shown["refusal"], shown["acl"]), (True, 1, LINE.decode(), [], [], "", False))
        self.assertRegex(shown["expect"], r"\A[0-9a-f]{16}\Z")

    def test_a_missing_ssh_directory_is_reported_and_not_created(self):
        os.rmdir(self.ssh)
        shown = mainconfig.preview()
        self.assertEqual((shown["create"], shown["refusal"]), (True, ""))
        self.assertFalse(os.path.exists(self.ssh))

    def test_the_line_and_its_neighbours_are_shown(self):
        self.write(b"# my ssh config\n\nUser admin\nHost a\n  HostName h\nHost b\n")
        shown = mainconfig.preview()
        self.assertEqual((shown["line"], shown["before"], shown["create"]), (3, ["# my ssh config", ""], False))
        self.assertEqual(shown["after"], ["User admin", "Host a", "  HostName h"])

    def test_context_lines_are_cleaned_and_capped(self):
        self.write(b"# bell\x07 and bidi \xe2\x80\xae" + b"x" * 300 + b"\nHost a\n")
        before = mainconfig.preview()["before"]
        self.assertEqual(len(before), 1)
        self.assertLessEqual(len(before[0]), 120)
        self.assertNotIn("\x07", before[0])
        self.assertNotIn("‮", before[0])

    def test_the_state_comes_from_the_real_parse(self):
        cases = {
            "Include omassh.config\nHost a\n": ("active", 1),
            "User x\nInclude omassh.config\n": ("late", 2),
            "Host a\n  Include omassh.config\n": ("scoped", 2),
            "Include conf.d/*\nHost a\n": ("missing", None),
        }
        for text, (state, line) in cases.items():
            self.write(text.encode())
            shown = mainconfig.preview()
            self.assertEqual(shown["include"], state, text)
            self.assertEqual(None if shown["where"] is None else shown["where"]["line"], line, text)

    def test_a_symlinked_config_shows_its_target_and_the_expectation_covers_it(self):
        elsewhere = os.path.join(self.home, "dotfiles", "ssh")
        self.write(b"Host a\n", os.path.join(elsewhere, "config"))
        os.symlink(os.path.join(elsewhere, "config"), self.config)
        first = mainconfig.preview()
        self.assertEqual((first["path"], first["target"], first["refusal"]), (self.config, os.path.join(elsewhere, "config"), ""))
        other = os.path.join(self.home, "other", "config")
        self.write(b"Host a\n", other)
        os.unlink(self.config)
        os.symlink(other, self.config)
        second = mainconfig.preview()
        self.assertEqual(second["target"], other)
        self.assertNotEqual(first["expect"], second["expect"])

    def test_the_expectation_changes_with_the_bytes(self):
        self.write(b"Host a\n")
        first = mainconfig.preview()["expect"]
        self.write(b"Host b\n")
        self.assertNotEqual(first, mainconfig.preview()["expect"])
        self.write(b"Host a\n")
        self.assertEqual(first, mainconfig.preview()["expect"])

    def test_every_refusal_is_reported_and_the_expectation_is_withheld(self):
        def bom():
            """Start the file with a byte order mark."""
            self.write(b"\xef\xbb\xbfHost a\n")

        def big():
            """Make the file larger than the limit."""
            self.write(b"#" * ((1 << 20) + 1))

        def group():
            """Make the file group writable."""
            self.write(b"Host a\n", mode=0o664)

        def world():
            """Make the file world writable."""
            self.write(b"Host a\n", mode=0o606)

        def links():
            """Give the file a second hard link."""
            self.write(b"Host a\n")
            os.link(self.config, os.path.join(self.ssh, "hard"))

        def directory():
            """Put a directory where the file belongs."""
            os.mkdir(self.config)

        def fifo():
            """Put a FIFO where the file belongs."""
            os.mkfifo(self.config)

        def dangling():
            """Point the config at nothing."""
            os.symlink(os.path.join(self.home, "nowhere"), self.config)

        def managed_link():
            """Make the host file a symlink."""
            self.write(b"Host a\n")
            os.symlink(self.config, self.managed)

        def managed_mode():
            """Make the host file group writable."""
            self.write(b"Host a\n")
            self.write(b"x", self.managed, mode=0o664)

        def managed_foreign():
            """Put a host file there that the plugin did not write."""
            self.write(b"Host a\n")
            self.write(b"Host x\n    Bogus yes\n", self.managed)

        def target_dir():
            """Link the config into a group writable directory."""
            elsewhere = os.path.join(self.home, "loose")
            self.write(b"Host a\n", os.path.join(elsewhere, "config"))
            os.chmod(elsewhere, 0o775)
            os.symlink(os.path.join(elsewhere, "config"), self.config)

        cases = [
            (bom, "bom"),
            (big, "too-large"),
            (group, "mode"),
            (world, "mode"),
            (links, "links"),
            (directory, "not-regular"),
            (fifo, "not-regular"),
            (dangling, "not-regular"),
            (managed_link, "managed-unsafe"),
            (managed_mode, "managed-unsafe"),
            (managed_foreign, "managed-foreign"),
            (target_dir, "dir"),
        ]
        for build, refusal in cases:
            for name in os.listdir(self.ssh):
                path = os.path.join(self.ssh, name)
                if os.path.islink(path) or os.path.isfile(path) or stat.S_ISFIFO(os.lstat(path).st_mode):
                    os.unlink(path)
                else:
                    os.rmdir(path)
            build()
            shown = mainconfig.preview()
            self.assertEqual((shown["refusal"], shown["expect"]), (refusal, ""), build.__name__)
            self.assertEqual(shown["insert"], LINE.decode())

    def test_an_ssh_directory_others_can_write_is_refused(self):
        self.write(b"Host a\n")
        os.chmod(self.ssh, 0o777)
        self.assertEqual(mainconfig.preview()["refusal"], "dir")

    def test_a_foreign_host_file_blocks_the_include(self):
        self.write(b"Host a\n")
        self.write(b"# my own notes\n", self.managed)
        shown = mainconfig.preview()
        self.assertEqual((shown["refusal"], shown["expect"]), ("managed-foreign", ""))

    def test_a_missing_or_canonical_host_file_does_not_block_the_include(self):
        self.write(b"Host a\n")
        self.assertEqual(mainconfig.preview()["refusal"], "")
        self.write(hostform.render([HOST]).encode(), self.managed)
        self.assertEqual(mainconfig.preview()["refusal"], "")

    def test_preview_changes_nothing_and_leaves_no_descriptor_open(self):
        self.write(b"Host a\n")
        before = (self.snapshot(), len(os.listdir("/proc/self/fd")))
        for _ in range(5):
            mainconfig.preview()
        self.assertEqual((self.snapshot(), len(os.listdir("/proc/self/fd"))), before)


class ApplyTests(Base):
    def test_one_line_goes_before_the_first_directive_and_nothing_else_changes(self):
        old = b"# my ssh config\n\nUser admin\nHost a\n  HostName h\n"
        shown, result = self.apply(old)
        self.assertEqual(self.read(), b"# my ssh config\n\n" + LINE + b"\nUser admin\nHost a\n  HostName h\n")
        self.assertEqual((result["ok"], result["changed"], result["include"]), (True, True, "active"))
        self.assertEqual(set(result), {"ok", "changed", "backup", "include"})
        self.assertEqual(os.path.dirname(result["backup"]), self.ssh)
        self.assertRegex(os.path.basename(result["backup"]), r"\Aconfig\.omassh-\d{8}T\d{6}Z-[0-9a-f]{4}\.bak\Z")
        self.assertEqual(self.read(result["backup"]), old)
        self.assertEqual(self.mode(result["backup"]), 0o600)
        self.assertEqual(sorted(os.listdir(self.ssh)), sorted(["config", os.path.basename(result["backup"])]))

    def test_it_works_on_raw_bytes_and_never_re_encodes_the_rest(self):
        old = b"# caf\xc3\xa9 \xff\xfe broken\r\nUser admin\r\nHost a\r\n  # \x80\r\n"
        self.apply(old)
        self.assertEqual(self.read(), b"# caf\xc3\xa9 \xff\xfe broken\r\n" + LINE + b"\r\nUser admin\r\nHost a\r\n  # \x80\r\n")

    def test_a_file_starting_with_a_host_gets_the_line_first(self):
        self.apply(b"Host a\n")
        self.assertEqual(self.read(), LINE + b"\nHost a\n")

    def test_comment_only_and_empty_files_get_the_line_appended(self):
        for old, new in ((b"# a\n", b"# a\n" + LINE + b"\n"), (b"# a", b"# a\n" + LINE + b"\n"), (b"", LINE + b"\n"), (b"# a\r\n", b"# a\r\n" + LINE + b"\r\n")):
            self.setUp()
            self.apply(old)
            self.assertEqual(self.read(), new, old)

    def test_a_late_include_gets_a_fresh_line_at_the_top_and_the_old_one_stays(self):
        old = b"User globaluser\nInclude omassh.config\n"
        _, result = self.apply(old)
        self.assertEqual(self.read(), LINE + b"\n" + old)
        self.assertEqual(result["include"], "active")

    def test_a_scoped_include_gets_a_fresh_line_at_the_top(self):
        old = b"Host other\n  Include omassh.config\n"
        _, result = self.apply(old)
        self.assertEqual(self.read(), LINE + b"\n" + old)
        self.assertEqual(result["include"], "active")

    def test_a_missing_file_is_created_private_with_only_the_line_and_no_backup(self):
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        shown, result = self.apply()
        self.assertEqual(self.read(), LINE + b"\n")
        self.assertEqual((self.mode(), result["backup"], result["changed"], result["include"]), (0o600, "", True, "active"))
        self.assertEqual(os.listdir(self.ssh), ["config"])

    def test_a_missing_ssh_directory_is_created_with_mode_0700(self):
        os.rmdir(self.ssh)
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        self.apply()
        self.assertEqual((self.mode(self.ssh), self.read()), (0o700, LINE + b"\n"))

    def test_it_is_idempotent_and_touches_nothing_the_second_time(self):
        self.apply(b"User admin\nHost a\n")
        first = self.snapshot()
        again = mainconfig.apply("0123456789abcdef")
        self.assertEqual(again, {"ok": True, "changed": False, "backup": "", "include": "active"})
        self.assertEqual(self.snapshot(), first)
        self.assertEqual(len(self.backups()), 1)

    def test_an_already_active_include_is_never_rewritten(self):
        self.write(b"# mine\nInclude omassh.config\nHost a\n")
        before = self.snapshot()
        self.assertEqual(mainconfig.apply(mainconfig.preview()["expect"])["changed"], False)
        self.assertEqual(self.snapshot(), before)

    def test_the_mode_is_kept_and_never_widened(self):
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        for mode, expected in ((0o600, 0o600), (0o644, 0o644), (0o640, 0o640), (0o400, 0o400), (0o755, 0o644), (0o700, 0o600)):
            self.setUp()
            self.apply(b"Host a\n", mode=mode)
            self.assertEqual(self.mode(), expected, oct(mode))
            self.assertEqual(self.mode() & ~mode, 0, oct(mode))

    def test_a_stale_expectation_is_refused_and_changes_nothing(self):
        self.write(b"Host a\n")
        expect = mainconfig.preview()["expect"]
        self.write(b"Host a\nHost b\n")
        before = self.snapshot()
        result = mainconfig.apply(expect)
        self.assertEqual((result["ok"], result["reason"], result["insert"]), (False, "conflict", LINE.decode()))
        self.assertIn(LINE.decode(), result["message"])
        self.assertEqual(self.snapshot(), before)

    def other_group(self):
        """A group of the process other than its effective group, or None."""
        return next((g for g in os.getgroups() if g != os.getegid()), None)

    def test_the_owner_group_and_mode_of_the_main_config_survive(self):
        gid = self.other_group()
        if gid is None:
            self.skipTest("the user has no supplementary group")
        for mode in (0o640, 0o600, 0o644):
            self.write(b"Host a\n", mode=mode)
            os.chown(self.config, -1, gid)
            self.assertTrue(self.apply()[1]["ok"])
            info = os.stat(self.config)
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (os.geteuid(), gid, mode))
            os.unlink(self.config)

    def test_a_group_that_cannot_be_kept_is_refused_and_nothing_changes(self):
        gid = self.other_group()
        if gid is None:
            self.skipTest("the user has no supplementary group")
        self.write(b"Host a\n", mode=0o640)
        os.chown(self.config, -1, gid)
        expect = mainconfig.preview()["expect"]
        before = self.snapshot()
        with mock.patch("safefile.os.fchown", side_effect=PermissionError):
            result = mainconfig.apply(expect)
        self.assertEqual((result["ok"], result["reason"], result["refusal"]), (False, "unsafe", "group"))
        self.assertEqual(self.snapshot(), before)

    def test_a_group_the_user_is_not_in_is_refused_in_the_preview(self):
        if os.geteuid() == 0:
            self.skipTest("root can give a file to any group")
        self.write(b"Host a\n", mode=0o640)
        before = self.snapshot()
        with mock.patch("mainconfig.os.getegid", return_value=os.getegid() + 7), mock.patch("mainconfig.os.getgroups", return_value=[]):
            shown = mainconfig.preview()
            result = mainconfig.apply("0" * 16)
        self.assertEqual((shown["refusal"], shown["expect"]), ("group", ""))
        self.assertEqual((result["reason"], result["refusal"]), ("unsafe", "group"))
        self.assertEqual(self.snapshot(), before)

    def test_a_wrong_or_empty_expectation_is_refused(self):
        self.write(b"Host a\n")
        before = self.snapshot()
        for expect in ("", "0" * 16, "f" * 16):
            self.assertEqual(mainconfig.apply(expect)["reason"], "conflict", expect)
        self.assertEqual(self.snapshot(), before)

    def test_every_refusal_returns_the_manual_line_and_changes_nothing(self):
        cases = {
            "bom": lambda: self.write(b"\xef\xbb\xbfHost a\n"),
            "mode": lambda: self.write(b"Host a\n", mode=0o664),
            "too-large": lambda: self.write(b"#" * ((1 << 20) + 1)),
        }
        for refusal, build in cases.items():
            self.setUp()
            build()
            before = self.snapshot()
            result = mainconfig.apply(mainconfig.preview()["expect"])
            self.assertEqual((result["ok"], result["reason"], result["refusal"], result["insert"]), (False, "unsafe", refusal, LINE.decode()))
            self.assertLessEqual(len(result["message"]), 200)
            self.assertEqual(self.snapshot(), before)

    def test_a_group_writable_target_directory_is_refused(self):
        elsewhere = os.path.join(self.home, "dotfiles")
        self.write(b"Host a\n", os.path.join(elsewhere, "config"))
        os.chmod(elsewhere, 0o775)
        os.symlink(os.path.join(elsewhere, "config"), self.config)
        result = mainconfig.apply(mainconfig.preview()["expect"])
        self.assertEqual((result["reason"], result["refusal"]), ("unsafe", "dir"))
        self.assertEqual(self.read(os.path.join(elsewhere, "config")), b"Host a\n")

    def test_a_hard_linked_file_is_refused(self):
        self.write(b"Host a\n")
        os.link(self.config, os.path.join(self.home, "second"))
        result = mainconfig.apply(mainconfig.preview()["expect"])
        self.assertEqual((result["reason"], result["refusal"]), ("unsafe", "links"))
        self.assertEqual(self.read(os.path.join(self.home, "second")), b"Host a\n")

    def test_an_unsafe_host_file_is_refused(self):
        self.write(b"Host a\n")
        self.write(hostform.render([HOST]).encode(), self.managed, mode=0o666)
        result = mainconfig.apply(mainconfig.preview()["expect"])
        self.assertEqual((result["reason"], result["refusal"]), ("unsafe", "managed-unsafe"))
        self.assertEqual(self.read(), b"Host a\n")

    def test_a_symlinked_config_is_followed_the_link_survives_and_the_backup_stays_in_the_ssh_directory(self):
        elsewhere = os.path.join(self.home, "dotfiles", "ssh")
        target = os.path.join(elsewhere, "config")
        self.write(b"# stow\nHost a\n", target, mode=0o644)
        os.symlink(os.path.relpath(target, self.ssh), self.config)
        shown, result = self.apply()
        self.assertTrue(os.path.islink(self.config))
        self.assertEqual(os.readlink(self.config), os.path.relpath(target, self.ssh))
        self.assertEqual(self.read(target), b"# stow\n" + LINE + b"\nHost a\n")
        self.assertEqual(self.mode(target), 0o644)
        self.assertEqual(os.listdir(elsewhere), ["config"])
        self.assertEqual(self.read(result["backup"]), b"# stow\nHost a\n")
        self.assertEqual(os.path.dirname(result["backup"]), self.ssh)
        self.assertEqual(shown["target"], target)

    def test_a_link_re_pointed_after_the_preview_is_a_conflict(self):
        first = os.path.join(self.home, "one", "config")
        second = os.path.join(self.home, "two", "config")
        self.write(b"Host a\n", first)
        self.write(b"Host a\n", second)
        os.symlink(first, self.config)
        expect = mainconfig.preview()["expect"]
        os.unlink(self.config)
        os.symlink(second, self.config)
        self.assertEqual(mainconfig.apply(expect)["reason"], "conflict")
        self.assertEqual((self.read(first), self.read(second)), (b"Host a\n", b"Host a\n"))

    def test_a_comment_with_another_line_separator_is_one_comment_as_ssh_reads_it(self):
        for old in (b"# note\x0bUser x\nHost a\n", b"# note\rUser x\nHost a\n", b"# n\xc2\x85User x\nHost a\n", b"# n\xe2\x80\xa8User x\nHost a\n"):
            self.write(old)
            result = mainconfig.apply(mainconfig.preview()["expect"])
            self.assertEqual((result["ok"], result["changed"], result["include"]), (True, True, "active"), old)
            head, _, tail = old.partition(b"\nHost")
            self.assertEqual(self.read(), head + b"\n" + LINE + b"\nHost" + tail, old)

    def test_a_candidate_the_parser_does_not_accept_is_refused_and_nothing_changes(self):
        self.write(b"User x\nHost a\n")
        before = self.snapshot()
        with mock.patch.object(mainconfig, "insert_point", return_value=(len(b"User x\nHost a\n"), 3)):
            result = mainconfig.apply(mainconfig.preview()["expect"])
        self.assertEqual((result["ok"], result["reason"]), (False, "check-failed"))
        self.assertEqual(self.snapshot(), before)

    def test_a_change_between_the_preview_and_the_rename_is_a_conflict(self):
        self.write(b"Host a\n")
        expect = mainconfig.preview()["expect"]

        def tamper(directory):
            """A hook factory whose check edits the file."""
            def check(name):
                """Edit the file when called."""
                with open(self.config, "ab") as fh:
                    fh.write(b"# edited\n")

            return check

        with mock.patch.object(mainconfig, "_candidate_check", tamper):
            result = mainconfig.apply(expect)
        self.assertEqual((result["ok"], result["reason"]), (False, "conflict"))
        self.assertEqual(self.read(), b"Host a\n# edited\n")
        self.assertEqual([n for n in os.listdir(self.ssh) if n.startswith(".")], [])
        self.assertEqual(self.backups(), [])

    def test_a_host_file_edited_between_the_preview_and_the_rename_is_refused(self):
        self.write(b"Host a\n")
        expect = mainconfig.preview()["expect"]
        before = self.snapshot()
        with mock.patch.object(mainconfig, "_ssh_refusal", side_effect=["", "managed-foreign"]):
            result = mainconfig.apply(expect)
        self.assertEqual((result["ok"], result["reason"]), (False, "unsafe"))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.backups(), [])

    def test_a_host_file_edited_by_hand_after_the_preview_is_refused_by_apply(self):
        self.write(b"Host a\n")
        expect = mainconfig.preview()["expect"]
        self.write(b"Host x\n    Bogus yes\n", self.managed)
        before = self.snapshot()
        result = mainconfig.apply(expect)
        self.assertEqual((result["ok"], result["reason"], result["refusal"]), (False, "unsafe", "managed-foreign"))
        self.assertIn("omassh.config", result["message"])
        self.assertEqual(self.snapshot(), before)

    def test_the_backup_is_exclusive_and_never_follows_a_symlink(self):
        self.write(b"Host a\n")
        decoy = os.path.join(self.home, "decoy")
        with open(decoy, "w") as fh:
            fh.write("keep me")
        stamp = "20260101T000000Z"
        os.symlink(decoy, os.path.join(self.ssh, "config.omassh-%s-abcd.bak" % stamp))
        before = self.read()
        with mock.patch("mainconfig.time.strftime", return_value=stamp), mock.patch("mainconfig.secrets.token_hex", return_value="abcd"):
            result = mainconfig.apply(mainconfig.preview()["expect"])
        self.assertEqual((result["ok"], result["reason"]), (False, "io"))
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "keep me")
        self.assertEqual(self.read(), before)

    def test_no_descriptor_is_left_open_by_any_outcome(self):
        before = len(os.listdir("/proc/self/fd"))
        self.apply(b"Host a\n")
        mainconfig.apply("0" * 16)
        self.write(b"Host a\n", mode=0o664)
        mainconfig.apply("0" * 16)
        os.unlink(self.config)
        self.apply()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


@unittest.skipUnless(hasattr(os, "getxattr") and hasattr(os, "removexattr") and shutil.which("setfacl"), "requires os xattr support and setfacl")
class AclApplyTests(Base):
    def setfacl(self, *args):
        try:
            subprocess.run(["setfacl", *args], check=True, capture_output=True)
        except (subprocess.CalledProcessError, OSError) as exc:
            self.skipTest("filesystem does not support POSIX ACLs: %s" % exc)

    def test_symlink_target_acl_is_reported_in_preview_and_preserved_on_apply(self):
        dotfiles = os.path.join(self.home, "dotfiles", "ssh")
        target = os.path.join(dotfiles, "config")
        self.write(b"Host a\n", target, mode=0o600)
        os.chmod(dotfiles, 0o750)
        self.setfacl("-m", "u:bin:r,g::---", target)
        os.symlink(target, self.config)

        shown = mainconfig.preview()
        self.assertTrue(shown["acl"])
        expected_acl = os.getxattr(target, "system.posix_acl_access")

        result = mainconfig.apply(shown["expect"])
        self.assertEqual((result["ok"], result["changed"], result["include"]), (True, True, "active"))
        self.assertEqual(os.getxattr(target, "system.posix_acl_access"), expected_acl)
        facl = subprocess.run(["getfacl", "-p", target], capture_output=True, text=True, check=True).stdout
        self.assertIn("group::---", facl)
        self.assertIn("user:bin:r--", facl)

    def test_default_directory_acl_is_not_inherited_when_target_had_no_acl(self):
        dotfiles = os.path.join(self.home, "dotfiles", "ssh")
        target = os.path.join(dotfiles, "config")
        self.write(b"Host a\n", target, mode=0o600)
        self.setfacl("-d", "-m", "u:bin:r", dotfiles)
        os.symlink(target, self.config)

        shown = mainconfig.preview()
        self.assertFalse(shown["acl"])
        result = mainconfig.apply(shown["expect"])
        self.assertEqual((result["ok"], result["changed"], result["include"]), (True, True, "active"))
        self.assertNotIn("system.posix_acl_access", os.listxattr(target))
        self.assertEqual(self.mode(target), 0o600)


if __name__ == "__main__":
    unittest.main()
