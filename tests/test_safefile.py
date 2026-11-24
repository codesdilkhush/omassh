import os
import sys
import stat
import shutil
import tempfile
import unittest
import subprocess
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import safefile


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.ssh = os.path.join(self.root, ".ssh")
        os.mkdir(self.ssh, 0o700)
        os.chmod(self.ssh, 0o700)
        self.dfd = safefile.open_dir(self.ssh)
        self.addCleanup(os.close, self.dfd)

    def path(self, name):
        """The full path of name inside the private directory."""
        return os.path.join(self.ssh, name)

    def write(self, name, data=b"old\n", mode=0o600):
        """Create name inside the private directory with data and mode."""
        with open(self.path(name), "wb") as fh:
            fh.write(data)
        os.chmod(self.path(name), mode)

    def read(self, name):
        """The bytes of name inside the private directory."""
        with open(self.path(name), "rb") as fh:
            return fh.read()

    def names(self):
        """The sorted names inside the private directory."""
        return sorted(os.listdir(self.ssh))

    def refused(self, call, *args, **kwargs):
        """The code of the Refused that call raises."""
        with self.assertRaises(safefile.Refused) as ctx:
            call(*args, **kwargs)
        return ctx.exception.code


class OpenDirTests(Base):
    def test_a_private_directory_opens(self):
        fd = safefile.open_dir(self.ssh)
        self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
        os.close(fd)

    def test_missing_is_reported_unless_create_is_set(self):
        target = os.path.join(self.root, "new")
        self.assertEqual(self.refused(safefile.open_dir, target), "missing")
        self.assertFalse(os.path.exists(target))

    def test_create_makes_a_0700_directory_even_with_umask_zero(self):
        target = os.path.join(self.root, "new")
        old = os.umask(0)
        try:
            fd = safefile.open_dir(target, True)
        finally:
            os.umask(old)
        os.close(fd)
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)

    def test_create_reuses_an_existing_directory(self):
        os.close(safefile.open_dir(self.ssh, True))
        self.assertEqual(stat.S_IMODE(os.stat(self.ssh).st_mode), 0o700)

    def test_group_or_other_writable_directories_are_refused(self):
        for mode in (0o770, 0o707, 0o777, 0o720, 0o702):
            os.chmod(self.ssh, mode)
            self.assertEqual(self.refused(safefile.open_dir, self.ssh), "dir", oct(mode))

    def test_readable_but_not_writable_by_others_is_fine(self):
        os.chmod(self.ssh, 0o755)
        os.close(safefile.open_dir(self.ssh))

    def test_a_directory_of_someone_else_is_refused(self):
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.assertEqual(self.refused(safefile.open_dir, self.ssh), "dir")

    def test_a_refused_directory_leaves_no_descriptor_open(self):
        os.chmod(self.ssh, 0o777)
        before = len(os.listdir("/proc/self/fd"))
        self.refused(safefile.open_dir, self.ssh)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_a_symlinked_directory_is_followed_and_checked(self):
        link = os.path.join(self.root, "link")
        os.symlink(self.ssh, link)
        os.close(safefile.open_dir(link))
        os.chmod(self.ssh, 0o777)
        self.assertEqual(self.refused(safefile.open_dir, link), "dir")

    def test_a_file_is_not_a_directory(self):
        self.write("plain")
        self.assertEqual(self.refused(safefile.open_dir, self.path("plain")), "dir")

    def test_a_dangling_symlink_is_not_created_through(self):
        link = os.path.join(self.root, "dangling")
        os.symlink(os.path.join(self.root, "nowhere"), link)
        self.assertIn(self.refused(safefile.open_dir, link, True), ("missing", "io", "dir"))
        self.assertFalse(os.path.exists(os.path.join(self.root, "nowhere")))

    def test_the_parent_must_exist(self):
        target = os.path.join(self.root, "a", "b")
        self.assertIn(self.refused(safefile.open_dir, target, True), ("io", "missing"))


class ReadTests(Base):
    def test_missing(self):
        self.assertEqual(safefile.read_nofollow(self.dfd, "nope", 100), (None, None))

    def test_a_regular_file(self):
        self.write("f", b"hello\n")
        data, info = safefile.read_nofollow(self.dfd, "f", 100)
        self.assertEqual(data, b"hello\n")
        self.assertEqual(info.st_size, 6)

    def test_empty_file(self):
        self.write("f", b"")
        self.assertEqual(safefile.read_nofollow(self.dfd, "f", 100)[0], b"")

    def test_a_symlink_to_a_good_file_is_refused(self):
        self.write("real", b"secret\n")
        os.symlink(self.path("real"), self.path("link"))
        self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "link", 100), "symlink")

    def test_a_dangling_symlink_is_refused(self):
        os.symlink(self.path("nowhere"), self.path("link"))
        self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "link", 100), "symlink")

    def test_a_directory_is_not_regular(self):
        os.mkdir(self.path("d"))
        self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "d", 100), "not-regular")

    def test_a_fifo_is_not_regular_and_does_not_block(self):
        os.mkfifo(self.path("fifo"), 0o600)
        self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "fifo", 100), "not-regular")

    def test_group_or_other_writable_files_are_refused(self):
        for mode in (0o664, 0o620, 0o602, 0o666, 0o660, 0o606):
            self.write("f", mode=mode)
            self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "f", 100), "mode", oct(mode))

    def test_readable_files_are_fine(self):
        for mode in (0o600, 0o644, 0o640, 0o400):
            self.write("f", mode=mode)
            self.assertEqual(safefile.read_nofollow(self.dfd, "f", 100)[0], b"old\n")
            os.chmod(self.path("f"), 0o600)

    def test_a_file_of_someone_else_is_refused(self):
        self.write("f")
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "f", 100), "owner")

    def test_the_size_limit(self):
        self.write("f", b"x" * 100)
        self.assertEqual(len(safefile.read_nofollow(self.dfd, "f", 100)[0]), 100)
        self.write("f", b"x" * 101)
        self.assertEqual(self.refused(safefile.read_nofollow, self.dfd, "f", 100), "too-large")

    def test_a_refused_read_leaves_no_descriptor_open(self):
        self.write("f", mode=0o666)
        before = len(os.listdir("/proc/self/fd"))
        self.refused(safefile.read_nofollow, self.dfd, "f", 100)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


class CreateExclusiveTests(Base):
    def test_creates_a_0600_file_even_with_umask_zero(self):
        old = os.umask(0)
        try:
            safefile.create_exclusive(self.dfd, "b", b"data")
        finally:
            os.umask(old)
        self.assertEqual((self.read("b"), stat.S_IMODE(os.stat(self.path("b")).st_mode)), (b"data", 0o600))

    def test_refuses_an_existing_name_and_leaves_it_alone(self):
        self.write("b", b"keep")
        self.assertEqual(self.refused(safefile.create_exclusive, self.dfd, "b", b"new"), "io")
        self.assertEqual(self.read("b"), b"keep")

    def test_a_symlink_is_never_followed(self):
        self.write("decoy", b"decoy")
        os.symlink(self.path("decoy"), self.path("b"))
        self.assertEqual(self.refused(safefile.create_exclusive, self.dfd, "b", b"new"), "io")
        self.assertEqual(self.read("decoy"), b"decoy")
        os.unlink(self.path("b"))
        os.symlink(self.path("nowhere"), self.path("b"))
        self.assertEqual(self.refused(safefile.create_exclusive, self.dfd, "b", b"new"), "io")
        self.assertFalse(os.path.exists(self.path("nowhere")))

    def test_a_failed_write_leaves_nothing_behind(self):
        with mock.patch("os.fsync", side_effect=OSError(5, "boom")):
            self.assertEqual(self.refused(safefile.create_exclusive, self.dfd, "b", b"x"), "io")
        self.assertEqual(self.names(), [])


class InstallTests(Base):
    def install(self, data=b"new\n", **kwargs):
        """Install data at target using the status of the file as it was just read."""
        _, before = safefile.read_nofollow(self.dfd, "target", 1000)
        safefile.install(self.dfd, "target", data, kwargs.pop("mode", 0o600), kwargs.pop("before", before), **kwargs)

    def test_creates_when_absent(self):
        old = os.umask(0)
        try:
            self.install()
        finally:
            os.umask(old)
        self.assertEqual((self.read("target"), stat.S_IMODE(os.stat(self.path("target")).st_mode)), (b"new\n", 0o600))
        self.assertEqual(self.names(), ["target"])

    def test_replaces_an_existing_file_with_the_requested_mode(self):
        self.write("target", mode=0o644)
        old = os.umask(0)
        try:
            self.install(mode=0o600)
        finally:
            os.umask(old)
        self.assertEqual((self.read("target"), stat.S_IMODE(os.stat(self.path("target")).st_mode)), (b"new\n", 0o600))
        self.assertEqual(self.names(), ["target"])

    def test_the_mode_is_never_wider_than_asked(self):
        self.write("target", mode=0o600)
        old = os.umask(0)
        try:
            self.install(mode=0o644)
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(self.path("target")).st_mode), 0o644)

    def test_the_temporary_file_is_private_random_and_hidden(self):
        seen = []

        def check(name):
            seen.append((name, stat.S_IMODE(os.stat(self.path(name)).st_mode), self.read(name)))

        old = os.umask(0)
        try:
            self.install(check=check)
            self.install(check=check)
        finally:
            os.umask(old)
        self.assertEqual(len(seen), 2)
        for name, mode, data in seen:
            self.assertRegex(name, r"\A\.target\.[0-9a-f]{16}\.tmp\Z")
            self.assertEqual((mode, data), (0o600, b"new\n"))
        self.assertNotEqual(seen[0][0], seen[1][0])

    def test_hooks_run_in_order_before_the_rename(self):
        self.write("target")
        order = []
        self.install(check=lambda name: order.append(("check", self.read("target"))), backup=lambda: order.append(("backup", self.read("target"))))
        self.assertEqual(order, [("check", b"old\n"), ("backup", b"old\n")])
        self.assertEqual(self.read("target"), b"new\n")

    def test_a_failing_check_changes_nothing_and_cleans_up(self):
        self.write("target")

        def check(name):
            raise safefile.Refused("bad")

        self.assertEqual(self.refused(self.install, check=check), "bad")
        self.assertEqual((self.read("target"), self.names()), (b"old\n", ["target"]))

    def test_a_failing_backup_changes_nothing_and_cleans_up(self):
        self.write("target")

        def backup():
            raise safefile.Refused("io")

        self.assertEqual(self.refused(self.install, backup=backup), "io")
        self.assertEqual((self.read("target"), self.names()), (b"old\n", ["target"]))

    def test_a_change_between_the_read_and_the_rename_is_a_conflict(self):
        self.write("target")

        def tamper(name):
            with open(self.path("target"), "ab") as fh:
                fh.write(b"user edit\n")

        self.assertEqual(self.refused(self.install, check=tamper), "conflict")
        self.assertEqual((self.read("target"), self.names()), (b"old\nuser edit\n", ["target"]))

    def test_the_backup_is_taken_only_after_the_identity_check_passed(self):
        self.write("target")
        ran = []

        def tamper(name):
            with open(self.path("target"), "ab") as fh:
                fh.write(b"user edit\n")

        self.assertEqual(self.refused(self.install, check=tamper, backup=lambda: ran.append("backup")), "conflict")
        self.assertEqual(ran, [])

    def test_the_backup_runs_after_the_guard_and_just_before_the_rename(self):
        self.write("target")
        seen = []
        self.install(backup=lambda: seen.append((self.read("target"), self.names())))
        self.assertEqual(seen[0][0], b"old\n")
        self.assertEqual(self.read("target"), b"new\n")

    def test_the_group_is_kept_when_asked(self):
        other = next((g for g in os.getgroups() if g != os.getegid()), None)
        if other is None:
            self.skipTest("the user has no supplementary group")
        self.write("target", mode=0o640)
        self.install(mode=0o640, gid=other)
        info = os.stat(self.path("target"))
        self.assertEqual((info.st_gid, stat.S_IMODE(info.st_mode)), (other, 0o640))

    def test_a_group_that_cannot_be_kept_is_refused_and_cleans_up(self):
        self.write("target")
        with mock.patch("safefile.os.fchown", side_effect=PermissionError):
            self.assertEqual(self.refused(self.install, gid=os.getegid() + 1), "group")
        self.assertEqual((self.read("target"), self.names()), (b"old\n", ["target"]))

    def test_an_in_place_touch_is_a_conflict(self):
        self.write("target")

        def touch(name):
            info = os.stat(self.path("target"))
            os.utime(self.path("target"), ns=(info.st_atime_ns, info.st_mtime_ns + 5_000_000_000))

        self.assertEqual(self.refused(self.install, check=touch), "conflict")
        self.assertEqual(self.read("target"), b"old\n")

    def test_a_swapped_inode_with_the_same_size_and_time_is_a_conflict(self):
        self.write("target", b"old\n")
        info = os.stat(self.path("target"))

        def swap(name):
            self.write("other", b"xyz\n")
            os.utime(self.path("other"), ns=(info.st_atime_ns, info.st_mtime_ns))
            os.replace(self.path("other"), self.path("target"))

        self.assertEqual(self.refused(self.install, check=swap), "conflict")
        self.assertEqual(self.read("target"), b"xyz\n")

    def test_a_file_that_appears_when_none_was_expected_is_a_conflict(self):
        def appear(name):
            self.write("target", b"theirs\n")

        self.assertEqual(self.refused(self.install, check=appear), "conflict")
        self.assertEqual(self.read("target"), b"theirs\n")

    def test_a_file_that_vanishes_is_a_conflict(self):
        self.write("target")

        def vanish(name):
            os.unlink(self.path("target"))

        self.assertEqual(self.refused(self.install, check=vanish), "conflict")
        self.assertEqual(self.names(), [])

    def test_a_symlink_swapped_in_is_a_conflict_and_the_decoy_is_untouched(self):
        self.write("target")
        self.write("decoy", b"decoy")

        def link(name):
            os.unlink(self.path("target"))
            os.symlink(self.path("decoy"), self.path("target"))

        self.assertEqual(self.refused(self.install, check=link), "conflict")
        self.assertEqual(self.read("decoy"), b"decoy")

    def test_a_symlink_at_the_target_is_replaced_not_followed_when_it_was_read_as_such(self):
        self.write("decoy", b"decoy")
        os.symlink(self.path("decoy"), self.path("target"))
        before = os.lstat(self.path("target"))
        safefile.install(self.dfd, "target", b"new\n", 0o600, before)
        self.assertEqual((self.read("decoy"), self.read("target")), (b"decoy", b"new\n"))
        self.assertFalse(os.path.islink(self.path("target")))

    def test_the_directory_is_synced_after_the_rename(self):
        calls = []
        real_fsync, real_replace = os.fsync, os.replace
        with mock.patch("os.fsync", side_effect=lambda fd: (calls.append(("fsync", fd)), real_fsync(fd))[1]):
            with mock.patch("os.replace", side_effect=lambda *a, **k: (calls.append(("replace", None)), real_replace(*a, **k))[1]):
                self.install()
        kinds = [k for k, fd in calls]
        self.assertEqual(kinds[-1], "fsync")
        self.assertEqual(calls[-1][1], self.dfd)
        self.assertLess(kinds.index("replace"), len(kinds) - 1)

    def test_a_failing_rename_cleans_up(self):
        self.write("target")
        with mock.patch("os.replace", side_effect=OSError(18, "boom")):
            self.assertEqual(self.refused(self.install), "io")
        self.assertEqual((self.read("target"), self.names()), (b"old\n", ["target"]))

    def test_a_failing_write_cleans_up_and_closes_the_descriptor(self):
        self.write("target")
        before = len(os.listdir("/proc/self/fd"))
        with mock.patch("os.fchmod", side_effect=OSError(1, "boom")):
            self.assertEqual(self.refused(self.install), "io")
        self.assertEqual((self.read("target"), self.names()), (b"old\n", ["target"]))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_a_failing_exclusive_create_closes_the_descriptor(self):
        before = len(os.listdir("/proc/self/fd"))
        with mock.patch("os.fchmod", side_effect=OSError(1, "boom")):
            self.assertEqual(self.refused(safefile.create_exclusive, self.dfd, "b", b"x"), "io")
        self.assertEqual((self.names(), len(os.listdir("/proc/self/fd"))), ([], before))

    def test_a_directory_at_the_target_aborts(self):
        os.mkdir(self.path("target"))
        before = os.lstat(self.path("target"))
        self.assertEqual(self.refused(safefile.install, self.dfd, "target", b"x", 0o600, before), "io")
        self.assertEqual(self.names(), ["target"])

    def test_an_unexpected_exception_still_cleans_up(self):
        def boom(name):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.install(check=boom)
        self.assertEqual(self.names(), [])


class ReplaceTests(Base):
    def test_a_symlinked_backup_is_replaced_and_the_decoy_is_untouched(self):
        self.write("decoy", b"decoy")
        os.symlink(self.path("decoy"), self.path("target.bak"))
        safefile.replace(self.dfd, "target.bak", b"old bytes", 0o600)
        self.assertEqual((self.read("decoy"), self.read("target.bak")), (b"decoy", b"old bytes"))
        self.assertFalse(os.path.islink(self.path("target.bak")))
        self.assertEqual(stat.S_IMODE(os.stat(self.path("target.bak")).st_mode), 0o600)

    def test_a_dangling_symlinked_backup_is_replaced(self):
        os.symlink(self.path("nowhere"), self.path("target.bak"))
        safefile.replace(self.dfd, "target.bak", b"b", 0o600)
        self.assertFalse(os.path.exists(self.path("nowhere")))
        self.assertEqual(self.read("target.bak"), b"b")

    def test_a_directory_in_the_way_aborts_and_cleans_up(self):
        os.mkdir(self.path("target.bak"))
        self.assertEqual(self.refused(safefile.replace, self.dfd, "target.bak", b"x", 0o600), "io")
        self.assertEqual(self.names(), ["target.bak"])

    def test_a_fifo_in_the_way_is_replaced_without_blocking(self):
        os.mkfifo(self.path("target.bak"), 0o600)
        safefile.replace(self.dfd, "target.bak", b"x", 0o600)
        self.assertTrue(stat.S_ISREG(os.lstat(self.path("target.bak")).st_mode))


class NameTests(Base):
    def calls(self, name):
        """One callable per entry point of safefile that takes a file name, all given name."""
        return [
            lambda: safefile.read_nofollow(self.dfd, name, 10),
            lambda: safefile.create_exclusive(self.dfd, name, b"x"),
            lambda: safefile.install(self.dfd, name, b"x", 0o600, None),
            lambda: safefile.replace(self.dfd, name, b"x", 0o600),
            lambda: safefile.remove(self.dfd, name),
        ]

    def test_only_plain_file_names_are_accepted(self):
        with open(os.path.join(self.root, "outside"), "wb") as fh:
            fh.write(b"x")
        os.chmod(os.path.join(self.root, "outside"), 0o600)
        before = os.stat(self.path("."))
        for name in ("../outside", "a/b", "/abs", "", ".", "..", "a\0b", ".ssh/../x"):
            for call in self.calls(name):
                with self.assertRaises(ValueError, msg=repr(name)):
                    call()
        self.assertEqual(self.names(), [])
        with open(os.path.join(self.root, "outside"), "rb") as fh:
            self.assertEqual(fh.read(), b"x")
        self.assertEqual(os.stat(self.path(".")).st_mtime_ns, before.st_mtime_ns)

    def test_dotted_and_hidden_names_are_fine(self):
        self.write(".hidden")
        self.assertEqual(safefile.read_nofollow(self.dfd, ".hidden", 10)[0], b"old\n")
        safefile.replace(self.dfd, "a.b.bak", b"x", 0o600)
        self.assertEqual(self.read("a.b.bak"), b"x")


class RemoveAndTokenTests(Base):
    def test_remove(self):
        self.write("f")
        safefile.remove(self.dfd, "f")
        safefile.remove(self.dfd, "f")
        self.assertEqual(self.names(), [])

    def test_remove_never_follows_a_link(self):
        self.write("decoy")
        os.symlink(self.path("decoy"), self.path("link"))
        safefile.remove(self.dfd, "link")
        self.assertEqual(self.names(), ["decoy"])

    def test_token(self):
        a = safefile.token(b"x", "/p/config")
        self.assertRegex(a, r"\A[0-9a-f]{16}\Z")
        self.assertEqual(a, safefile.token(b"x", "/p/config"))
        for other in (safefile.token(b"y", "/p/config"), safefile.token(b"x", "/q/config"), safefile.token(None, "/p/config"), safefile.token(b"", "/p/config")):
            self.assertNotEqual(a, other)
        self.assertNotEqual(safefile.token(None, "/p"), safefile.token(b"", "/p"))

    def test_token_separates_path_from_data(self):
        self.assertNotEqual(safefile.token(b"b", "/a"), safefile.token(b"", "/ab"))


class RefusedTests(unittest.TestCase):
    def test_carries_a_code(self):
        exc = safefile.Refused("mode", "detail")
        self.assertEqual((exc.code, exc.detail, str(exc)), ("mode", "detail", "mode"))
        self.assertEqual(safefile.Refused("x").detail, "")


class AclTests(Base):
    def test_read_and_install_preserves_acl(self):
        if not hasattr(os, "getxattr") or not shutil.which("setfacl"):
            return
        self.write("file_with_acl")
        path = self.path("file_with_acl")
        try:
            subprocess.run(["setfacl", "-m", "u:bin:r", path], check=True, capture_output=True)
        except (subprocess.CalledProcessError, OSError):
            return
        acl = safefile.read_acl(self.dfd, "file_with_acl")
        self.assertIsNotNone(acl)
        _, info = safefile.read_nofollow(self.dfd, "file_with_acl", 100)
        safefile.install(self.dfd, "file_with_acl", b"new content\n", 0o640, info, acl=acl)
        new_acl = safefile.read_acl(self.dfd, "file_with_acl")
        self.assertEqual(new_acl, acl)
        self.assertEqual(self.read("file_with_acl"), b"new content\n")


if __name__ == "__main__":
    unittest.main()
