import os
import sys
import json
import hashlib
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import commands


class CommandsCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "commands.json")

    def write(self, doc, mode=0o644):
        """Write the commands file as JSON (or raw text or bytes) with the given permissions."""
        with open(self.path, "wb") as fh:
            fh.write(doc if isinstance(doc, bytes) else (doc if isinstance(doc, str) else json.dumps(doc)).encode("utf-8"))
        os.chmod(self.path, mode)

    def load(self, entries, **kwargs):
        """Write entries as the commands list and load the file."""
        self.write({"commands": entries}, **kwargs)
        return commands.load(self.path)


class PathTests(unittest.TestCase):
    def test_absolute_xdg_config_home_is_used(self):
        self.assertEqual(commands.commands_path({"XDG_CONFIG_HOME": "/srv/cfg"}), "/srv/cfg/omassh/commands.json")

    def test_unset_empty_or_relative_xdg_config_home_falls_back_to_the_home_config(self):
        expected = os.path.join(os.path.expanduser("~"), ".config", "omassh", "commands.json")
        for env in ({}, {"XDG_CONFIG_HOME": ""}, {"XDG_CONFIG_HOME": "relative/dir"}):
            self.assertEqual(commands.commands_path(env), expected, env)


class IdTests(unittest.TestCase):
    def test_id_is_sixteen_hex_digits_of_the_name_and_command(self):
        cid = commands.command_id("Disk usage", "df -h")
        self.assertRegex(cid, r"^[0-9a-f]{16}$")
        self.assertEqual(cid, commands.command_id("Disk usage", "df -h"))
        self.assertNotEqual(cid, commands.command_id("Disk usage", "df -H"))
        self.assertNotEqual(cid, commands.command_id("Disk usagf", "df -h"))
        self.assertNotEqual(commands.command_id("a", "bc"), commands.command_id("ab", "c"))

    def test_id_is_the_documented_hash(self):
        self.assertEqual(commands.command_id("Disk usage", "df -h"), hashlib.sha256(b"Disk usage\x00df -h").hexdigest()[:16])


class FileRuleTests(CommandsCase):
    ENTRY = {"name": "Disk usage", "command": "df -h"}

    def test_a_missing_file_means_no_commands_and_no_error(self):
        self.assertEqual(commands.load(self.path), {"commands": [], "error": "", "skipped": 0})

    def test_a_missing_directory_means_no_commands_and_no_error(self):
        self.assertEqual(commands.load(os.path.join(self.path, "x")), {"commands": [], "error": "", "skipped": 0})

    def test_a_private_or_group_readable_file_is_accepted(self):
        for mode in (0o600, 0o640, 0o644, 0o400):
            self.assertEqual(self.load([self.ENTRY], mode=mode)["error"], "", oct(mode))
            self.assertEqual(len(commands.load(self.path)["commands"]), 1, oct(mode))

    def test_a_group_or_world_writable_file_is_insecure_and_yields_nothing(self):
        for mode in (0o664, 0o666, 0o620, 0o602, 0o777):
            loaded = self.load([self.ENTRY], mode=mode)
            self.assertEqual((loaded["error"], loaded["commands"]), ("insecure", []), oct(mode))

    def test_a_file_owned_by_someone_else_is_insecure(self):
        self.write({"commands": [self.ENTRY]})
        real = os.getuid
        commands.os.getuid = lambda: real() + 1
        self.addCleanup(setattr, commands.os, "getuid", real)
        self.assertEqual(commands.load(self.path)["error"], "insecure")

    def test_a_directory_fifo_or_device_is_not_regular(self):
        os.mkdir(self.path)
        self.assertEqual(commands.load(self.path)["error"], "not-regular")
        os.rmdir(self.path)
        os.mkfifo(self.path)
        self.assertEqual(commands.load(self.path)["error"], "not-regular")
        os.unlink(self.path)
        self.assertEqual(commands.load("/dev/null")["error"], "not-regular")

    def test_a_fifo_never_blocks_the_reader(self):
        os.mkfifo(self.path)
        self.assertEqual(commands.load(self.path)["commands"], [])

    def test_an_oversize_file_is_too_large(self):
        self.write(b" " * (commands.MAX_BYTES + 1))
        self.assertEqual(commands.load(self.path)["error"], "too-large")
        self.write(json.dumps({"commands": [self.ENTRY]}).encode() + b" " * commands.MAX_BYTES)
        self.assertEqual(commands.load(self.path)["error"], "too-large")

    def test_a_file_of_exactly_the_limit_is_read(self):
        body = json.dumps({"commands": [self.ENTRY]}).encode()
        self.write(body + b" " * (commands.MAX_BYTES - len(body)))
        loaded = commands.load(self.path)
        self.assertEqual((loaded["error"], len(loaded["commands"])), ("", 1))

    def test_more_than_fifty_commands_is_too_large(self):
        many = [{"name": "n%d" % i, "command": "echo %d" % i} for i in range(commands.MAX_COMMANDS + 1)]
        loaded = self.load(many)
        self.assertEqual((loaded["error"], loaded["commands"]), ("too-large", []))
        self.assertEqual(len(self.load(many[:-1])["commands"]), commands.MAX_COMMANDS)

    def test_malformed_documents_are_invalid(self):
        for doc in (b"", b"{", b"\xff\xfe", b"[]", b"null", b'"x"', b'{"commands": 3}', b'{"commands": {}}', b'{"other": []}', b"[" * 30000):
            self.write(doc)
            self.assertEqual(commands.load(self.path)["error"], "invalid", doc[:20])

    def test_deeply_nested_json_is_invalid_not_a_crash(self):
        self.write(b'{"commands":[' + b"[" * 20000 + b"]" * 20000 + b"]}")
        self.assertEqual(commands.load(self.path)["commands"], [])
        self.write(b"[" * 30000)
        self.assertEqual(commands.load(self.path)["error"], "invalid")


class EnsureTests(CommandsCase):
    def test_creates_the_directory_and_an_empty_file_that_loads(self):
        self.path = os.path.join(self.tmp.name, "omassh", "commands.json")
        self.assertEqual(commands.ensure(self.path), "")
        self.assertEqual((os.stat(os.path.dirname(self.path)).st_mode & 0o777, os.stat(self.path).st_mode & 0o777), (0o700, 0o600))
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b'{"commands": []}\n')
        self.assertEqual(commands.load(self.path), {"commands": [], "error": "", "skipped": 0})

    def test_an_existing_regular_file_is_left_alone(self):
        self.write("not json", mode=0o644)
        before = os.stat(self.path)
        self.assertEqual(commands.ensure(self.path), "")
        after = os.stat(self.path)
        self.assertEqual((after.st_mtime_ns, after.st_mode, after.st_ino), (before.st_mtime_ns, before.st_mode, before.st_ino))
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "not json")

    def test_a_directory_fifo_or_symlink_is_refused(self):
        os.mkdir(self.path)
        self.assertEqual(commands.ensure(self.path), "not-regular")
        os.rmdir(self.path)
        os.mkfifo(self.path)
        self.assertEqual(commands.ensure(self.path), "not-regular")
        os.unlink(self.path)
        os.symlink(os.path.join(self.tmp.name, "elsewhere"), self.path)
        self.assertEqual(commands.ensure(self.path), "not-regular")
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "elsewhere")))

    def test_a_symlink_to_a_regular_file_of_ours_is_accepted_and_left_alone(self):
        real = os.path.join(self.tmp.name, "dotfiles-commands.json")
        with open(real, "w") as fh:
            fh.write("keep")
        os.symlink(real, self.path)
        self.assertEqual(commands.ensure(self.path), "")
        self.assertEqual(os.readlink(self.path), real)
        with open(real) as fh:
            self.assertEqual(fh.read(), "keep")

    def test_a_symlink_to_a_directory_a_dangling_one_or_a_foreign_file_is_refused(self):
        real = os.path.join(self.tmp.name, "real.json")
        os.mkdir(real)
        os.symlink(real, self.path)
        self.assertEqual(commands.ensure(self.path), "not-regular")
        os.unlink(self.path)
        os.rmdir(real)
        os.symlink(real, self.path)
        self.assertEqual(commands.ensure(self.path), "not-regular")
        self.assertFalse(os.path.exists(real))
        os.unlink(self.path)
        with open(real, "w") as fh:
            fh.write("x")
        os.symlink(real, self.path)
        with mock.patch.object(commands.os, "getuid", return_value=os.getuid() + 1):
            self.assertEqual(commands.ensure(self.path), "not-regular")

    def test_an_unusable_parent_is_invalid(self):
        self.write("x")
        self.assertEqual(commands.ensure(os.path.join(self.path, "sub", "commands.json")), "invalid")
        self.assertEqual(commands.ensure("/proc/omassh-none/commands.json"), "invalid")


class EntryRuleTests(CommandsCase):
    def test_a_valid_entry_has_an_id_and_no_host_restriction(self):
        loaded = self.load([{"name": "Disk usage", "command": "df -h"}])
        self.assertEqual(loaded["commands"], [{"id": commands.command_id("Disk usage", "df -h"), "name": "Disk usage", "command": "df -h", "hosts": None}])
        self.assertEqual((loaded["error"], loaded["skipped"]), ("", 0))

    def test_name_and_command_lengths(self):
        ok = [{"name": "n" * 60, "command": "c" * 1000}, {"name": "n", "command": "c"}]
        bad = [{"name": "n" * 61, "command": "c"}, {"name": "n", "command": "c" * 1001}, {"name": "", "command": "c"}, {"name": "n", "command": ""}]
        self.assertEqual(len(self.load(ok)["commands"]), 2)
        loaded = self.load(bad)
        self.assertEqual((loaded["commands"], loaded["skipped"]), ([], 4))

    def test_blank_names_and_commands_are_skipped(self):
        self.assertEqual(self.load([{"name": "  ", "command": "ls"}, {"name": "n", "command": " 　 "}])["commands"], [])

    def test_wrong_types_are_skipped(self):
        entries = [None, 5, "ls", [], {"name": 1, "command": "ls"}, {"name": "n", "command": ["ls"]}, {"name": "n"}, {"command": "ls"}, {"name": "n", "command": "ls", "hosts": "web"}]
        loaded = self.load(entries)
        self.assertEqual((loaded["commands"], loaded["skipped"]), ([], len(entries)))

    def test_every_control_format_and_separator_character_is_refused(self):
        hostile = ["a\nb", "a\tb", "a\x1bb", "a\x00b", "a\rb", "a\x7fb", "a‮b", "a​b", "a b", "a b", "a\ud800b", "ab", "a͸b", "a\x85b"]
        for text in hostile:
            for field in ("name", "command"):
                entry = {"name": "n", "command": "c"}
                entry[field] = text
                loaded = self.load([entry])
                self.assertEqual((loaded["commands"], loaded["skipped"]), ([], 1), (field, text))

    def test_ordinary_unicode_and_punctuation_are_kept(self):
        entries = [{"name": "Café 日本", "command": "echo '$HOME' | grep \"x\" && ls; true"}]
        self.assertEqual(len(self.load(entries)["commands"]), 1)

    def test_hosts_must_be_a_short_list_of_valid_aliases(self):
        base = {"name": "n", "command": "ls"}
        good = [["web"], ["a", "b"], [], ["a.b-c_d"]]
        bad = [["-oX=y"], ["a b"], ["a@b"], ["web*"], ["web?"], [1], [None], "web", 3, {}, ["web\n"], ["a" * 129], ["a"] * 201]
        for hosts in good:
            self.assertEqual(self.load([dict(base, hosts=hosts)])["commands"][0]["hosts"], hosts, hosts)
        for hosts in bad:
            loaded = self.load([dict(base, hosts=hosts)])
            self.assertEqual((loaded["commands"], loaded["skipped"]), ([], 1), hosts)
        self.assertEqual(len(self.load([dict(base, hosts=["a"] * 200)])["commands"]), 1)

    def test_a_duplicate_id_keeps_the_first_and_counts_the_rest(self):
        loaded = self.load([{"name": "n", "command": "ls", "hosts": ["a"]}, {"name": "n", "command": "ls"}, {"name": "m", "command": "ls"}])
        self.assertEqual([c["hosts"] for c in loaded["commands"]], [["a"], None])
        self.assertEqual(loaded["skipped"], 1)

    def test_an_invalid_entry_does_not_hide_the_others(self):
        loaded = self.load([{"name": "a", "command": "ls"}, {"name": "b", "command": "x\ny"}, {"name": "c", "command": "pwd"}])
        self.assertEqual(([c["name"] for c in loaded["commands"]], loaded["skipped"]), (["a", "c"], 1))


class SummaryTests(CommandsCase):
    def test_summary_never_carries_the_full_text(self):
        loaded = self.load([{"name": "Long", "command": "x" * 500, "hosts": ["web"]}])
        (item,) = commands.summary(loaded)
        self.assertEqual(set(item), {"id", "name", "preview", "hosts"})
        self.assertEqual((item["preview"], item["hosts"]), ("x" * commands.PREVIEW, ["web"]))
        self.assertNotIn("x" * (commands.PREVIEW + 1), json.dumps(item))


class FindTests(CommandsCase):
    def setUp(self):
        super().setUp()
        self.loaded = self.load([{"name": "Free", "command": "df -h"}, {"name": "Only", "command": "uptime", "hosts": ["web", "db"]}])
        self.free = commands.command_id("Free", "df -h")
        self.only = commands.command_id("Only", "uptime")

    def test_an_unrestricted_command_resolves_for_any_alias_or_none(self):
        self.assertEqual(commands.find(self.loaded, self.free, "anything"), "df -h")
        self.assertEqual(commands.find(self.loaded, self.free, None), "df -h")

    def test_a_restricted_command_resolves_only_for_its_exact_aliases(self):
        self.assertEqual(commands.find(self.loaded, self.only, "web"), "uptime")
        self.assertEqual(commands.find(self.loaded, self.only, "db"), "uptime")
        for alias in ("server", "web2", "Web", "w*", "", None):
            self.assertIsNone(commands.find(self.loaded, self.only, alias), alias)

    def test_unknown_or_malformed_ids_do_not_resolve(self):
        for cid in ("0" * 16, "", self.free.upper(), self.free[:15], self.free + "0", None, 5, "../" + self.free[:13]):
            self.assertIsNone(commands.find(self.loaded, cid, "web"), cid)

    def test_an_entry_whose_text_no_longer_matches_its_id_is_refused(self):
        self.loaded["commands"][0]["command"] = "rm -rf ~"
        self.assertIsNone(commands.find(self.loaded, self.free, "web"))
        self.loaded["commands"][0]["command"] = "df -h"
        self.loaded["commands"][0]["name"] = "Other"
        self.assertIsNone(commands.find(self.loaded, self.free, "web"))

    def test_editing_the_file_after_listing_makes_the_old_id_unresolvable(self):
        self.write({"commands": [{"name": "Free", "command": "rm -rf ~"}]})
        self.assertIsNone(commands.find(commands.load(self.path), self.free, "web"))

    def test_nothing_resolves_when_the_file_is_unusable(self):
        self.write({"commands": [{"name": "Free", "command": "df -h"}]}, mode=0o666)
        self.assertIsNone(commands.find(commands.load(self.path), self.free, "web"))


if __name__ == "__main__":
    unittest.main()
