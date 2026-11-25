import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import sshconfig
import probe


_SYSTEM_PATCH = None


def setUpModule():
    global _SYSTEM_PATCH
    _SYSTEM_PATCH = mock.patch.object(sshconfig, "SYSTEM_CONFIG_PATH", "")
    _SYSTEM_PATCH.start()


def tearDownModule():
    if _SYSTEM_PATCH is not None:
        _SYSTEM_PATCH.stop()


def parse(text, files=None):
    """Parse ``text`` as ~/.ssh/config inside a throwaway directory."""
    with tempfile.TemporaryDirectory() as ssh_dir:
        with open(os.path.join(ssh_dir, "config"), "w", encoding="utf-8") as fh:
            fh.write(text)
        for name, body in (files or {}).items():
            path = os.path.join(ssh_dir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        return sshconfig.load(ssh_dir=ssh_dir)


def aliases(result):
    return [h["alias"] for h in result["hosts"]]


class SplitArgsTests(unittest.TestCase):
    def test_plain_and_quoted(self):
        self.assertEqual(sshconfig.split_args('a "b c" d'), ["a", "b c", "d"])
        self.assertEqual(sshconfig.split_args("a 'b c'"), ["a", "b c"])

    def test_comment_only_at_word_start(self):
        self.assertEqual(sshconfig.split_args("a # trailing comment"), ["a"])
        self.assertEqual(sshconfig.split_args("a#b"), ["a#b"])
        self.assertEqual(sshconfig.split_args('"a #b"'), ["a #b"])

    def test_escapes(self):
        self.assertEqual(sshconfig.split_args(r'"a\"b"'), ['a"b'])
        self.assertEqual(sshconfig.split_args(r"a\ b"), ["a b"])

    def test_unterminated_quote_raises(self):
        with self.assertRaises(ValueError):
            sshconfig.split_args('"never closed')

    def test_empty(self):
        self.assertEqual(sshconfig.split_args("   "), [])


class SplitKeywordTests(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(sshconfig.split_keyword("Host server"), ("Host", "server"))
        self.assertEqual(sshconfig.split_keyword("  Host=server"), ("Host", "server"))
        self.assertEqual(sshconfig.split_keyword("Host = server"), ("Host", "server"))
        self.assertEqual(sshconfig.split_keyword("\tHostName\t192.0.2.1"), ("HostName", "192.0.2.1"))

    def test_blank_and_comment(self):
        self.assertIsNone(sshconfig.split_keyword(""))
        self.assertIsNone(sshconfig.split_keyword("   "))
        self.assertIsNone(sshconfig.split_keyword("# Host nope"))


class HostParsingTests(unittest.TestCase):
    def test_basic_host(self):
        r = parse("Host server\n  HostName 192.0.2.10\n  User admin\n  Port 2222\n")
        self.assertEqual(aliases(r), ["server"])
        h = r["hosts"][0]
        self.assertEqual((h["hostname"], h["user"], h["port"]), ("192.0.2.10", "admin", 2222))
        self.assertTrue(r["configFound"])
        self.assertEqual(r["errors"], [])

    def test_keywords_case_insensitive_and_equals(self):
        r = parse("host=server\n  hostname = 192.0.2.1\n  USER=me\n")
        self.assertEqual(r["hosts"][0]["hostname"], "192.0.2.1")
        self.assertEqual(r["hosts"][0]["user"], "me")

    def test_multiple_patterns_on_one_line_share_options(self):
        r = parse("Host a b\n  User shared\n")
        self.assertEqual(aliases(r), ["a", "b"])
        self.assertEqual([h["user"] for h in r["hosts"]], ["shared", "shared"])

    def test_wildcards_and_negation_are_not_hosts(self):
        r = parse("Host *\n  User x\nHost *.corp\nHost !bad ok ?\n")
        self.assertEqual(aliases(r), ["ok"])
        self.assertEqual(r["skipped"], 0)

    def test_wildcard_blocks_apply_like_ssh_does(self):
        r = parse("Host server\n  HostName h\nHost *\n  User everyone\n")
        self.assertEqual(r["hosts"][0]["user"], "everyone")

    def test_a_wildcard_block_that_comes_first_wins(self):
        r = parse("Host *\n  User everyone\nHost server\n  User me\n")
        self.assertEqual(r["hosts"][0]["user"], "everyone")

    def test_match_blocks_are_ignored_and_end_the_host_block(self):
        r = parse("Host a\n  User one\nMatch host a\n  User two\n  HostName evil\n")
        self.assertEqual(r["hosts"][0]["user"], "one")
        self.assertEqual(r["hosts"][0]["hostname"], "")
        self.assertTrue(r["hosts"][0]["noProbe"])

    def test_first_value_wins(self):
        r = parse("Host a\n  User first\n  User second\n")
        self.assertEqual(r["hosts"][0]["user"], "first")

    def test_duplicate_alias_first_block_wins(self):
        r = parse("Host a\n  User first\nHost a\n  User second\n")
        self.assertEqual(aliases(r), ["a"])
        self.assertEqual(r["hosts"][0]["user"], "first")

    def test_options_before_any_host_apply_to_every_host(self):
        r = parse("User everyone\nHost a\nHost b\n")
        self.assertEqual([h["user"] for h in r["hosts"]], ["everyone", "everyone"])

    def test_comments_and_inline_comments(self):
        r = parse("# Host hidden\nHost a # trailing\n  User me # c\n")
        self.assertEqual(aliases(r), ["a"])
        self.assertEqual(r["hosts"][0]["user"], "me")

    def test_proxy_flags(self):
        r = parse("Host j\n  ProxyJump bastion\nHost c\n  ProxyCommand ssh -W %h:%p x\nHost n\n  ProxyCommand none\n")
        by = {h["alias"]: h for h in r["hosts"]}
        self.assertEqual(by["j"]["jump"], "bastion")
        self.assertTrue(by["c"]["proxy"])
        self.assertFalse(by["n"]["proxy"])

    def test_proxycommand_text_is_never_exposed(self):
        r = parse("Host c\n  ProxyCommand touch /tmp/x; evil\n")
        self.assertNotIn("evil", repr(r))

    def test_invalid_ports(self):
        for bad in ("0", "65536", "-1", "abc", "22x", "１２", "123456"):
            r = parse("Host a\n  Port %s\n" % bad)
            self.assertIsNone(r["hosts"][0]["port"], bad)

    def test_unterminated_quote_reports_error_and_continues(self):
        r = parse('Host a\n  User "oops\nHost b\n')
        self.assertEqual(aliases(r), ["a", "b"])
        self.assertEqual(len(r["errors"]), 1)

    def test_missing_config_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            r = sshconfig.load(ssh_dir=d)
        self.assertFalse(r["configFound"])
        self.assertEqual((r["hosts"], r["errors"]), ([], []))

    def test_crlf_line_endings(self):
        r = parse("Host a\r\n  User me\r\n")
        self.assertEqual(r["hosts"][0]["user"], "me")


class AliasSafetyTests(unittest.TestCase):

    HOSTILE = [
        "-oProxyCommand=touch",
        "-J",
        "--help",
        "a@b",
        "root@evil",
        "a;b",
        "a|b",
        "a&b",
        "a`b`",
        "a$(b)",
        "a$b",
        "a/b",
        "a\\b",
        "a:b",
        "a'b",
        'a"b',
        "a b",
        ".leading-dot",
        "_leading-underscore",
        "é",
        "a‮b",
        "a" * 129,
    ]

    def test_hostile_aliases_are_rejected(self):
        for alias in self.HOSTILE:
            self.assertFalse(sshconfig.is_valid_alias(alias), alias)

    def test_reasonable_aliases_are_accepted(self):
        for alias in ("server", "web-1", "db.internal", "A_b", "x" * 128, "0day"):
            self.assertTrue(sshconfig.is_valid_alias(alias), alias)

    def test_non_strings_rejected(self):
        for value in (None, 1, b"server", ["server"], "server\n", "server\x00"):
            self.assertFalse(sshconfig.is_valid_alias(value), repr(value))

    def test_trailing_newline_is_not_accepted(self):
        self.assertFalse(sshconfig.is_valid_alias("server\n"))

    def test_hostile_host_lines_never_become_hosts(self):
        text = "".join("Host %s\n" % a for a in ("-oProxyCommand=x", "a@b", "a;b", "good"))
        r = parse(text)
        self.assertEqual(aliases(r), ["good"])
        self.assertEqual(r["skipped"], 3)


class SafePathTests(unittest.TestCase):
    def test_accepts_absolute_shell_neutral_paths(self):
        for value in ("/", "/a", "/home/u/.ssh/config", "/a+b@c:d,e=f/g-h_i.j"):
            self.assertTrue(sshconfig.is_safe_path(value), value)

    def test_rejects_everything_else(self):
        for value in ("", "rel/path", "~/x", "/a b", "/a;id", "/a$(id)", "/a`id`", "/a'b", '/a"b', "/a|b", "/a&b", "/a*", "/a?", "/a\\b", "/a\n", "/a\x00", "/\u00e9", "/a\n/b"):
            self.assertFalse(sshconfig.is_safe_path(value), repr(value))

    def test_non_strings_are_rejected(self):
        for value in (None, 5, b"/a", ["/a"]):
            self.assertFalse(sshconfig.is_safe_path(value), value)


class ForwardTests(unittest.TestCase):
    def forwards(self, text, alias="a", files=None):
        """The parsed host alias of a config text."""
        return [h for h in parse(text, files)["hosts"] if h["alias"] == alias][0]

    def kinds(self, host):
        """The forwards of a host as (kind, listen, target) tuples."""
        return [(f["kind"], f["listen"], f["target"]) for f in host["forwards"]]

    def test_every_kind_is_collected(self):
        host = self.forwards("Host a\n LocalForward 8080 localhost:80\n RemoteForward 9000 localhost:22\n RemoteForward 9001\n DynamicForward 1080\n")
        self.assertEqual(
            self.kinds(host),
            [("L", "8080", "localhost:80"), ("R", "9000", "localhost:22"), ("R", "9001", ""), ("D", "1080", "")],
        )
        self.assertEqual((host["forwardsMore"], host["forwardsUncertain"]), (0, False))

    def test_forwards_accumulate_across_blocks_in_reading_order(self):
        host = self.forwards("Host a\n LocalForward 1 h:1\nHost *\n LocalForward 2 h:2\nHost a\n LocalForward 3 h:3\n")
        self.assertEqual([f["listen"] for f in host["forwards"]], ["1", "2", "3"])

    def test_global_and_included_forwards_apply(self):
        host = self.forwards("LocalForward 1 h:1\nHost a\n Include extra\n LocalForward 3 h:3\n", files={"extra": "DynamicForward 2\n"})
        self.assertEqual([f["listen"] for f in host["forwards"]], ["1", "2", "3"])

    def test_blocks_that_do_not_apply_add_nothing(self):
        host = self.forwards("Host b\n LocalForward 1 h:1\nHost a\n LocalForward 2 h:2\n")
        self.assertEqual([f["listen"] for f in host["forwards"]], ["2"])

    def test_exact_duplicates_collapse_and_different_targets_stay(self):
        host = self.forwards("Host a\n LocalForward 8080 h:1\nHost *\n LocalForward 8080 [h]:1\n LocalForward 8080 h:2\n DynamicForward 8080\n")
        self.assertEqual(self.kinds(host), [("L", "8080", "h:1"), ("L", "8080", "h:2"), ("D", "8080", "")])

    def test_clear_all_forwardings_first_value_wins(self):
        for text, expected in (
            ("Host a\n ClearAllForwardings yes\n LocalForward 1 h:1\n", 0),
            ("Host a\n LocalForward 1 h:1\n ClearAllForwardings yes\n", 0),
            ("Host *\n ClearAllForwardings no\nHost a\n ClearAllForwardings yes\n LocalForward 1 h:1\n", 1),
            ("Host a\n ClearAllForwardings YES\n LocalForward 1 h:1\nHost *\n ClearAllForwardings no\n", 0),
            ("Host a\n ClearAllForwardings false\n LocalForward 1 h:1\n", 1),
            ("Host a\n ClearAllForwardings yes\n ClearAllForwardings no\n LocalForward 1 h:1\n", 0),
            ("Host a\n ClearAllForwardings no\n ClearAllForwardings yes\n LocalForward 1 h:1\n", 1),
        ):
            self.assertEqual(len(self.forwards(text)["forwards"]), expected, text)

    def test_a_bad_clear_all_value_is_reported_and_ignored(self):
        r = parse("Host a\n ClearAllForwardings maybe\n LocalForward 1 h:1\n")
        self.assertEqual(len(r["hosts"][0]["forwards"]), 1)
        self.assertTrue(any("ClearAllForwardings" in e["message"] for e in r["errors"]))

    def test_wrong_argument_counts_are_reported_and_skipped(self):
        text = (
            "Host a\n LocalForward 1\n LocalForward 1 h:1 x\n RemoteForward\n RemoteForward 1 h:1 x\n"
            " DynamicForward\n DynamicForward 1 x\n LocalForward 7 h:7\n"
        )
        r = parse(text)
        self.assertEqual(self.kinds(r["hosts"][0]), [("L", "7", "h:7")])
        notes = [e["message"] for e in r["errors"]]
        self.assertEqual(len(notes), 6)
        self.assertTrue(all("bad forwarding specification" in n for n in notes))
        self.assertIn("line 2: bad forwarding specification", notes)

    def test_match_with_forwards_marks_every_host_uncertain(self):
        for body in ("LocalForward 1 h:1", "DynamicForward 1", "ClearAllForwardings yes"):
            r = parse("Host a\nHost b\nMatch all\n %s\n" % body)
            self.assertTrue(all(h["forwardsUncertain"] for h in r["hosts"]), body)
            self.assertEqual([h["forwards"] for h in r["hosts"]], [[], []])

    def test_match_without_forwards_is_not_uncertain(self):
        r = parse("Host a\n LocalForward 1 h:1\nMatch host a\n User x\n")
        self.assertFalse(r["hosts"][0]["forwardsUncertain"])

    def test_forwards_in_a_match_included_block_are_uncertain(self):
        r = parse("Host a\nMatch host a\n Include extra\n", files={"extra": "Host a\n LocalForward 1 h:1\n"})
        self.assertTrue(r["hosts"][0]["forwardsUncertain"])

    def test_variables_and_tilde_are_shown_raw(self):
        host = self.forwards("Host a\n LocalForward 1 ${HOME}:1\n LocalForward 2 ~:2\n")
        self.assertEqual(self.kinds(host), [("L", "1", "${HOME}:1"), ("L", "2", "~:2")])

    def test_hostile_text_is_cleaned_and_stays_plain(self):
        host = self.forwards('Host a\n LocalForward "80\x0080" "<b>x</b>\u202e:1\x07"\n DynamicForward "<img src=x>\u200b"\n')
        self.assertEqual(self.kinds(host), [("L", "8080", "<b>x</b>:1"), ("D", "<img src=x>", "")])

    def test_tokens_are_capped(self):
        host = self.forwards("Host a\n LocalForward %s %s\n" % ("1" * 500, "h" * 500))
        self.assertEqual(len(host["forwards"][0]["listen"]), sshconfig.FORWARD_FIELD)
        self.assertEqual(len(host["forwards"][0]["target"]), sshconfig.FORWARD_FIELD)

    def test_the_list_is_capped_and_the_overflow_counted(self):
        text = "Host a\n" + "".join(" LocalForward %d h:1\n" % (1000 + i) for i in range(sshconfig.MAX_FORWARDS + 8))
        host = self.forwards(text)
        self.assertEqual(len(host["forwards"]), sshconfig.MAX_FORWARDS)
        self.assertEqual(host["forwardsMore"], 8)

    def test_the_number_of_forward_lines_is_capped(self):
        text = "Host a\n" + "".join(" LocalForward %d h:1\n" % i for i in range(sshconfig.MAX_FORWARD_LINES + 10))
        r = parse(text)
        self.assertTrue(any("forwarding lines" in e["message"] for e in r["errors"]))
        self.assertEqual(r["hosts"][0]["forwardsMore"] + len(r["hosts"][0]["forwards"]), sshconfig.MAX_FORWARD_LINES)

    def test_a_host_without_forwards_has_empty_fields(self):
        host = self.forwards("Host a\n User u\n")
        self.assertEqual((host["forwards"], host["forwardsMore"], host["forwardsUncertain"]), ([], 0, False))

    def test_forward_lines_do_not_change_the_other_fields(self):
        host = self.forwards("Host a\n HostName h\n User u\n Port 2201\n LocalForward 1 h:1\n")
        self.assertEqual((host["hostname"], host["user"], host["port"]), ("h", "u", 2201))


class CopyTargetTests(unittest.TestCase):
    def test_plain_values_are_copyable(self):
        for user, host, expected in (
            ("admin", "server.example.com", "admin@server.example.com"),
            ("admin", "192.0.2.10", "admin@192.0.2.10"),
            ("admin", "2001:db8::1", "admin@2001:db8::1"),
            ("admin", "::1", "admin@::1"),
            ("_svc.1-x", "h-1.example", "_svc.1-x@h-1.example"),
            ("admin", "", "admin@alias"),
            ("admin", "%h.example.com", "admin@alias.example.com"),
            ("admin", "%h", "admin@alias"),
        ):
            self.assertEqual(sshconfig._copy_target("alias", user, host), expected, (user, host))

    def test_anything_else_is_refused(self):
        for user, host in (
            ("", "server.example.com"),
            ("-oProxyCommand=x", "server.example.com"),
            ("-admin", "server.example.com"),
            ("a b", "server.example.com"),
            ("%r", "server.example.com"),
            ("a@b", "server.example.com"),
            ("a$(id)", "server.example.com"),
            ("a;id", "server.example.com"),
            ("u" * 65, "server.example.com"),
            ("admin", "-oProxyCommand=x"),
            ("admin", "-h.example.com"),
            ("admin", "a b"),
            ("admin", "$(id)"),
            ("admin", "`id`"),
            ("admin", "a;b"),
            ("admin", "%p.example.com"),
            ("admin", "%%h"),
            ("admin", "%h%u"),
            ("admin", "h" * 254),
            ("admin", "fe80::1%eth0"),
            ("admin", "1:2:3:4:5:6:7:8:9"),
            ("admin", ":::"),
            ("admin", "host\n"),
            ("admin", "[::1]"),
        ):
            self.assertEqual(sshconfig._copy_target("alias", user, host), "", (user, host))

    def test_load_reports_the_target(self):
        r = parse("Host a\n HostName 192.0.2.10\n User admin\nHost b\n HostName h.example.com\nHost c\n User u\n HostName %h.example.com\nHost d\n User $x\n")
        self.assertEqual({h["alias"]: h["target"] for h in r["hosts"]}, {"a": "admin@192.0.2.10", "b": "", "c": "u@c.example.com", "d": ""})

    def test_a_match_block_that_sets_the_host_or_user_blanks_every_target(self):
        for option in ("HostName elsewhere.example.com", "User other"):
            r = parse("Host a\n HostName 192.0.2.10\n User admin\nHost b\n HostName 192.0.2.11\n User admin\nMatch host a\n %s\n" % option)
            self.assertEqual([h["target"] for h in r["hosts"]], ["", ""], option)

    def test_a_match_block_that_sets_neither_keeps_the_targets(self):
        r = parse("Host a\n HostName 192.0.2.10\n User admin\nMatch host a\n Port 2222\n ForwardAgent yes\n")
        self.assertEqual(r["hosts"][0]["target"], "admin@192.0.2.10")

    def test_a_match_included_file_that_sets_the_user_blanks_the_target(self):
        r = parse("Host a\n HostName 192.0.2.10\n User admin\nMatch host a\n Include extra\n", {"extra": "User other\n"})
        self.assertEqual(r["hosts"][0]["target"], "")

    def test_target_uses_the_raw_value_not_the_cleaned_one(self):
        r = parse("Host a\n HostName h.example.com\n User \"ad\u202emin\"\n")
        self.assertEqual(r["hosts"][0]["target"], "")


class CleanTests(unittest.TestCase):
    def test_strips_control_and_bidi(self):
        self.assertEqual(sshconfig.clean("a\x00b\x1b[31mc‮d e"), "ab[31mcde")

    def test_truncates(self):
        self.assertEqual(len(sshconfig.clean("x" * 1000)), sshconfig.MAX_FIELD)

    def test_displayed_fields_are_cleaned(self):
        r = parse("Host a\n  HostName evil‮.example\n  User us\x07er\n")
        self.assertEqual(r["hosts"][0]["hostname"], "evil.example")
        self.assertEqual(r["hosts"][0]["user"], "user")

    def test_markup_stays_inert_text(self):
        r = parse('Host a\n  HostName "<img src=https://evil.invalid/x>"\n')
        self.assertEqual(r["hosts"][0]["hostname"], "<img src=https://evil.invalid/x>")


class IncludeTests(unittest.TestCase):
    def test_relative_include_resolves_against_ssh_dir(self):
        r = parse("Include extra\nHost a\n", {"extra": "Host b\n  User inc\n"})
        self.assertEqual(sorted(aliases(r)), ["a", "b"])
        self.assertEqual(r["files"], 2)

    def test_glob_include_is_sorted(self):
        r = parse("Include conf.d/*\n", {"conf.d/2": "Host two\n", "conf.d/1": "Host one\n"})
        self.assertEqual(aliases(r), ["one", "two"])

    def test_include_cycle_terminates(self):
        r = parse("Include config\nHost a\n")
        self.assertEqual(aliases(r), ["a"])
        self.assertEqual((r["errors"], r["files"]), ([], 1))
        r = parse("Include a\n", {"a": "Include b\nHost ha\n", "b": "Include a\nHost hb\n"})
        self.assertEqual(sorted(aliases(r)), ["ha", "hb"])

    def test_depth_is_limited(self):
        files = {"f%d" % i: "Include f%d\nHost h%d\n" % (i + 1, i) for i in range(1, 12)}
        r = parse("Include f1\n", files)
        self.assertLessEqual(len(r["hosts"]), sshconfig.MAX_DEPTH + 1)
        self.assertTrue(any("deep" in e["message"] for e in r["errors"]))

    def test_expansion_tokens_are_not_followed(self):
        files = {"%d/x": "Host leaked-percent\n", "$HOME/y": "Host leaked-dollar\n"}
        r = parse("Include %d/x $HOME/y\nHost a\n", files)
        self.assertEqual(aliases(r), ["a"])

    def test_missing_include_is_silent(self):
        r = parse("Include nope\nHost a\n")
        self.assertEqual((aliases(r), r["errors"]), (["a"], []))
        self.assertEqual((r["hosts"][0]["forwardsUncertain"], r["hosts"][0]["noProbe"]), (False, False))

    def test_include_inside_a_host_block_is_conditional_on_it(self):
        files = {"extra": "User from-include\n"}
        r = parse("Host a\nInclude extra\nHost b\n", files)
        users = {h["alias"]: h["user"] for h in r["hosts"]}
        self.assertEqual(users, {"a": "from-include", "b": ""})

    def test_the_parent_block_resumes_after_an_include(self):
        files = {"extra": "Host zed\n  User zeduser\n"}
        r = parse("Host a\nInclude extra\n  HostName after\n", files)
        by = {h["alias"]: h for h in r["hosts"]}
        self.assertEqual(by["a"]["hostname"], "after")
        self.assertEqual(by["zed"]["user"], "")

    def test_the_same_file_can_be_included_twice(self):
        files = {"extra": "User shared\n"}
        r = parse("Host a\nInclude extra\nHost b\nInclude extra\n", files)
        self.assertEqual([h["user"] for h in r["hosts"]], ["shared", "shared"])
        self.assertEqual(r["files"], 3)

    def test_file_count_is_limited(self):
        files = {"c/%03d" % i: "Host h%03d\n" % i for i in range(sshconfig.MAX_FILES + 10)}
        r = parse("Include c/*\n", files)
        self.assertLessEqual(r["files"], sshconfig.MAX_FILES)
        self.assertTrue(r["errors"])


class LineEndingTests(unittest.TestCase):
    def test_only_a_newline_splits_lines_and_a_trailing_carriage_return_is_dropped(self):
        for separator in ("\x85", "\u2028", "\u2029", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e"):
            r = parse("# note%sHost decoy\n# note%sUser decoy\nHost web\n HostName 192.0.2.10\n" % (separator, separator))
            self.assertEqual([(h["alias"], h["hostname"], h["user"], h["line"]) for h in r["hosts"]], [("web", "192.0.2.10", "", 3)], repr(separator))
        r = parse("Host web\r\n HostName 192.0.2.10\r\n User admin\r\r\n")
        self.assertEqual([(h["alias"], h["hostname"], h["user"]) for h in r["hosts"]], [("web", "192.0.2.10", "admin")])


class IncompleteParseTests(unittest.TestCase):
    HIDDEN = {"extra": "RemoteForward 2222 localhost:22\n"}

    def flags(self, result):
        """The uncertainty flags and target of every host, by alias."""
        return {h["alias"]: (h["forwardsUncertain"], h["noProbe"], h["target"]) for h in result["hosts"]}

    def assert_uncertain(self, result, aliases_expected):
        """Every expected host is flagged uncertain, unprobed and without a copy target."""
        self.assertEqual(sorted(aliases(result)), sorted(aliases_expected))
        for alias, (uncertain, no_probe, target) in self.flags(result).items():
            self.assertEqual((uncertain, no_probe, target), (True, True, ""), alias)

    def test_an_include_with_a_variable_or_token_flags_every_host(self):
        for pattern in ("${OMX_EXTRA}", "$OMX_EXTRA", "%d/extra", "~/%u"):
            r = parse("Host web\n HostName 192.0.2.10\n User admin\n LocalForward 8080 h:80\nInclude %s\nHost db\n" % pattern, self.HIDDEN)
            self.assert_uncertain(r, ["web", "db"])
            self.assertEqual(len(r["hosts"][0]["forwards"]), 1)

    def test_a_chain_deeper_than_the_limit_flags_every_host(self):
        files = {"f%d" % i: "Include f%d\n" % (i + 1) for i in range(1, 7)}
        files["f7"] = self.HIDDEN["extra"]
        r = parse("Host web\n LocalForward 8080 h:80\nHost db\nInclude f1\n", files)
        self.assertTrue(any("deep" in e["message"] for e in r["errors"]))
        self.assert_uncertain(r, ["web", "db"])

    def test_a_chain_within_the_limit_does_not(self):
        files = {"f%d" % i: "Include f%d\n" % (i + 1) for i in range(1, 4)}
        files["f4"] = "Host inner\n"
        r = parse("Host web\n LocalForward 8080 h:80\nInclude f1\n", files)
        self.assertEqual([self.flags(r)[a][:2] for a in aliases(r)], [(False, False), (False, False)])

    def test_too_many_files_flag_every_host(self):
        files = {"c/%03d" % i: "Host h%03d\n" % i for i in range(sshconfig.MAX_FILES + 10)}
        r = parse("Host web\nInclude c/*\n", files)
        self.assertTrue(all(f[:2] == (True, True) for f in self.flags(r).values()))

    def test_an_oversized_include_flags_every_host(self):
        r = parse("Host web\nInclude big\n", {"big": "# " + "x" * sshconfig.MAX_FILE_BYTES + "\n"})
        self.assert_uncertain(r, ["web"])

    def test_a_fifo_include_flags_every_host(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(os.path.join(d, "pipe"))
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write("Host web\nInclude pipe\n")
            r = sshconfig.load(ssh_dir=d)
        self.assert_uncertain(r, ["web"])

    def test_an_unreadable_include_flags_every_host(self):
        if os.geteuid() == 0:
            self.skipTest("root can read everything")
        with tempfile.TemporaryDirectory() as d:
            secret = os.path.join(d, "secret")
            with open(secret, "w") as fh:
                fh.write("RemoteForward 1 h:1\n")
            os.chmod(secret, 0)
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write("Host web\nInclude secret\n")
            r = sshconfig.load(ssh_dir=d)
        self.assert_uncertain(r, ["web"])

    def test_the_forward_line_cap_flags_every_host(self):
        text = "Host web\n" + "".join(" LocalForward %d h:1\n" % i for i in range(sshconfig.MAX_FORWARD_LINES + 1)) + "Host db\n"
        self.assert_uncertain(parse(text), ["web", "db"])

    def test_the_block_cap_flags_every_host(self):
        text = "".join("Host h%d\n  User u\n" % i for i in range(sshconfig.MAX_BLOCKS + 5))
        r = parse(text)
        self.assertTrue(all(f[:2] == (True, True) for f in self.flags(r).values()))

    def test_a_missing_include_and_a_cycle_do_not(self):
        r = parse("Host web\n HostName 192.0.2.10\n User admin\nInclude nope\nInclude config\n")
        self.assertEqual(self.flags(r), {"web": (False, False, "admin@192.0.2.10")})

    def test_the_host_cap_flags_every_host_and_the_whole_parse(self):
        text = "".join("Host h%d\n" % i for i in range(sshconfig.MAX_HOSTS + 25))
        r = parse(text)
        self.assertEqual(len(r["hosts"]), sshconfig.MAX_HOSTS)
        self.assertTrue(r["incomplete"])
        self.assertTrue(all(f[:2] == (True, True) for f in self.flags(r).values()))

    def test_the_parse_reports_incomplete_for_every_cause(self):
        files = {"f%d" % i: "Include f%d\n" % (i + 1) for i in range(1, 7)}
        big = {"big": "# " + "x" * sshconfig.MAX_FILE_BYTES + "\n"}
        many = {"c/%03d" % i: "Host h%03d\n" % i for i in range(sshconfig.MAX_FILES + 10)}
        causes = {
            "variable": parse("Include ${HOME}/x\nHost a\n"),
            "dollar": parse("Include $HOME/x\nHost a\n"),
            "token": parse("Include %d/x\nHost a\n"),
            "depth": parse("Include f1\nHost a\n", files),
            "files": parse("Include c/*\n", many),
            "large": parse("Include big\nHost a\n", big),
            "hosts": parse("".join("Host h%d\n" % i for i in range(sshconfig.MAX_HOSTS + 1))),
            "blocks": parse("".join("Host h%d\n  User u\n" % i for i in range(sshconfig.MAX_BLOCKS + 5))),
            "forwards": parse("Host a\n" + "".join(" LocalForward %d h:1\n" % i for i in range(sshconfig.MAX_FORWARD_LINES + 1))),
        }
        with mock.patch.object(sshconfig, "MAX_WORK", 1):
            causes["work"] = parse("".join("Host h%d\n  User u%d\n" % (i, i) for i in range(20)))
        for name, result in causes.items():
            self.assertTrue(result["incomplete"], name)

    def test_a_parse_that_read_everything_is_complete(self):
        text = "Host web\n HostName 192.0.2.10\nHost a@b\nHost -x\nInclude nope\nInclude config\nInclude extra\nHost *\n User u\n"
        r = parse(text, {"extra": "Host db\n"})
        self.assertEqual((r["incomplete"], r["skipped"]), (False, 2))
        self.assertFalse(parse("")["incomplete"])


class LimitTests(unittest.TestCase):
    def test_oversized_file_is_skipped(self):
        r = parse("Host a\n# " + "x" * sshconfig.MAX_FILE_BYTES + "\n")
        self.assertEqual(r["hosts"], [])
        self.assertTrue(any("too large" in e["message"] for e in r["errors"]))

    def test_host_count_is_capped(self):
        text = "".join("Host h%d\n" % i for i in range(sshconfig.MAX_HOSTS + 25))
        r = parse(text)
        self.assertEqual(len(r["hosts"]), sshconfig.MAX_HOSTS)
        self.assertEqual(len(r["errors"]), 1)

    def test_error_list_is_capped(self):
        r = parse('Host a\n' + '  User "x\n' * 500)
        self.assertLessEqual(len(r["errors"]), sshconfig.MAX_NOTES)

    def test_binary_garbage_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config"), "wb") as fh:
                fh.write(b"\xff\xfe\x00Host a\n\x80\x81Host b\n" + os.urandom(2000))
            r = sshconfig.load(ssh_dir=d)
        self.assertIsInstance(r["hosts"], list)

    def test_fifo_does_not_hang(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(os.path.join(d, "pipe"))
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write("Include pipe\nHost a\n")
            r = sshconfig.load(ssh_dir=d)
        self.assertEqual(aliases(r), ["a"])
        self.assertTrue(any("regular" in e["message"] for e in r["errors"]))

    def test_unreadable_include_is_reported_not_raised(self):
        if os.geteuid() == 0:
            self.skipTest("root can read everything")
        with tempfile.TemporaryDirectory() as d:
            secret = os.path.join(d, "secret")
            with open(secret, "w") as fh:
                fh.write("Host hidden\n")
            os.chmod(secret, 0)
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write("Include secret\nHost a\n")
            r = sshconfig.load(ssh_dir=d)
        self.assertEqual(aliases(r), ["a"])
        self.assertTrue(r["errors"])

    def test_block_count_is_capped(self):
        text = "".join("Host h%d\n  User u\n" % i for i in range(sshconfig.MAX_BLOCKS + 50))
        r = parse(text)
        self.assertTrue(any("blocks" in e["message"] for e in r["errors"]))

    def test_result_has_no_private_keys(self):
        r = parse("Host a\n  User u\n")
        self.assertFalse([k for k in r["hosts"][0] if k.startswith("_")])


def managed(config, files=None, managed_name="omassh.config"):
    """Parse ``config`` with the managed file at ``managed_name`` inside a throwaway ssh directory."""
    with tempfile.TemporaryDirectory() as root:
        ssh_dir = os.path.join(root, ".ssh")
        os.makedirs(ssh_dir)
        tree = {"config": config, **(files or {})}
        for name, body in tree.items():
            path = os.path.join(ssh_dir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        with mock.patch.dict(os.environ, {"HOME": root}):
            return sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, managed_name)), ssh_dir


def origins(result):
    """The origin of every host of a parse result, by alias."""
    return {h["alias"]: h["origin"] for h in result["hosts"]}


class OriginTests(unittest.TestCase):
    def test_without_a_managed_path_everything_is_from_the_config(self):
        r = parse("Host a\nInclude other\n", {"other": "Host b\n"})
        self.assertEqual(origins(r), {"a": "config", "b": "config"})
        self.assertEqual((r["managedInclude"], r["managedWhere"]), ("missing", None))

    def test_managed_config_and_both(self):
        r, _ = managed("Include omassh.config\nHost c\nHost shared\n", {"omassh.config": "Host m\nHost shared\n"})
        self.assertEqual(origins(r), {"m": "managed", "shared": "both", "c": "config"})

    def test_both_in_the_other_order(self):
        r, _ = managed("Host shared\nInclude omassh.config\n", {"omassh.config": "Host shared\nHost m\n"})
        self.assertEqual(origins(r), {"shared": "both", "m": "managed"})

    def test_a_host_that_only_appears_in_a_nested_include_of_the_managed_file(self):
        r, _ = managed("Include omassh.config\n", {"omassh.config": "Include deep\n", "deep": "Host d\n"})
        self.assertEqual(origins(r), {"d": "config"})

    def test_two_aliases_on_one_line_and_wildcards(self):
        r, _ = managed("Include omassh.config\nHost *\n", {"omassh.config": "Host a b *.x\n"})
        self.assertEqual(origins(r), {"a": "managed", "b": "managed"})

    def test_the_host_cap_does_not_hide_the_origin_of_a_known_alias(self):
        with mock.patch.object(sshconfig, "MAX_HOSTS", 2):
            r, _ = managed("Host a b\nInclude omassh.config\n", {"omassh.config": "Host c a\n"})
        self.assertEqual(origins(r), {"a": "both", "b": "config"})

    def test_a_symlink_to_the_managed_file_counts_as_managed(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            with open(os.path.join(root, "real.conf"), "w") as fh:
                fh.write("Host m\n")
            os.symlink(os.path.join(root, "real.conf"), os.path.join(ssh_dir, "omassh.config"))
            with open(os.path.join(ssh_dir, "config"), "w") as fh:
                fh.write("Include omassh.config\n")
            r = sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, "omassh.config"))
        self.assertEqual((origins(r), r["managedInclude"]), ({"m": "managed"}, "active"))


class ManagedIncludeTests(unittest.TestCase):
    def status(self, config, files=None, **kwargs):
        """The managed include state and place found for config."""
        r, _ = managed(config, files, **kwargs)
        return r["managedInclude"], r["managedWhere"]

    def test_missing_without_an_include_line(self):
        self.assertEqual(self.status("Host a\n", {"omassh.config": "Host m\n"}), ("missing", None))
        self.assertEqual(self.status(""), ("missing", None))

    def test_active_at_the_top_after_comments_and_blanks(self):
        self.assertEqual(self.status("# note\n\n  \nInclude omassh.config\nUser x\n"), ("active", {"file": "config", "line": 4}))

    def test_active_even_when_the_managed_file_does_not_exist_yet(self):
        self.assertEqual(self.status("Include omassh.config\nHost a\n"), ("active", {"file": "config", "line": 1}))

    def test_active_through_every_spelling(self):
        for line in ("Include omassh.config", "Include ./omassh.config", "Include omassh.*", "Include o?assh.config", "Include [o]massh.config", "include=omassh.config", 'Include "omassh.config"', "Include ~/.ssh/omassh.config", "Include conf.d/../omassh.config"):
            self.assertEqual(self.status(line + "\nHost a\n", {"omassh.config": "Host m\n", "conf.d/x": ""})[0], "active", line)

    def test_active_with_an_absolute_path(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            target = os.path.join(ssh_dir, "omassh.config")
            with open(os.path.join(ssh_dir, "config"), "w") as fh:
                fh.write("Include %s\n" % target)
            r = sshconfig.load(ssh_dir=ssh_dir, managed_path=target)
        self.assertEqual(r["managedInclude"], "active")

    def test_active_when_nested_in_another_global_include(self):
        status = self.status("Include inc\nHost a\n", {"inc": "# c\nInclude omassh.config\n"})
        self.assertEqual(status, ("active", {"file": "inc", "line": 2}))

    def test_late_after_a_global_option(self):
        self.assertEqual(self.status("User x\nInclude omassh.config\n"), ("late", {"file": "config", "line": 2}))

    def test_late_after_any_other_include(self):
        self.assertEqual(self.status("Include conf.d/*\nInclude omassh.config\n", {"conf.d/10": "Host a\n"})[0], "late")
        self.assertEqual(self.status("Include nothing-here\nInclude omassh.config\n")[0], "late")

    def test_late_after_an_unknown_or_broken_line(self):
        self.assertEqual(self.status("Compression yes\nInclude omassh.config\n")[0], "late")
        self.assertEqual(self.status('User "broken\nInclude omassh.config\n')[0], "late")

    def test_late_when_an_earlier_pattern_on_the_same_line_brings_a_directive(self):
        self.assertEqual(self.status("Include inc omassh.config\n", {"inc": "User x\n"})[0], "late")
        self.assertEqual(self.status("Include omassh.config inc\n", {"inc": "User x\n"})[0], "active")

    def test_late_when_an_earlier_file_of_the_same_glob_has_a_directive(self):
        files = {"conf.d/10-a": "User a\n", "conf.d/20-managed": "Host m\n"}
        self.assertEqual(self.status("Include conf.d/*\n", files, managed_name="conf.d/20-managed"), ("late", {"file": "config", "line": 1}))
        files = {"conf.d/10-managed": "Host m\n", "conf.d/20-a": "User a\n"}
        self.assertEqual(self.status("Include conf.d/*\n", files, managed_name="conf.d/10-managed")[0], "active")

    def test_late_when_the_directive_is_in_the_managed_files_own_parent_include(self):
        self.assertEqual(self.status("Include inc\n", {"inc": "Port 1\nInclude omassh.config\n"})[0], "late")

    def test_scoped_inside_a_host_or_match_block(self):
        self.assertEqual(self.status("Host a\n  Include omassh.config\n"), ("scoped", {"file": "config", "line": 2}))
        self.assertEqual(self.status("Match all\n  Include omassh.config\n"), ("scoped", {"file": "config", "line": 2}))
        self.assertEqual(self.status("Host *\n  Include omassh.config\n")[0], "scoped")

    def test_scoped_through_an_include_opened_inside_a_block(self):
        self.assertEqual(self.status("Host a\n  Include inc\n", {"inc": "Include omassh.config\n"})[0], "scoped")

    def test_the_block_of_an_included_file_does_not_leak_out(self):
        self.assertEqual(self.status("Include inc\nInclude omassh.config\n", {"inc": "Host a\n"})[0], "late")
        self.assertEqual(self.status("Include inc inc2\n", {"inc": "Host a\n", "inc2": "Include omassh.config\n"})[0], "late")

    def test_the_best_state_wins_and_the_first_of_it_is_reported(self):
        config = "Host a\n  Include omassh.config\nHost b\n"
        self.assertEqual(self.status("Include omassh.config\n" + config), ("active", {"file": "config", "line": 1}))
        self.assertEqual(self.status("User x\nInclude omassh.config\n" + config), ("late", {"file": "config", "line": 2}))
        self.assertEqual(self.status("Include omassh.config\nInclude omassh.config\n"), ("active", {"file": "config", "line": 1}))
        self.assertEqual(self.status("User x\nInclude omassh.config\nInclude omassh.config\nHost a\n  Include omassh.config\n"), ("late", {"file": "config", "line": 2}))

    def test_not_followed_includes_do_not_count(self):
        self.assertEqual(self.status("Include ${HOME}/.ssh/omassh.config\n")[0], "missing")
        self.assertEqual(self.status("Include %d/omassh.config\n")[0], "missing")

    def test_a_deeply_nested_include_is_not_followed(self):
        files = {"f%d" % i: "Include f%d\n" % (i + 1) for i in range(1, 7)}
        files["f7"] = "Include omassh.config\n"
        self.assertEqual(self.status("Include f1\n", files)[0], "missing")

    def test_another_file_with_a_similar_name_is_not_the_managed_file(self):
        self.assertEqual(self.status("Include omassh.config.bak\nInclude omassh.config2\n", {"omassh.config.bak": "Host a\n"})[0], "missing")


class SystemConfigTests(unittest.TestCase):
    def load_with_system(self, user_config, system_config, system_files=None, user_files=None, use_default_attr=False):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            with open(os.path.join(ssh_dir, "config"), "w", encoding="utf-8") as fh:
                fh.write(user_config)
            for name, body in (user_files or {}).items():
                path = os.path.join(ssh_dir, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
            sys_dir = os.path.join(root, "etc_ssh")
            os.makedirs(sys_dir)
            sys_conf = os.path.join(sys_dir, "ssh_config")
            with open(sys_conf, "w", encoding="utf-8") as fh:
                fh.write(system_config)
            for name, body in (system_files or {}).items():
                path = os.path.join(sys_dir, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
            if use_default_attr:
                with mock.patch.object(sshconfig, "SYSTEM_CONFIG_PATH", sys_conf):
                    return sshconfig.load(ssh_dir=ssh_dir)
            return sshconfig.load(ssh_dir=ssh_dir, system_path=sys_conf)

    def test_system_proxyjump_applies_to_user_host_and_blocks_probe(self):
        r = self.load_with_system(
            "Host srv.corp\n  Hostname 10.0.0.1\n",
            "Host *.corp\n  ProxyJump bastion.corp\nHost sysonly\n  Hostname 1.2.3.4\n",
            use_default_attr=True,
        )
        hosts = {h["alias"]: h for h in r["hosts"]}
        self.assertIn("srv.corp", hosts)
        self.assertNotIn("sysonly", hosts)
        self.assertEqual(hosts["srv.corp"]["jump"], "bastion.corp")
        self.assertIsNone(probe.target(hosts["srv.corp"]))

    def test_system_proxycommand_applies_and_blocks_probe(self):
        r = self.load_with_system(
            "Host srv.corp\n  Hostname 10.0.0.1\n",
            "Host *.corp\n  ProxyCommand ssh -W %h:%p gateway.corp\n",
        )
        hosts = {h["alias"]: h for h in r["hosts"]}
        self.assertTrue(hosts["srv.corp"]["proxy"])
        self.assertEqual(hosts["srv.corp"]["jump"], "")
        self.assertIsNone(probe.target(hosts["srv.corp"]))

    def test_system_match_block_with_routing_blocks_probe(self):
        r = self.load_with_system(
            "Host srv.corp\n  Hostname 10.0.0.1\nHost other\n  Hostname 10.0.0.2\n",
            "Match host *.corp\n  ProxyJump bastion.corp\n",
        )
        hosts = {h["alias"]: h for h in r["hosts"]}
        self.assertTrue(hosts["srv.corp"]["noProbe"])
        self.assertTrue(hosts["other"]["noProbe"])
        self.assertIsNone(probe.target(hosts["srv.corp"]))
        self.assertIsNone(probe.target(hosts["other"]))

    def test_system_include_resolves_relative_to_system_dir_and_blocks_probe(self):
        r = self.load_with_system(
            "Host srv.corp\n  Hostname 10.0.0.1\n",
            "Include ssh_config.d/*.conf\n",
            system_files={"ssh_config.d/10-jump.conf": "Host *.corp\n  ProxyJump jump.corp\n"},
        )
        hosts = {h["alias"]: h for h in r["hosts"]}
        self.assertEqual(hosts["srv.corp"]["jump"], "jump.corp")
        self.assertEqual(r["files"], 3)
        self.assertIsNone(probe.target(hosts["srv.corp"]))

    def test_system_files_respect_max_files_cap(self):
        sys_files = {"ssh_config.d/%03d.conf" % i: "Host h%03d\n  User u\n" % i for i in range(sshconfig.MAX_FILES + 5)}
        r = self.load_with_system(
            "Host srv.corp\n  Hostname 10.0.0.1\n",
            "Include ssh_config.d/*.conf\n",
            system_files=sys_files,
        )
        self.assertLessEqual(r["files"], sshconfig.MAX_FILES)
        self.assertTrue(r["incomplete"])
        self.assertTrue(r["errors"])
        hosts = {h["alias"]: h for h in r["hosts"]}
        self.assertTrue(hosts["srv.corp"]["noProbe"])
        self.assertIsNone(probe.target(hosts["srv.corp"]))

    def test_user_files_at_cap_mark_incomplete_when_system_config_exists(self):
        user_files = {"c/%03d" % i: "Host h%03d\n" % i for i in range(sshconfig.MAX_FILES - 1)}
        r = self.load_with_system(
            "Include c/*\n",
            "Host *\n  ProxyJump bastion.corp\n",
            user_files=user_files,
        )
        self.assertEqual(r["files"], sshconfig.MAX_FILES)
        self.assertTrue(r["incomplete"])
        self.assertTrue(r["errors"])
        self.assertTrue(r["hosts"][0]["noProbe"])

    def test_user_proxyjump_none_and_proxycommand_none_override_system(self):
        r = self.load_with_system(
            "Host direct1\n  Hostname 10.0.0.1\n  ProxyJump none\nHost direct2\n  Hostname 10.0.0.2\n  ProxyCommand none\n",
            "Host direct1\n  ProxyJump bastion.corp\nHost direct2\n  ProxyCommand ssh -W %h:%p gw\n",
        )
        hosts = {h["alias"]: h for h in r["hosts"]}
        self.assertEqual(hosts["direct1"]["jump"], "")
        self.assertFalse(hosts["direct1"]["proxy"])
        self.assertEqual(hosts["direct2"]["jump"], "")
        self.assertFalse(hosts["direct2"]["proxy"])

    def test_system_config_ignored_when_explicit_config_path_given(self):
        with tempfile.TemporaryDirectory() as root:
            custom_conf = os.path.join(root, "custom_config")
            with open(custom_conf, "w") as fh:
                fh.write("Host srv.corp\n  Hostname 10.0.0.1\n")
            sys_conf = os.path.join(root, "system_ssh_config")
            with open(sys_conf, "w") as fh:
                fh.write("Host *.corp\n  ProxyJump bastion.corp\n")
            r = sshconfig.load(config_path=custom_conf, system_path=sys_conf)
            hosts = {h["alias"]: h for h in r["hosts"]}
            self.assertEqual(hosts["srv.corp"]["jump"], "")


if __name__ == "__main__":
    unittest.main()
