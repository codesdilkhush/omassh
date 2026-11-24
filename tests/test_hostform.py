import os
import re
import sys
import random
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import support
import hostform
import sshconfig

HOSTILE = [
    "\n", "\r", "\r\n", "\x00", "\x0b", "\x0c", "\x1c", "\x1f", "\x7f", "\x85", "\xa0", "\u2028", "\u2029", "\u202e", "\u200b", "\ufeff", "\u3000",
    "%h", "%%", "%u", "${HOME}", "$HOME", "`x`", "$(x)", "~root/x", "-oProxyCommand=x", "a;b", "a b", "a\tb", '"a"', "'a'", "#", "\\", "=", "&", "|",
    "<", ">", "*", "?", "!", "{", "}", "(", ")", ",", "\u212a", "\u0131", "\u0130", "\uff18\uff10", "\u00b2", "\u0663", "\u0e51",
]


exists = support.anything_exists


def norm(**kwargs):
    """Normalize a host whose fields default to a bare alias, overridden by kwargs."""
    raw = {"alias": "web", "hostname": "", "user": "", "port": "", "proxyJump": "", "identityFile": "", "forwards": []}
    raw.update(kwargs)
    return hostform.normalize(raw, exists)


def accepted(**kwargs):
    """True when the host built from kwargs is accepted."""
    host, errors = norm(**kwargs)
    return host is not None and not errors


def rejected(field, code=None, **kwargs):
    """True when the host built from kwargs is refused with an error on field, and with code when given."""
    host, errors = norm(**kwargs)
    if host is not None:
        return False
    return any(e["field"] == field and (code is None or e["code"] == code) for e in errors)


class AliasTests(unittest.TestCase):
    def test_accepts(self):
        for value in ("web", "a", "Web-1", "a.b_c", "x0", "a" * 128, " web ", "\tweb\t"):
            host, errors = norm(alias=value)
            self.assertEqual(errors, [], value)
            self.assertEqual(host["alias"], value.strip(" \t"))

    def test_rejects(self):
        for value in ("", "-a", ".a", "_a", "a" * 129, "a b", "a/b", "web*", "web?", "!web", "a,b", "\u212a", "a\u00e9"):
            self.assertTrue(rejected("alias", alias=value), repr(value))

    def test_codes(self):
        self.assertTrue(rejected("alias", "required", alias=""))
        self.assertTrue(rejected("alias", "required", alias="  "))
        self.assertTrue(rejected("alias", "too-long", alias="a" * 129))
        self.assertTrue(rejected("alias", "invalid", alias="a b"))

    def test_hostile_values_and_trailing_newline(self):
        for bad in HOSTILE:
            for value in ("web" + bad, bad + "web", "we" + bad + "b"):
                if value.strip(" \t") == "web":
                    continue
                self.assertTrue(rejected("alias", alias=value), repr(value))


class ShorthandTests(unittest.TestCase):
    BAD = ["9", "010", "0x7f.1", "0x", "1.2", "1.2.3", "010.0.2.1", "256.1.1.1", "0203.0.113.4", "203.0.113.04", "0X1", "4294967295"]
    GOOD = ["203.0.113.4", "192.0.2.5", ".".join("0000"), "255.255.255.255", "192.0.2.4.5", "9a", "a9", "0x1g", "1.2.3.", "face", "1.a"]

    def test_hostname(self):
        for value in self.BAD:
            self.assertTrue(rejected("hostname", "invalid", hostname=value), value)
        for value in self.GOOD:
            self.assertEqual(norm(hostname=value)[1], [], value)

    def test_hops_and_targets(self):
        for value in self.BAD:
            self.assertTrue(rejected("proxyJump", "hop", proxyJump=value), value)
            self.assertTrue(rejected("proxyJump", "hop", proxyJump="u@%s:22" % value), value)
            self.assertTrue(rejected("forwards", "forward", forwards=["L 1 %s:2" % value]), value)
            self.assertTrue(rejected("forwards", "forward", forwards=["R 1 %s:2" % value]), value)
        for value in self.GOOD:
            self.assertEqual(norm(proxyJump=value)[1], [], value)
            self.assertEqual(norm(forwards=["L 1 %s:2" % value])[1], [], value)

    def test_alias_without_a_hostname(self):
        for value in self.BAD:
            self.assertTrue(rejected("alias", "invalid", alias=value), value)
            self.assertEqual(norm(alias=value, hostname="h.example")[1], [], value)
        for value in self.GOOD:
            self.assertEqual(norm(alias=value)[1], [], value)


class HostnameTests(unittest.TestCase):
    def test_accepts_and_lowercases(self):
        table = {
            "web.example.com": "web.example.com",
            "WEB.Example.COM": "web.example.com",
            "192.0.2.5": "192.0.2.5",
            "2001:db8::1": "2001:db8::1",
            "2001:DB8::ABCD": "2001:db8::abcd",
            "2001:db8:0:0:0:0:0:93c4": "2001:db8::93c4",
            "2001:0db8::0001": "2001:db8::1",
            "0:0:0:0:0:0:0:1": "::1",
            "::ffff:c000:201": "::ffff:192.0.2.1",
            "64:ff9b::192.0.2.1": "64:ff9b::c000:201",
            "::1": "::1",
            "::ffff:192.0.2.1": "::ffff:192.0.2.1",
            "a": "a",
            "a" * 253: "a" * 253,
        }
        for value, expected in table.items():
            host, errors = norm(hostname=value)
            self.assertEqual(errors, [], value)
            self.assertEqual(host["hostname"], expected)

    def test_empty_is_allowed(self):
        self.assertEqual(norm(hostname="")[0]["hostname"], "")

    def test_rejects(self):
        table = ["[::1]", "[2001:db8::1]", "::c000:201", "::192.0.2.1", "::2", "0:0:0:0:0:0:0:2", "fe80::1%eth0", "fe80::1%25eth0", "::g", ":::", "1:2:3:4:5:6:7:8:9", "-a", ".a", "a b", "a/b", "a:b", "a:80", "a@b", "a" * 254]
        for value in table:
            self.assertTrue(rejected("hostname", hostname=value), repr(value))

    def test_codes(self):
        self.assertTrue(rejected("hostname", "too-long", hostname="a" * 254))
        self.assertTrue(rejected("hostname", "invalid", hostname="[::1]"))

    def test_the_grammar_runs_before_lowercasing(self):
        for value in ("\u212a.example.com", "\u212aelvin", "web\u212a", "\u0130stanbul"):
            self.assertTrue(rejected("hostname", hostname=value), repr(value))

    def test_hostile_values_and_trailing_newline(self):
        for bad in HOSTILE:
            for value in ("web.example.com" + bad, bad + "web.example.com", "web" + bad + ".example.com"):
                self.assertTrue(rejected("hostname", hostname=value), repr(value))
        self.assertTrue(rejected("hostname", hostname="2001:db8::1\n"))


class UserTests(unittest.TestCase):
    def test_accepts(self):
        for value in ("admin", "a", "_svc", ".x", "user.name-1", "a" * 64, "Admin"):
            self.assertEqual(norm(user=value)[0]["user"], value)

    def test_rejects(self):
        for value in ("-a", "a@b", "a b", "a" * 65, "a:b", "a\u00e9", "%u", "${USER}", "a/b", "root\u200b"):
            self.assertTrue(rejected("user", user=value), repr(value))

    def test_hostile_values_and_trailing_newline(self):
        for bad in HOSTILE:
            for value in ("admin" + bad, bad + "admin", "ad" + bad + "min"):
                self.assertTrue(rejected("user", user=value), repr(value))


class PortTests(unittest.TestCase):
    def test_accepts(self):
        for value in ("1", "22", "2222", "65535", "10000"):
            self.assertEqual(norm(port=value)[0]["port"], value)

    def test_rejects(self):
        table = ["0", "00", "022", "+22", "-1", "65536", "99999", "100000", "1_0", "1.0", "0x16", "2 2", "\uff18\uff10", "\u00b2", "\u0662\u0662", "\u0e52", "1e3", ""]
        for value in table[:-1]:
            self.assertTrue(rejected("port", "port", port=value), repr(value))
        self.assertEqual(norm(port="")[0]["port"], "")

    def test_hostile_values_and_trailing_newline(self):
        for bad in HOSTILE:
            self.assertTrue(rejected("port", port="22" + bad), repr(bad))
            self.assertTrue(rejected("port", port=bad + "22"), repr(bad))


class ProxyJumpTests(unittest.TestCase):
    def test_accepts(self):
        table = [
            "bastion",
            "bastion,admin@jump.example.com:2200",
            "admin@jump",
            "jump:22",
            "[2001:db8::1]",
            "admin@[2001:db8::1]:2200",
            "A.Example,b-1.example",
            " a , b ",
            ",".join("h%d" % i for i in range(8)),
            "192.0.2.1",
            "u@192.0.2.1:2",
        ]
        for value in table:
            host, errors = norm(proxyJump=value)
            self.assertEqual(errors, [], value)
            self.assertEqual(host["proxyJump"], ",".join(hop.strip(" \t") for hop in value.split(",")))

    def test_case_is_kept(self):
        self.assertEqual(norm(proxyJump="Bastion.Example")[0]["proxyJump"], "Bastion.Example")

    def test_rejects(self):
        table = [
            "none",
            "None",
            "a,none",
            "ssh://a",
            "ssh://a:22",
            "::1",
            "2001:db8::1",
            "[::1",
            "::1]",
            "[::1]x",
            "[::1]:",
            "[abc]",
            "[]",
            "a,,b",
            ",a",
            "a,",
            "a:",
            "a:0",
            "a:99999",
            "a:022",
            "a:b",
            "a:1:2",
            "@a",
            "u@",
            "a@b@c",
            "a b",
            "a;touch",
            "-oProxyCommand=x",
            "a\\b",
            "a%h",
            "a$b",
            "a#",
            "'a'",
            "[fe80::1%eth0]",
            "-jump.example.com",
            "admin@-jump",
            "-admin@jump",
            "a,-b",
            "a,b,-c",
            "[2001:db8::1]:99999",
        ]
        for value in table:
            self.assertTrue(rejected("proxyJump", proxyJump=value), repr(value))

    def test_codes(self):
        self.assertTrue(rejected("proxyJump", "too-many", proxyJump=",".join("h%d" % i for i in range(9))))
        self.assertTrue(rejected("proxyJump", "too-long", proxyJump="a" * 1025))
        self.assertTrue(rejected("proxyJump", "hop", proxyJump="a,none"))
        self.assertTrue(rejected("proxyJump", "self", alias="web", proxyJump="web"))
        self.assertTrue(rejected("proxyJump", "self", alias="web", proxyJump="bastion,admin@WEB:22"))
        self.assertTrue(accepted(alias="web", proxyJump="web2"))

    def test_hostile_values_and_trailing_newline(self):
        for bad in HOSTILE:
            for value in ("jump" + bad, bad + "jump", "a," + bad + "b", "admin@jump" + bad):
                if bad == ",":
                    continue
                self.assertTrue(rejected("proxyJump", proxyJump=value), repr(value))

    def test_accepted_hops_only_use_the_whitelist(self):
        pattern = re.compile(r"[A-Za-z0-9._@:\[\]-]+")
        for value in ("a,b", "u@[2001:db8::1]:22", "x.y-z"):
            for hop in norm(proxyJump=value)[0]["proxyJump"].split(","):
                self.assertIsNotNone(pattern.fullmatch(hop))
                self.assertFalse(hop.startswith("-"))


class IdentityFileTests(unittest.TestCase):
    def test_accepts(self):
        for value in ("~/.ssh/id_ed25519", "/home/u/.ssh/id.rsa", "~/a/b+c@d-e_f.pub", "/a", "~/.x", "/a/.../b"):
            self.assertEqual(norm(identityFile=value)[0]["identityFile"], value)

    def test_rejects(self):
        table = [
            "id_ed25519",
            "~",
            "~/",
            "~root/x",
            "~user/.ssh/id",
            "/",
            "//a",
            "/a//b",
            "/a/",
            "/a/./b",
            "/a/../b",
            "/..",
            "~/..",
            "~/../x",
            "/a b",
            "/a;b",
            "/a%h",
            "/a$HOME",
            "/a\\b",
            "/a#",
            '/a"b',
            "/a=b",
            "none",
            "-i",
            "/" + "a" * 1024,
            "/a\u00e9",
            "~/a~",
        ]
        for value in table:
            self.assertTrue(rejected("identityFile", identityFile=value), repr(value))

    def test_codes(self):
        self.assertTrue(rejected("identityFile", "too-long", identityFile="/" + "a" * 1024))
        self.assertTrue(rejected("identityFile", "invalid", identityFile="/a b"))

    def test_must_exist(self):
        host, errors = hostform.normalize({"alias": "web", "identityFile": "/a/b"}, lambda path: False)
        self.assertIsNone(host)
        self.assertEqual(errors, [{"field": "identityFile", "code": "not-found"}])
        seen = []
        hostform.normalize({"alias": "web", "identityFile": "~/k"}, lambda path: seen.append(path) or True)
        self.assertEqual(seen, ["~/k"])

    def test_a_failing_existence_check_is_not_found(self):
        def boom(path):
            raise OSError("no")

        host, errors = hostform.normalize({"alias": "web", "identityFile": "/a/b"}, boom)
        self.assertIsNone(host)
        self.assertEqual(errors, [{"field": "identityFile", "code": "not-found"}])

    def test_hostile_values_and_trailing_newline(self):
        for bad in HOSTILE:
            for value in ("/a/key" + bad, bad + "/a/key", "/a/k" + bad + "ey", "~/k" + bad):
                self.assertTrue(rejected("identityFile", identityFile=value), repr(value))

    def test_the_check_is_not_reached_for_an_invalid_path(self):
        seen = []
        hostform.normalize({"alias": "web", "identityFile": "/a/../b"}, lambda path: seen.append(path) or True)
        self.assertEqual(seen, [])


class ForwardTests(unittest.TestCase):
    def test_accepts_and_canonicalizes(self):
        table = {
            "L 8080 localhost:80": "L 8080 localhost:80",
            "l 8080 localhost:80": "L 8080 localhost:80",
            "  L   8080\tlocalhost:80  ": "L 8080 localhost:80",
            "L 127.0.0.1:8080 db.example.com:5432": "L 127.0.0.1:8080 db.example.com:5432",
            "L localhost:8080 192.0.2.1:22": "L localhost:8080 192.0.2.1:22",
            "L [::1]:8080 [2001:db8::1]:22": "L [::1]:8080 [2001:db8::1]:22",
            "L 8080 DB.Example:1": "L 8080 DB.Example:1",
            "R 9000 localhost:22": "R 9000 localhost:22",
            "r 9001": "R 9001",
            "R localhost:9002": "R localhost:9002",
            "R [::1]:9003 h:1": "R [::1]:9003 h:1",
            "D 1080": "D 1080",
            "d localhost:1081": "D localhost:1081",
            "D [::1]:1082": "D [::1]:1082",
            "D 127.0.0.1:1083": "D 127.0.0.1:1083",
            "D 65535": "D 65535",
        }
        for row, expected in table.items():
            host, errors = norm(forwards=[row])
            self.assertEqual(errors, [], row)
            self.assertEqual(host["forwards"], [expected])

    def test_rejects(self):
        table = [
            "*:8080",
            "L *:8080 h:1",
            "L %s:8080 h:1" % ".".join("0000"),
            "L [::]:8080 h:1",
            "L 192.0.2.1:8080 h:1",
            "L :8080 h:1",
            "L Localhost:8080 h:1",
            "L [::1]8080 h:1",
            "L /tmp/sock h:1",
            "L 8080 /tmp/sock",
            "L 8080",
            "L 8080 h",
            "L 8080 h:",
            "L 8080 h:0",
            "L 8080 h:65536",
            "L 0 h:1",
            "L 65536 h:1",
            "L 8080 h:1 extra",
            "L 8080 ::1:22",
            "L 8080 [h]:22",
            "L 8080 [::1]",
            "L 8080 -h:22",
            "L 8080 h:1;x",
            "L 8080 h%h:1",
            "L 08080 h:1",
            "R",
            "R 1 2 3 4",
            "R 9000 h",
            "R *:9000",
            "D",
            "D 1 2",
            "D 0",
            "D *:1080",
            "D :1080",
            "D 1080 h:1",
            "X 8080 h:1",
            "LocalForward 8080 h:1",
            "8080 h:1",
            "L\n8080 h:1",
            "L 8080 h:1\nL 9090 h:2",
            "L\u20288080 h:1",
            "L\x858080 h:1",
            "L 8080 h:1\r",
            "L 8080 h:1\x00",
            "L 8080 h:1 # x",
            "L 8080 'h':1",
            "L ${HOME} h:1",
            "L 8080 h:1=",
            "L \uff18\uff10\uff18\uff10 h:1",
        ]
        for row in table:
            self.assertTrue(rejected("forwards", "forward", forwards=[row]), repr(row))

    def test_error_index_is_the_submitted_row(self):
        host, errors = norm(forwards=["L 1 h:1", "", "bad", "D 2"])
        self.assertIsNone(host)
        self.assertEqual(errors, [{"field": "forwards", "index": 2, "code": "forward"}])

    def test_blank_rows_are_dropped(self):
        self.assertEqual(norm(forwards=["", "  ", "\t", "D 1080"])[0]["forwards"], ["D 1080"])

    def test_duplicates(self):
        host, errors = norm(forwards=["L 1 h:1", "l  1 h:1", "D 2"])
        self.assertIsNone(host)
        self.assertEqual(errors, [{"field": "forwards", "index": 1, "code": "duplicate"}])
        self.assertIsNotNone(norm(forwards=["L 1 h:1", "L 1 h:2"])[0])

    def test_limits(self):
        sixteen = ["L %d h:1" % (i + 1) for i in range(16)]
        self.assertEqual(len(norm(forwards=sixteen)[0]["forwards"]), 16)
        host, errors = norm(forwards=sixteen + ["L 17 h:1"])
        self.assertIsNone(host)
        self.assertEqual(errors, [{"field": "forwards", "code": "too-many"}])
        self.assertEqual(len(norm(forwards=sixteen + ["", " "])[0]["forwards"]), 16)
        host, errors = norm(forwards=["L 1 " + "h" * 300 + ":1"])
        self.assertEqual(errors, [{"field": "forwards", "index": 0, "code": "too-long"}])

    def test_rows_are_ordered_by_kind_keeping_order_inside_a_kind(self):
        rows = ["D 1", "R 2", "L 3 h:1", "D 4", "R 5", "L 6 h:1"]
        self.assertEqual(norm(forwards=rows)[0]["forwards"], ["L 3 h:1", "L 6 h:1", "R 2", "R 5", "D 1", "D 4"])

    def test_wrong_types(self):
        for value in ("L 1 h:1", None, 5, {"a": 1}):
            self.assertTrue(rejected("forwards", "invalid", forwards=value), repr(value))
        host, errors = norm(forwards=["D 1", 7, None])
        self.assertIsNone(host)
        self.assertEqual([e["index"] for e in errors], [1, 2])

    def test_hostile_values_and_trailing_newline(self):
        rows = ("L 8080 localhost:80", "R 9000", "D 1080")
        for bad in HOSTILE:
            for row in rows:
                for value in (row + bad, bad + row, row[:2] + bad + row[2:], row[:-1] + bad + row[-1]):
                    host, errors = norm(forwards=[value])
                    if host is None:
                        continue
                    for line in host["forwards"]:
                        self.assertIsNotNone(re.fullmatch(r"[LRD]( [A-Za-z0-9.:\[\]-]+)+", line), repr(value))
                        self.assertTrue(line.isascii())
        for row in rows:
            self.assertTrue(rejected("forwards", forwards=[row + "\n"]))
            self.assertTrue(rejected("forwards", forwards=[row + "\x0b"]))
            self.assertTrue(rejected("forwards", forwards=[row + "\x85"]))


class NormalizeTests(unittest.TestCase):
    def test_a_full_host(self):
        host, errors = norm(
            alias="web",
            hostname="Web.Example.com",
            user="admin",
            port="2222",
            proxyJump="bastion",
            identityFile="~/.ssh/id_ed25519",
            forwards=["D 1080", "l 8080 localhost:80"],
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            host,
            {
                "alias": "web",
                "hostname": "web.example.com",
                "user": "admin",
                "port": "2222",
                "proxyJump": "bastion",
                "identityFile": "~/.ssh/id_ed25519",
                "forwards": ["L 8080 localhost:80", "D 1080"],
            },
        )

    def test_missing_keys_are_empty(self):
        host, errors = hostform.normalize({"alias": "web"}, exists)
        self.assertEqual(errors, [])
        self.assertEqual(host["forwards"], [])
        self.assertEqual(host["hostname"], "")

    def test_non_string_values_are_invalid(self):
        for field in ("alias", "hostname", "user", "port", "proxyJump", "identityFile"):
            for value in (None, 5, 1.5, True, ["a"], {"a": 1}, b"a"):
                host, errors = norm(**{field: value})
                self.assertIsNone(host, (field, value))
                self.assertEqual([e["field"] for e in errors], [field])
                self.assertEqual(errors[0]["code"], "invalid")

    def test_not_a_dict(self):
        for raw in (None, [], "web", 5):
            host, errors = hostform.normalize(raw, exists)
            self.assertIsNone(host)
            self.assertTrue(errors)

    def test_errors_cover_every_bad_field(self):
        host, errors = norm(alias="", hostname="[::1]", user="-a", port="0", proxyJump="none", identityFile="x", forwards=["bad"])
        self.assertIsNone(host)
        self.assertEqual(
            [(e["field"], e["code"]) for e in errors],
            [
                ("alias", "required"),
                ("hostname", "invalid"),
                ("user", "invalid"),
                ("port", "port"),
                ("proxyJump", "hop"),
                ("identityFile", "invalid"),
                ("forwards", "forward"),
            ],
        )

    def test_idempotent_through_the_form(self):
        host = norm(alias="web", hostname="H.example", port="22", proxyJump="a,b", forwards=["R 9", "L 1 h:1"])[0]
        again = hostform.normalize(hostform.to_form(host), exists)
        self.assertEqual(again, (host, []))

    def test_unknown_keys_are_ignored(self):
        host, errors = hostform.normalize({"alias": "web", "expect": "x", "other": 1}, exists)
        self.assertEqual(errors, [])
        self.assertEqual(set(host), {"alias", "hostname", "user", "port", "proxyJump", "identityFile", "forwards"})


SAMPLE = [
    {
        "alias": "web",
        "hostname": "web.example.com",
        "user": "admin",
        "port": "2222",
        "proxyJump": "bastion,admin@jump.example.com:2200",
        "identityFile": "~/.ssh/id_ed25519",
        "forwards": ["L 8080 localhost:80", "R 9000 localhost:22", "R 9001", "D 1080"],
    },
    {"alias": "db", "hostname": "192.0.2.5", "user": "", "port": "", "proxyJump": "", "identityFile": "", "forwards": []},
]


def intended_lines(host):
    """The keyword and argument list ssh must read from each line of the rendered block of host."""
    expected = [("Host", [host["alias"]])]
    expected += [(hostform.KEYWORDS[field], [host[field]]) for field in ("hostname", "user", "port", "proxyJump", "identityFile") if host[field]]
    expected += [(hostform.KEYWORDS[row[0]], row.split(" ")[1:]) for row in host["forwards"]]
    return expected


def read_back(host):
    """The keyword and argument list that sshconfig's tokenizer finds in the rendered block of host."""
    found = []
    for line in hostform.render_block(host).splitlines():
        keyword, rest = sshconfig.split_keyword(line)
        found.append((keyword, sshconfig.split_args(rest)))
    return found


class RenderTests(unittest.TestCase):
    def test_the_documented_layout(self):
        text = hostform.render(SAMPLE)
        self.assertEqual(
            text,
            hostform.HEADER
            + "\n\nHost web\n    HostName web.example.com\n    User admin\n    Port 2222\n    ProxyJump bastion,admin@jump.example.com:2200\n"
            "    IdentityFile ~/.ssh/id_ed25519\n    LocalForward 8080 localhost:80\n    RemoteForward 9000 localhost:22\n    RemoteForward 9001\n"
            "    DynamicForward 1080\n\nHost db\n    HostName 192.0.2.5\n",
        )

    def test_an_empty_list_is_the_header(self):
        self.assertEqual(hostform.render([]), hostform.HEADER + "\n")
        self.assertEqual(hostform.parse(hostform.render([])), [])

    def test_a_host_with_no_options_is_one_line(self):
        host = norm()[0]
        self.assertEqual(hostform.render_block(host), "Host web\n")

    def test_the_text_is_ascii_lf_only(self):
        text = hostform.render(support.random_hosts(random.Random(1), 20))
        self.assertTrue(text.isascii())
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))

    def test_only_the_whitelisted_keywords_are_ever_rendered(self):
        allowed = {"Host", "HostName", "User", "Port", "ProxyJump", "IdentityFile", "LocalForward", "RemoteForward", "DynamicForward"}
        for host in support.random_hosts(random.Random(2), 60):
            for line in hostform.render_block(host).splitlines():
                self.assertIn(sshconfig.split_keyword(line)[0], allowed)

    def test_every_rendered_line_is_one_keyword_with_exactly_the_intended_arguments(self):
        for host in support.random_hosts(random.Random(3), 80) + support.random_wild_hosts(random.Random(4), 80):
            self.assertEqual(read_back(host), intended_lines(host))


class ParseTests(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(hostform.parse(hostform.render(SAMPLE)), SAMPLE)
        self.assertEqual(hostform.parse(hostform.render(SAMPLE).encode()), SAMPLE)

    def test_round_trip_of_random_valid_hosts(self):
        rng = random.Random(7)
        for _ in range(150):
            hosts = support.random_hosts(rng, rng.randrange(0, 8))
            text = hostform.render(hosts)
            self.assertEqual(hostform.parse(text), hosts)
            self.assertEqual(hostform.render(hostform.parse(text)), text)
            for host in hosts:
                self.assertEqual(hostform.normalize(hostform.to_form(host), exists), (host, []))

    def test_foreign_files_are_none(self):
        text = hostform.render(SAMPLE)
        header = hostform.HEADER + "\n"
        cases = {
            "comment": text.replace("\n\nHost db", "\n# note\n\nHost db"),
            "trailing comment": text.replace("User admin", "User admin # x"),
            "reordered": text.replace("    User admin\n    Port 2222\n", "    Port 2222\n    User admin\n"),
            "lowercase keyword": text.replace("HostName web", "hostname web", 1),
            "tab indent": text.replace("    User admin", "\tUser admin"),
            "two space indent": text.replace("    User admin", "  User admin"),
            "trailing space": text.replace("User admin", "User admin "),
            "leading space value": text.replace("User admin", "User  admin"),
            "crlf": text.replace("\n", "\r\n"),
            "missing header": text[len(header) :],
            "other header": text.replace("OmaSSH host file", "My hosts", 1),
            "non ascii": text.replace("admin", "adm\u00efn"),
            "bom": "\ufeff" + text,
            "double blank": text.replace("\n\nHost db", "\n\n\nHost db"),
            "no separator": text.replace("\n\nHost db", "\nHost db"),
            "no trailing newline": text[:-1],
            "extra trailing newline": text + "\n",
            "leading blank": header + "\n" + text[len(header) :],
            "equals sign": text.replace("User admin", "User=admin"),
            "duplicate option": text.replace("    Port 2222\n", "    Port 2222\n    Port 2223\n"),
            "unknown keyword": text.replace("    Port 2222\n", "    Port 2222\n    Compression yes\n"),
            "keyword before host": header + "    User x\n" + text[len(header) :],
            "match": text + "\nMatch all\n    User x\n",
            "include": text + "\nInclude other\n",
            "duplicate host": text + "\nHost db\n    HostName 192.0.2.5\n",
            "forwards out of order": text.replace("    LocalForward 8080 localhost:80\n    RemoteForward 9000 localhost:22\n", "    RemoteForward 9000 localhost:22\n    LocalForward 8080 localhost:80\n"),
            "uppercase hostname": text.replace("web.example.com", "WEB.example.com"),
            "tilde": text.replace("~/.ssh", "~root/.ssh"),
            "forward kind": text.replace("LocalForward 8080", "LocalForward 0.0.0.0:8080"),
            "empty": "",
            "header only plus blank": header + "\n",
            "nul": text.replace("admin", "ad\x00min"),
        }
        for name, case in cases.items():
            self.assertIsNone(hostform.parse(case), name)
            self.assertIsNone(hostform.parse(case.encode("utf-8")), name)

    def test_limits(self):
        hosts = [norm(alias="h%d" % i)[0] for i in range(hostform.MAX_HOSTS)]
        self.assertEqual(hostform.parse(hostform.render(hosts)), hosts)
        hosts.append(norm(alias="extra")[0])
        self.assertIsNone(hostform.parse(hostform.render(hosts)))
        big = hostform.HEADER + "\n" + "\n" * hostform.MAX_BYTES
        self.assertIsNone(hostform.parse(big))

    def test_wrong_types_and_bad_encodings(self):
        self.assertIsNone(hostform.parse(b"\xff\xfe"))
        self.assertIsNone(hostform.parse("\u00e9"))
        self.assertIsNone(hostform.parse(hostform.HEADER.encode() + b"\n\xc3\xa9"))

    def test_every_single_byte_change_gives_none_or_a_file_that_renders_to_itself(self):
        text = hostform.render(SAMPLE)
        replacements = "\n\r\t \x00 #=%$\\\"'-.:,@[]*~;|&aZ09HhL\x85\x7f\u00e9\u2028"
        survivors = 0
        for index in range(len(text)):
            mutants = [text[:index] + text[index + 1 :]]
            for ch in replacements:
                mutants.append(text[:index] + ch + text[index + 1 :])
                mutants.append(text[:index] + ch + text[index:])
            for mutant in mutants:
                parsed = hostform.parse(mutant)
                if parsed is not None:
                    survivors += 1
                    self.assertEqual(hostform.render(parsed), mutant)
        self.assertGreater(survivors, 0)

    def test_every_single_byte_change_of_random_files(self):
        rng = random.Random(11)
        for _ in range(6):
            text = hostform.render(support.random_hosts(rng, 2))
            for _ in range(600):
                index = rng.randrange(len(text))
                ch = rng.choice(HOSTILE + list("abcL19:@[]. "))
                mutant = rng.choice([text[:index] + ch + text[index + 1 :], text[:index] + ch + text[index:], text[:index] + text[index + 1 :]])
                parsed = hostform.parse(mutant)
                if parsed is not None:
                    self.assertEqual(hostform.render(parsed), mutant)

    def test_the_lenient_reader_still_cannot_accept_a_non_canonical_text(self):
        text = hostform.render(SAMPLE)
        lines = text.split("\n")
        shuffled = "\n".join([lines[0]] + sorted(lines[1:]))
        self.assertIsNone(hostform.parse(shuffled))


class BlockHashTests(unittest.TestCase):
    def test_shape_and_sensitivity(self):
        host = SAMPLE[0]
        digest = hostform.block_hash(host)
        self.assertRegex(digest, r"\A[0-9a-f]{16}\Z")
        self.assertEqual(digest, hostform.block_hash(dict(host)))
        for field, value in (("user", "root"), ("port", "22"), ("hostname", "x.example"), ("forwards", ["D 1"]), ("alias", "web2")):
            self.assertNotEqual(hostform.block_hash({**host, field: value}), digest, field)

    def test_to_form(self):
        form = hostform.to_form(SAMPLE[0])
        self.assertEqual(set(form), {"alias", "hostname", "user", "port", "proxyJump", "identityFile", "forwards", "expect"})
        self.assertEqual(form["expect"], hostform.block_hash(SAMPLE[0]))
        form["forwards"].append("D 2")
        self.assertEqual(len(SAMPLE[0]["forwards"]), 4)


class DashGTests(unittest.TestCase):
    def output(self, **changes):
        """A host and the ssh -G output that matches it, with lines replaced or removed through changes."""
        host = dict(SAMPLE[0])
        lines = {
            "hostname": "web.example.com",
            "user": "admin",
            "port": "2222",
            "proxyjump": "bastion,admin@jump.example.com:2200",
            "identityfile": "~/.ssh/id_ed25519",
            "clearallforwardings": "no",
        }
        lines.update(changes)
        out = ["%s %s" % (key, value) for key, value in lines.items() if value is not None]
        out += ["localforward 8080 [localhost]:80", "remoteforward 9000 [localhost]:22", "remoteforward 9001 [socks]:0", "dynamicforward 1080"]
        return host, "\n".join(out) + "\n"

    def test_expected_values(self):
        expected = hostform.dash_g("web", SAMPLE[0])
        self.assertEqual(expected["equal"]["hostname"], "web.example.com")
        self.assertEqual(expected["equal"]["port"], "2222")
        self.assertEqual(expected["equal"]["user"], "admin")
        self.assertEqual(expected["equal"]["clearallforwardings"], "no")
        self.assertEqual(expected["among"], {"identityfile": "~/.ssh/id_ed25519"})
        self.assertEqual(expected["ordered"]["localforward"], ["8080 [localhost]:80"])
        self.assertEqual(expected["ordered"]["remoteforward"], ["9000 [localhost]:22", "9001 [socks]:0"])
        self.assertEqual(expected["ordered"]["dynamicforward"], ["1080"])

    def test_defaults_for_a_bare_host(self):
        host = norm(alias="Web")[0]
        expected = hostform.dash_g("Web", host)
        self.assertEqual(expected["equal"], {"hostname": "web", "port": "22", "clearallforwardings": "no"})
        self.assertEqual(expected["absent"], ["proxyjump"])
        self.assertEqual(expected["among"], {})

    def test_forward_forms(self):
        host = norm(forwards=["L 127.0.0.1:1 [::1]:2", "L [::1]:3 h:4", "R localhost:5", "R [::1]:6 h:7", "D localhost:8", "D [::1]:9", "D 10"])[0]
        ordered = hostform.dash_g("web", host)["ordered"]
        self.assertEqual(ordered["localforward"], ["[127.0.0.1]:1 [::1]:2", "[::1]:3 [h]:4"])
        self.assertEqual(ordered["remoteforward"], ["[localhost]:5 [socks]:0", "[::1]:6 [h]:7"])
        self.assertEqual(ordered["dynamicforward"], ["[localhost]:8", "[::1]:9", "10"])

    def test_a_matching_output(self):
        host, out = self.output()
        self.assertEqual(hostform.diff_g(hostform.dash_g("web", host), out), "")

    def test_every_difference_is_named(self):
        cases = {
            "hostname": self.output(hostname="other.example"),
            "port": self.output(port="22"),
            "user": self.output(user="root"),
            "proxyjump": self.output(proxyjump="other"),
            "identityfile": self.output(identityfile="~/.ssh/other"),
            "clearallforwardings": self.output(clearallforwardings="yes"),
        }
        for name, (host, out) in cases.items():
            self.assertEqual(hostform.diff_g(hostform.dash_g("web", host), out), name)

    def test_missing_and_extra_lines(self):
        host, out = self.output()
        expected = hostform.dash_g("web", host)
        self.assertEqual(hostform.diff_g(expected, out.replace("dynamicforward 1080\n", "")), "dynamicforward")
        self.assertEqual(hostform.diff_g(expected, out + "localforward 1 [h]:1\n"), "localforward")
        self.assertEqual(hostform.diff_g(expected, out.replace("remoteforward 9000 [localhost]:22\n", "")), "remoteforward")
        self.assertEqual(hostform.diff_g(expected, self.output(proxyjump=None)[1]), "proxyjump")
        self.assertEqual(hostform.diff_g(expected, self.output(identityfile=None)[1]), "identityfile")
        bare = norm()[0]
        self.assertEqual(hostform.diff_g(hostform.dash_g("web", bare), "hostname web\nport 22\nclearallforwardings no\nproxyjump x\n"), "proxyjump")

    def test_empty_output_is_a_failure(self):
        for out in ("", "\n"):
            self.assertEqual(hostform.diff_g(hostform.dash_g("web", norm()[0]), out), "empty")

    def test_only_the_first_value_of_a_scalar_counts(self):
        host, out = self.output()
        expected = hostform.dash_g("web", host)
        self.assertEqual(hostform.diff_g(expected, "port 1\n" + out), "port")


class FuzzTests(unittest.TestCase):
    ALPHABET = list("abcAZ019-._~/@:,[]; \t=#\"'\\%$*?!") + HOSTILE

    def random_string(self, rng):
        """A short random string over the hostile alphabet."""
        return "".join(rng.choice(self.ALPHABET) for _ in range(rng.randrange(0, 14)))

    def test_normalize_never_raises_and_accepts_only_the_whitelist(self):
        rng = random.Random(1234)
        ascii_name = re.compile(r"[A-Za-z0-9._@:\[\]~/+,-]*")
        accepted_count = 0
        for _ in range(20000):
            raw = {field: self.random_string(rng) if rng.random() < 0.2 else "" for field in ("alias", "hostname", "user", "port", "proxyJump", "identityFile")}
            raw["forwards"] = [self.random_string(rng) for _ in range(rng.randrange(0, 2))] if rng.random() < 0.3 else []
            if rng.random() < 0.8:
                raw["alias"] = rng.choice(["web", "a1", "h.x"])
            host, errors = hostform.normalize(raw, exists)
            self.assertEqual(host is None, bool(errors), raw)
            if host is None:
                continue
            accepted_count += 1
            for field in ("alias", "hostname", "user", "port", "proxyJump", "identityFile"):
                self.assertIsNotNone(ascii_name.fullmatch(host[field]), (field, host[field]))
                self.assertTrue(host[field].isascii())
            for line in host["forwards"]:
                self.assertIsNotNone(re.fullmatch(r"[LRD]( [A-Za-z0-9.:\[\]-]+)+", line), line)
            for hop in filter(None, host["proxyJump"].split(",")):
                self.assertFalse(hop.startswith("-"))
                self.assertIsNotNone(re.fullmatch(r"[A-Za-z0-9._@:\[\]-]+", hop))
            self.check_rendering(host)
        self.assertGreater(accepted_count, 200)

    def check_rendering(self, host):
        """Assert that a canonical host renders to lines that ssh parses as exactly the intended keywords and arguments."""
        self.assertEqual(read_back(host), intended_lines(host))
        self.assertEqual(hostform.parse(hostform.render([host])), [host])

    def test_hostile_text_never_reaches_the_file(self):
        rng = random.Random(99)
        for _ in range(4000):
            field = rng.choice(("alias", "hostname", "user", "port", "proxyJump", "identityFile"))
            raw = {"alias": "web", field: self.random_string(rng) or "x"}
            host, errors = hostform.normalize(raw, exists)
            if host is not None:
                text = hostform.render([host])
                self.assertTrue(text.isascii())
                self.assertEqual(text.count("\n"), 3 + sum(1 for f in ("hostname", "user", "port", "proxyJump", "identityFile") if host[f]))


if __name__ == "__main__":
    unittest.main()
