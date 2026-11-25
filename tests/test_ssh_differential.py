import os
import sys
import random
import shutil
import tempfile
import unittest
import subprocess
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import support
import hostform
import sshconfig
import mainconfig

SSH = shutil.which("ssh")
_SYSTEM_PATCH = None


def setUpModule():
    global _SYSTEM_PATCH
    _SYSTEM_PATCH = mock.patch.object(sshconfig, "SYSTEM_CONFIG_PATH", "")
    _SYSTEM_PATCH.start()


def tearDownModule():
    if _SYSTEM_PATCH is not None:
        _SYSTEM_PATCH.stop()


def write_tree(home, config, files):
    ssh_dir = os.path.join(home, ".ssh")
    os.makedirs(ssh_dir)
    with open(os.path.join(ssh_dir, "config"), "w", encoding="utf-8") as fh:
        fh.write(config)
    for name, body in (files or {}).items():
        path = os.path.join(ssh_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    return ssh_dir


def ssh_effective_lists(home, alias, extra_env=None):
    """``ssh -G`` result as a dict of value lists in output order, or ``None`` if ssh rejects the config."""
    env = {"HOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), **(extra_env or {})}
    r = subprocess.run(
        [SSH, "-G", "-F", os.path.join(home, ".ssh", "config"), alias],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if r.returncode != 0:
        return None
    out = {}
    for line in r.stdout.splitlines():
        key, _, value = line.partition(" ")
        out.setdefault(key, []).append(value)
    return out


def ssh_effective(home, alias):
    """``ssh -G`` result as a dict of first values, or ``None`` if ssh rejects the config."""
    lists = ssh_effective_lists(home, alias)
    return None if lists is None else {key: values[0] for key, values in lists.items()}


def dash_g_endpoint(token):
    """A forward endpoint the way ``ssh -G`` prints it: a bare port stays, ``host:port`` becomes ``[host]:port``."""
    if token.startswith("[") or token.isdigit():
        return token
    host, _, port = token.rpartition(":")
    return "[%s]:%s" % (host, port)


def dash_g_forwards(host):
    """Our forwards as ``ssh -G`` lines, grouped by its option name."""
    names = {"L": "localforward", "R": "remoteforward", "D": "dynamicforward"}
    out = {name: [] for name in names.values()}
    for fwd in host["forwards"]:
        line = dash_g_endpoint(fwd["listen"])
        if fwd["kind"] == "R" and not fwd["target"]:
            line += " [socks]:0"
        elif fwd["kind"] != "D":
            line += " " + dash_g_endpoint(fwd["target"])
        out[names[fwd["kind"]]].append(line)
    return out


def default_user():
    with tempfile.TemporaryDirectory() as home:
        os.makedirs(os.path.join(home, ".ssh"))
        open(os.path.join(home, ".ssh", "config"), "w").close()
        return ssh_effective(home, "whatever")["user"]


@unittest.skipUnless(SSH, "ssh is not installed")
class DifferentialCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.default_user = default_user()

    def setUp(self):
        self.forwarded = self.cleared = 0

    def check(self, config, files=None):
        """Return the number of hosts compared; fail on any disagreement."""
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_tree(home, config, files)
            parsed = sshconfig.load(ssh_dir=ssh_dir)
            compared = 0
            for host in parsed["hosts"]:
                alias = host["alias"]
                lists = ssh_effective_lists(home, alias)
                if lists is None:
                    return None
                truth = {key: values[0] for key, values in lists.items()}
                msg = "\n--- config ---\n%s\n--- files ---\n%r\n--- host %s ---\nours:  %r\nssh -G: %r" % (config, files, alias, host, truth)
                hostname = host["hostname"].replace("%h", alias) or alias
                self.assertEqual(truth["hostname"], hostname, msg)
                self.assertEqual(truth["user"], host["user"] or self.default_user, msg)
                self.assertEqual(int(truth["port"]), host["port"] or 22, msg)
                self.assertEqual(truth.get("proxyjump", ""), host["jump"], msg)
                self.assertEqual("proxycommand" in truth, host["proxy"], msg)
                ours = dash_g_forwards(host)
                if truth["clearallforwardings"] == "yes":
                    self.assertEqual(host["forwards"], [], msg)
                for name, lines in ours.items():
                    self.assertEqual(lists.get(name, [])[: len(lines)], lines, msg)
                total = sum(len(lists.get(name, [])) for name in ours)
                self.assertEqual(total, len(host["forwards"]) + host["forwardsMore"], msg)
                self.forwarded += bool(host["forwards"])
                self.cleared += truth["clearallforwardings"] == "yes"
                compared += 1
            return compared


class ScenarioTests(DifferentialCase):
    def test_basic(self):
        self.assertEqual(self.check("Host a\n HostName h\n User u\n Port 2201\nHost b\n"), 2)

    def test_jump_from_a_later_wildcard_block(self):
        self.check("Host db\n HostName 198.51.100.23\nHost *\n ProxyJump bastion\n")
        self.check("Host db\n HostName 198.51.100.23\nHost *.internal db\n ProxyJump bastion\n")

    def test_proxycommand_from_a_later_wildcard_block(self):
        self.check("Host db\n HostName 198.51.100.23\nHost *\n ProxyCommand nc %h %p\n")

    def test_options_before_any_host_apply_to_everyone(self):
        self.check("User globaluser\nPort 2299\nHost a\n HostName h\nHost b\n")

    def test_first_value_wins(self):
        self.check("Host *\n User wild\nHost a\n User spec\n")
        self.check("Host a\n User spec\nHost *\n User wild\n")
        self.check("Host a\n User one\n User two\n")

    def test_negation(self):
        self.check("Host a b skip\nHost * !skip\n User negated\n")
        self.check("Host a\nHost skip\nHost !skip *\n User x\n")

    def test_matching_is_case_sensitive(self):
        self.check("Host WEB\n HostName up.example\nHost web\n")

    def test_wildcards(self):
        self.check("Host web1\nHost web2\nHost webx10\nHost web?\n User q\nHost web*\n Port 2230\n")

    def test_proxy_none_disables_a_later_jump(self):
        self.check("Host a\n ProxyJump none\nHost *\n ProxyJump b\n")
        self.check("Host a\n ProxyCommand none\nHost *\n ProxyCommand nc %h %p\n")

    def test_proxyjump_and_proxycommand_compete_in_every_order(self):
        values = ["ProxyJump none", "ProxyJump j1", "ProxyCommand none", "ProxyCommand nc %h %p"]
        for first in values:
            for second in values:
                self.check("Host a\n %s\n %s\n" % (first, second))
                self.check("Host a\n %s\nHost *\n %s\n" % (first, second))

    def test_include_at_top(self):
        self.check("Include extra\nHost a\n HostName h\n", {"extra": "User inc-user\nPort 2201\n"})

    def test_include_glob(self):
        self.check("Include conf.d/*\nHost a\n", {"conf.d/10": "Host a\n User ten\n", "conf.d/20": "Host a\n User twenty\n"})

    def test_include_inside_a_host_block_is_conditional(self):
        files = {"extra": "User inc-user\nPort 2201\n"}
        self.check("Host a\n Include extra\n HostName after-include\nHost b\n HostName for-b\n", files)

    def test_include_that_opens_blocks_inside_a_host_block(self):
        files = {"extra": "Host zed\n User zeduser\n"}
        self.check("Host a zed\n Include extra\n HostName after\n", files)
        self.check("Host a\n Include extra\n HostName after\nHost zed\n", files)

    def test_syntax_variants(self):
        self.check('host=a # comment\n  hostname = "quoted.example"   # trailing\n  USER=Mixed\n')

    def test_hostname_tokens(self):
        self.check("Host a b\n HostName %h.example.org\n")

    def test_forwards_accumulate_across_blocks_in_reading_order(self):
        config = "Host a\n LocalForward 8080 localhost:80\nHost *\n LocalForward 9090 db:5432\n DynamicForward 1080\nHost a\n RemoteForward 9000 localhost:22\n LocalForward 7070 [::1]:22\n"
        self.assertEqual(self.check(config), 1)

    def test_every_forward_form(self):
        config = (
            "Host a\n LocalForward 8080 localhost:80\n LocalForward 127.0.0.1:8081 db:5432\n LocalForward [::1]:8082 [::1]:22\n"
            " LocalForward localhost:8083 localhost:80\n LocalForward :8084 h:1\n LocalForward *:8085 h:1\n"
            " RemoteForward 9000 localhost:22\n RemoteForward 9001\n RemoteForward 127.0.0.1:9002 h:1\n RemoteForward [::1]:9003\n"
            " DynamicForward 1080\n DynamicForward 127.0.0.1:1081\n DynamicForward [::1]:1082\n DynamicForward localhost:1083\n"
        )
        self.assertEqual(self.check(config), 1)

    def test_exact_duplicates_collapse(self):
        self.assertEqual(self.check("Host a\n LocalForward 8080 h:1\nHost *\n LocalForward 8080 h:1\n LocalForward 8080 h:2\n LocalForward 8080 h:1\n"), 1)
        self.assertEqual(self.check("Host a\n LocalForward 8080 h:1\n LocalForward 8080 [h]:1\n DynamicForward 8080\n DynamicForward 8080\n"), 1)
        self.assertEqual(self.check("Host a\n RemoteForward 9001\n RemoteForward 9001\n RemoteForward 9001 h:1\n"), 1)

    def test_clear_all_forwardings_in_both_orders(self):
        for first in ("ClearAllForwardings yes", "ClearAllForwardings no", "LocalForward 1 h:1"):
            for second in ("ClearAllForwardings yes", "ClearAllForwardings no", "LocalForward 2 h:2"):
                self.assertEqual(self.check("Host a\n %s\n %s\n" % (first, second)), 1)
                self.assertEqual(self.check("Host a\n %s\nHost *\n %s\n" % (first, second)), 1)
                self.assertEqual(self.check("Host *\n %s\nHost a\n %s\n LocalForward 3 h:3\n" % (first, second)), 1)

    def test_clear_all_forwardings_spellings(self):
        for value in ("yes", "YES", "true", "True", "no", "false"):
            self.assertEqual(self.check("Host a\n LocalForward 1 h:1\n ClearAllForwardings %s\n" % value), 1)

    def test_forwards_through_include_and_wildcards(self):
        files = {"extra": "LocalForward 2 h:2\nDynamicForward 1081\n", "conf.d/10": "Host web*\n LocalForward 3 h:3\n"}
        config = "LocalForward 1 h:1\nHost web1\n Include extra\n LocalForward 4 h:4\nInclude conf.d/*\nHost web2 other\n RemoteForward 5 h:5\n"
        self.assertEqual(self.check(config, files), 3)

    def test_forwards_in_a_block_that_does_not_apply(self):
        self.assertEqual(self.check("Host b\n LocalForward 1 h:1\nHost a\n LocalForward 2 h:2\nHost !a *\n LocalForward 3 h:3\n"), 2)

    def test_a_bad_forward_line_makes_ssh_reject_the_whole_config(self):
        for line in ("LocalForward 1", "LocalForward 1 h:1 x", "RemoteForward", "DynamicForward 1 x", "ClearAllForwardings maybe"):
            self.assertIsNone(self.check("Host a\n %s\n" % line), line)

    def test_a_match_block_with_forwards_is_flagged_uncertain(self):
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_tree(home, "Host a\n LocalForward 1 h:1\nMatch all\n LocalForward 2 h:2\n", None)
            host = sshconfig.load(ssh_dir=ssh_dir)["hosts"][0]
            lists = ssh_effective_lists(home, "a")
        self.assertTrue(host["forwardsUncertain"])
        self.assertEqual(lists["localforward"], ["1 [h]:1", "2 [h]:2"])
        self.assertEqual(dash_g_forwards(host)["localforward"], ["1 [h]:1"])


    def uncertain_host(self, config, files, alias, extra_env=None):
        """The parsed host and the ``ssh -G`` lists of a config whose include we cannot follow."""
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_tree(home, config, files)
            extra_env = {key: value.replace("@DIR@", ssh_dir) for key, value in (extra_env or {}).items()}
            host = next(h for h in sshconfig.load(ssh_dir=ssh_dir)["hosts"] if h["alias"] == alias)
            return host, ssh_effective_lists(home, alias, extra_env)

    def test_an_include_with_a_variable_hides_a_forward_and_flags_the_host(self):
        config = "Host web\n LocalForward 8080 h:80\nInclude ${OMX_EXTRA}\n"
        host, lists = self.uncertain_host(config, {"extra": "RemoteForward 2222 localhost:22\n"}, "web", {"OMX_EXTRA": "@DIR@/extra"})
        self.assertEqual(len(lists["remoteforward"]), 1)
        self.assertEqual([f["kind"] for f in host["forwards"]], ["L"])
        self.assertTrue(host["forwardsUncertain"] and host["noProbe"])

    def test_an_include_chain_past_the_depth_limit_hides_a_forward_and_flags_the_host(self):
        files = {"f%d" % i: "Include f%d\n" % (i + 1) for i in range(1, 7)}
        files["f7"] = "RemoteForward 2222 localhost:22\n"
        host, lists = self.uncertain_host("Host web\n LocalForward 8080 h:80\nInclude f1\n", files, "web")
        self.assertEqual(len(lists["remoteforward"]), 1)
        self.assertEqual([f["kind"] for f in host["forwards"]], ["L"])
        self.assertTrue(host["forwardsUncertain"] and host["noProbe"])


class MatchTests(unittest.TestCase):

    def parse(self, text):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write(text)
            return {h["alias"]: h for h in sshconfig.load(ssh_dir=d)["hosts"]}

    def test_match_that_can_reroute_blocks_probing_for_every_host(self):
        for option in ("ProxyJump bastion", "ProxyCommand nc %h %p", "HostName elsewhere", "Port 2222"):
            hosts = self.parse("Host a\nHost b\nMatch host a\n %s\n" % option)
            self.assertTrue(all(h["noProbe"] for h in hosts.values()), option)

    def test_match_that_cannot_reroute_is_harmless(self):
        hosts = self.parse("Host a\nMatch host a\n User x\n ForwardAgent yes\n")
        self.assertFalse(hosts["a"]["noProbe"])
        self.assertEqual(hosts["a"]["user"], "")

    def test_a_block_opened_inside_a_match_include_is_conditional_too(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write("Host a\nMatch host a\n Include extra\n")
            with open(os.path.join(d, "extra"), "w") as fh:
                fh.write("Host a\n ProxyJump bastion\n")
            host = sshconfig.load(ssh_dir=d)["hosts"][0]
        self.assertTrue(host["noProbe"])

    def test_no_match_no_flag(self):
        self.assertFalse(self.parse("Host a\n")["a"]["noProbe"])


@unittest.skipUnless(SSH, "ssh is not installed")
class FuzzTests(DifferentialCase):

    PATTERNS = ["a", "b", "c", "d", "*", "a*", "?", "!b", "!a", "*c", "c*", "!d", "??"]
    OPTIONS = [
        "HostName h1",
        "HostName h2.example",
        "HostName %h.corp",
        "User u1",
        "User u2",
        "Port 2201",
        "Port 2202",
        "ProxyJump j1",
        "ProxyJump j2",
        "ProxyJump none",
        "ProxyCommand nc %h %p",
        "ProxyCommand none",
    ]

    def random_config(self, rng, allow_include):
        lines = []
        for _ in range(rng.randint(2, 9)):
            roll = rng.random()
            if roll < 0.45:
                lines.append("Host " + " ".join(rng.sample(self.PATTERNS, rng.randint(1, 3))))
            elif allow_include and roll < 0.55:
                lines.append("Include " + rng.choice(["x1", "x2"]))
            else:
                lines.append(" " + rng.choice(self.OPTIONS))
        return "\n".join(lines) + "\n"

    def test_random_configs_agree_with_ssh(self):
        rng = random.Random(20261124)
        compared = rejected = 0
        for _ in range(250):
            config = self.random_config(rng, allow_include=True)
            files = {"x1": self.random_config(rng, False), "x2": self.random_config(rng, False)}
            config = "Host a b c d\n" + config if rng.random() < 0.5 else config + "Host a\nHost c\n"
            n = self.check(config, files)
            if n is None:
                rejected += 1
            else:
                compared += n
        self.assertGreater(compared, 400)
        self.assertLess(rejected, 25)


@unittest.skipUnless(SSH, "ssh is not installed")
class ForwardFuzzTests(DifferentialCase):

    OPTIONS = [
        "LocalForward 8080 localhost:80",
        "LocalForward 8080 db:5432",
        "LocalForward 127.0.0.1:8081 localhost:80",
        "LocalForward [::1]:8082 [::1]:22",
        "LocalForward localhost:8083 db:5432",
        "LocalForward 8083 [::1]:22",
        "RemoteForward 9000 localhost:22",
        "RemoteForward 9001",
        "DynamicForward 1080",
        "DynamicForward 127.0.0.1:1081",
        "ClearAllForwardings yes",
        "ClearAllForwardings no",
        "User u1",
    ]

    def random_config(self, rng, allow_include):
        """A random config of Host lines and forwarding options, with an Include of x1 or x2 when allowed."""
        lines = []
        for _ in range(rng.randint(3, 12)):
            roll = rng.random()
            if roll < 0.35:
                lines.append("Host " + " ".join(rng.sample(FuzzTests.PATTERNS, rng.randint(1, 3))))
            elif allow_include and roll < 0.42:
                lines.append("Include " + rng.choice(["x1", "x2"]))
            else:
                lines.append(" " + rng.choice(self.OPTIONS))
        return "\n".join(lines) + "\n"

    def test_random_forwards_agree_with_ssh(self):
        rng = random.Random(20261125)
        compared = rejected = 0
        for _ in range(150):
            config = self.random_config(rng, allow_include=True)
            files = {"x1": self.random_config(rng, False), "x2": self.random_config(rng, False)}
            config = "Host a b c d\n" + config if rng.random() < 0.5 else config + "Host a\nHost c\n"
            n = self.check(config, files)
            if n is None:
                rejected += 1
                continue
            compared += n
        self.assertGreater(compared, 300)
        self.assertEqual(rejected, 0)
        self.assertGreater(self.forwarded, 150)
        self.assertGreater(self.cleared, 20)


def write_managed(home, config, hosts):
    """Write config and a rendered managed file for hosts under home/.ssh and return the ssh directory."""
    ssh_dir = write_tree(home, config, {"omassh.config": hostform.render(hosts)})
    return ssh_dir


def dash_g_text(home, path, alias):
    """Raw ``ssh -G`` output for alias read from the config at path, or ``None`` if ssh rejects it."""
    env = {"HOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    r = subprocess.run([SSH, "-G", "-F", path, "--", alias], env=env, capture_output=True, text=True, timeout=30)
    return r.stdout if r.returncode == 0 else None


@unittest.skipUnless(SSH, "ssh is not installed")
class ManagedFileTests(unittest.TestCase):
    def host(self, **fields):
        """A canonical host named web with the given fields."""
        host, errors = hostform.normalize({"alias": "web", **fields}, support.anything_exists)
        self.assertEqual(errors, [])
        return host

    def test_dash_g_expectations_match_ssh_for_random_hosts(self):
        hosts = support.random_hosts(random.Random(20261124), 60)
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "Include omassh.config\n", hosts)
            for host in hosts:
                out = dash_g_text(home, os.path.join(ssh_dir, "omassh.config"), host["alias"])
                self.assertIsNotNone(out, host)
                self.assertEqual(hostform.diff_g(hostform.dash_g(host["alias"], host), out), "", host)

    def test_dash_g_expectations_match_ssh_for_unusual_spellings(self):
        rng = random.Random(20261125)
        hosts = support.random_wild_hosts(rng, 300)
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "Include omassh.config\n", hosts)
            for host in hosts:
                out = dash_g_text(home, os.path.join(ssh_dir, "omassh.config"), host["alias"])
                self.assertIsNotNone(out, host)
                self.assertEqual(hostform.diff_g(hostform.dash_g(host["alias"], host), out), "", host)

    def test_every_forward_and_hop_form(self):
        host = self.host(
            hostname="WEB.Example.com",
            user="admin",
            port="2222",
            proxyJump="bastion,admin@jump.example.com:2200,[2001:db8::1],u@[2001:db8::2]:22",
            identityFile="~/.ssh/id_ed25519",
            forwards=[
                "L 8080 localhost:80",
                "L 127.0.0.1:8081 [::1]:80",
                "L [::1]:8082 db.example.com:5432",
                "R 9000 localhost:22",
                "R 9001",
                "R localhost:9002",
                "R [::1]:9003 h:1",
                "D 1080",
                "D localhost:1081",
                "D [::1]:1082",
            ],
        )
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "Include omassh.config\n", [host])
            out = dash_g_text(home, os.path.join(ssh_dir, "omassh.config"), "web")
            self.assertEqual(hostform.diff_g(hostform.dash_g("web", host), out), "")
            through = dash_g_text(home, os.path.join(ssh_dir, "config"), "web")
            self.assertEqual(hostform.diff_g(hostform.dash_g("web", host), through), "")

    def test_alias_case_does_not_change_the_reported_hostname(self):
        host = self.host(alias="Web")
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "Include omassh.config\n", [host])
            out = dash_g_text(home, os.path.join(ssh_dir, "omassh.config"), "Web")
        self.assertEqual(hostform.diff_g(hostform.dash_g("Web", host), out), "")
        self.assertIn("hostname web\n", out)

    def test_numeric_looking_names_are_reported_as_written(self):
        names = ["203.0.113.4", "192.0.2.5", ".".join("0000"), "255.255.255.255", "192.0.2.4.5", "9a", "a9", "0x1g", "1.2.3.", "face", "1.a"]
        hosts = [self.host(alias="h%d" % i, hostname="target.example.com", proxyJump=name, forwards=["L 1 %s:2" % name]) for i, name in enumerate(names)]
        hosts += [self.host(alias=name) for name in names] + [self.host(alias="g%d" % i, hostname=name) for i, name in enumerate(names)]
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "Include omassh.config\n", hosts)
            for host in hosts:
                out = dash_g_text(home, os.path.join(ssh_dir, "omassh.config"), host["alias"])
                self.assertEqual(hostform.diff_g(hostform.dash_g(host["alias"], host), out), "", host)

    def test_an_active_include_makes_managed_values_win(self):
        host = self.host(user="fromform", port="2201")
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "# mine\nInclude omassh.config\nHost *\n User wild\n Port 2299\n", [host])
            lists = ssh_effective_lists(home, "web")
            parsed = sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, "omassh.config"))
        self.assertEqual((lists["user"], lists["port"]), (["fromform"], ["2201"]))
        self.assertEqual(parsed["managedInclude"], "active")
        self.assertEqual({h["alias"]: h["origin"] for h in parsed["hosts"]}, {"web": "managed"})

    def test_an_include_that_is_missing_its_file_is_harmless_and_active(self):
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_tree(home, "Include omassh.config\nHost a\n", None)
            self.assertIsNotNone(ssh_effective_lists(home, "a"))
            parsed = sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, "omassh.config"))
        self.assertEqual(parsed["managedInclude"], "active")

    def test_a_late_include_lets_a_global_option_override_the_managed_value(self):
        host = self.host(user="fromform", port="2201")
        for config in ("User globaluser\nInclude omassh.config\n", "Include conf.d/*\nUser globaluser\nInclude omassh.config\n"):
            with tempfile.TemporaryDirectory() as home:
                ssh_dir = write_managed(home, config, [host])
                os.makedirs(os.path.join(ssh_dir, "conf.d"))
                lists = ssh_effective_lists(home, "web")
                parsed = sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, "omassh.config"))
            self.assertEqual(lists["user"], ["globaluser"], config)
            self.assertEqual(lists["port"], ["2201"], config)
            self.assertEqual(parsed["managedInclude"], "late", config)

    def test_an_include_after_another_include_is_late_only_when_that_include_brings_a_directive(self):
        host = self.host(user="fromform")
        with tempfile.TemporaryDirectory() as home:
            ssh_dir = write_managed(home, "Include other\nInclude omassh.config\n", [host])
            with open(os.path.join(ssh_dir, "other"), "w") as fh:
                fh.write("User fromother\n")
            lists = ssh_effective_lists(home, "web")
            parsed = sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, "omassh.config"))
        self.assertEqual(lists["user"], ["fromother"])
        self.assertEqual(parsed["managedInclude"], "late")

    def test_a_scoped_include_does_not_apply_to_the_managed_host(self):
        host = self.host(hostname="managed.example.com", user="fromform", port="2201")
        for config in ("Host other\n Include omassh.config\n", "Match all\n Include omassh.config\n", "Host *\n Include omassh.config\n"):
            with tempfile.TemporaryDirectory() as home:
                ssh_dir = write_managed(home, config, [host])
                lists = ssh_effective_lists(home, "web")
                parsed = sshconfig.load(ssh_dir=ssh_dir, managed_path=os.path.join(ssh_dir, "omassh.config"))
            self.assertEqual(parsed["managedInclude"], "scoped", config)
            if config.startswith("Host other"):
                self.assertEqual((lists["hostname"], lists["port"]), (["web"], ["22"]), config)
                self.assertNotEqual(lists["user"], ["fromform"], config)


class LineSeparatorTests(DifferentialCase):
    SEPARATORS = ["\x85", "\u2028", "\u2029", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e"]

    def test_only_a_newline_ends_a_line_for_ssh_and_for_us(self):
        for separator in self.SEPARATORS:
            config = "# note%sHost decoy\n# note%sUser decoy\nHost web\n HostName real.example.com\n" % (separator, separator)
            with tempfile.TemporaryDirectory() as home:
                ssh_dir = write_tree(home, config, None)
                self.assertEqual([h["alias"] for h in sshconfig.load(ssh_dir=ssh_dir)["hosts"]], ["web"], repr(separator))
                self.assertEqual(ssh_effective(home, "web")["user"], self.default_user, repr(separator))
            self.assertEqual(self.check(config), 1, repr(separator))

    def test_a_trailing_carriage_return_is_part_of_the_line_ending_for_both(self):
        self.assertEqual(self.check("Host web\r\n HostName real.example.com\r\n User admin\r\n"), 1)
        self.assertEqual(self.check("Host web\r\n HostName real.example.com\r\r\n"), 1)

    def test_a_line_with_only_a_separator_is_blank_for_both(self):
        for separator in ("\r", " ", "\t"):
            self.assertEqual(self.check("Host web\n%s\n HostName real.example.com\n" % separator), 1, repr(separator))


@unittest.skipUnless(SSH, "ssh is not installed")
class InsertionTests(DifferentialCase):

    PATTERNS = ["a", "b", "c", "d", "*", "a*", "?", "!b", "*c", "c*", "m?", "m*"]
    OPTIONS = ["HostName h1", "HostName %h.corp", "User u1", "User u2", "Port 2201", "Port 2202", "ProxyJump j1", "ProxyJump none", "IdentityFile ~/.ssh/other"]
    PLAIN = ["a", "b", "c", "d", "zz"]

    def random_main(self, rng):
        """A random main config with leading comments, global options, Host blocks and Includes, in a random line-ending style."""
        lines = rng.choice([[], ["# my config"], ["", "# x", ""], ["   # indented", "\t"], ["# odd\x0bseparator", "# a\x0c b"], ["# carriage\rreturn"]])
        for _ in range(rng.randint(2, 10)):
            roll = rng.random()
            if roll < 0.4:
                lines.append("Host " + " ".join(rng.sample(self.PATTERNS, rng.randint(1, 3))))
            elif roll < 0.5:
                lines.append("Include " + rng.choice(["x1", "x2"]))
            else:
                lines.append(" " + rng.choice(self.OPTIONS))
        eol = rng.choice(["\n", "\n", "\r\n"])
        text = eol.join(lines) + eol
        return text[: -len(eol)] if rng.random() < 0.2 else text

    def managed_hosts(self, rng, count):
        """Hosts named m0, m1, ... that set everything the main config could also set."""
        hosts = []
        for index in range(count):
            raw = {
                "alias": "m%d" % index,
                "hostname": "managed%d.example.com" % index,
                "user": "mu%d" % index,
                "port": str(2300 + index),
                "proxyJump": "jump%d,u@[2001:db8::%x]:22" % (index, index + 1),
                "identityFile": "~/.ssh/id_m",
                "forwards": rng.sample(["L 8080 localhost:80", "R 9000", "D 1080", "L [::1]:8081 db:5432"], rng.randint(0, 3)),
            }
            host, errors = hostform.normalize(raw, support.anything_exists)
            self.assertEqual(errors, [])
            hosts.append(host)
        return hosts

    def test_the_inserted_include_changes_no_other_host_and_managed_values_win(self):
        rng = random.Random(20261126)
        compared = managed = 0
        for _ in range(180):
            hosts = self.managed_hosts(rng, rng.randint(1, 3))
            files = {"x1": " User fromx1\nHost a\n Port 2203\n", "x2": "Host d\n HostName fromx2\n", "omassh.config": hostform.render(hosts)}
            with tempfile.TemporaryDirectory() as home:
                main = self.random_main(rng)
                ssh_dir = write_tree(home, main, files)
                os.chmod(ssh_dir, 0o700)
                config = os.path.join(ssh_dir, "config")
                before = {alias: dash_g_text(home, config, alias) for alias in self.PLAIN}
                if None in before.values():
                    continue
                with mock.patch.dict(os.environ, {"HOME": home}):
                    shown = mainconfig.preview()
                    self.assertEqual(shown["refusal"], "")
                    result = mainconfig.apply(shown["expect"])
                self.assertEqual((result["ok"], result["include"]), (True, "active"), main)
                with open(config) as fh:
                    text = fh.read()
                self.assertEqual(sum(line.strip() == "Include ~/.ssh/omassh.config" for line in text.splitlines()), 1)
                for alias in self.PLAIN:
                    self.assertEqual(dash_g_text(home, config, alias), before[alias], (alias, text))
                    compared += 1
                for host in hosts:
                    out = dash_g_text(home, config, host["alias"])
                    self.assertEqual(hostform.diff_g(hostform.dash_g(host["alias"], host), out), "", (host, text))
                    managed += 1
        self.assertGreater(compared, 400)
        self.assertGreater(managed, 100)


class MatcherTests(unittest.TestCase):
    def setUp(self):
        self.ctx = sshconfig._Context("/nonexistent")

    def match(self, pattern, text):
        return sshconfig._wild_match(pattern, text, self.ctx)

    def test_basics(self):
        for pattern, text, expected in [
            ("a", "a", True),
            ("a", "b", False),
            ("*", "anything", True),
            ("*", "", True),
            ("?", "x", True),
            ("?", "", False),
            ("a*", "abc", True),
            ("*c", "abc", True),
            ("a*c", "abc", True),
            ("a*c", "ab", False),
            ("a?c", "abc", True),
            ("a?c", "ac", False),
            ("*a*b*", "xxaxxbxx", True),
            ("A", "a", False),
            ("[ab]", "a", False),
            ("a.c", "abc", False),
        ]:
            self.assertEqual(self.match(pattern, text), expected, (pattern, text))

    def test_hostile_pattern_is_not_exponential(self):
        import time

        pattern = "*a" * 40 + "*b"
        start = time.monotonic()
        self.assertFalse(self.match(pattern, "a" * 128))
        self.assertLess(time.monotonic() - start, 1.0)

    def test_an_exhausted_work_budget_fails_safe(self):
        config = "Host a\n HostName h\nHost b\nHost *\n ProxyJump bastion\n" + "".join("Host x%d\n User u\n" % i for i in range(30))
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write(config)
            saved = sshconfig.MAX_WORK
            sshconfig.MAX_WORK = 10
            try:
                result = sshconfig.load(ssh_dir=d)
            finally:
                sshconfig.MAX_WORK = saved
        unresolved = [h for h in result["hosts"] if h["noProbe"]]
        self.assertTrue(unresolved)
        self.assertTrue(any("too complex" in e["message"] for e in result["errors"]))

    def test_work_budget_stops_a_hostile_config(self):
        import time

        lines = ["Host target"]
        lines += ["Host " + " ".join("*a" * 12 + "*b%d" % (i * 60 + j) for j in range(60)) + "\n User u%d" % i for i in range(400)]
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config"), "w") as fh:
                fh.write("\n".join(lines) + "\n")
            start = time.monotonic()
            result = sshconfig.load(ssh_dir=d)
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 20)
        self.assertEqual([h["alias"] for h in result["hosts"]], ["target"])


if __name__ == "__main__":
    unittest.main()
