import os
import sys
import json
import hashlib
import tempfile
import unittest
import subprocess

SESSION = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "scripts", "session.sh"))


class SessionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.bin)
        self.record = os.path.join(self.tmp.name, "argv")
        self.stub("ssh", 0)
        self.stub("sftp", 0)
        self.stub("ssh-copy-id", 0)
        with open(os.path.join(self.bin, "python3"), "w") as fh:
            fh.write('#!/bin/sh\nexec "%s" "$@"\n' % sys.executable)
        os.chmod(os.path.join(self.bin, "python3"), 0o755)
        self.config_home = os.path.join(self.tmp.name, "xdg")

    def stub(self, name, status):
        path = os.path.join(self.bin, name)
        with open(path, "w") as fh:
            fh.write('#!/bin/sh\nprintf "%%s\\0" "$@" > "%s"\nexit %d\n' % (self.record, status))
        os.chmod(path, 0o755)

    def run_session(self, *args, stdin=""):
        env = {"PATH": self.bin + ":/usr/bin:/bin", "HOME": self.tmp.name, "XDG_CONFIG_HOME": self.config_home}
        return subprocess.run([SESSION, *args], input=stdin, capture_output=True, text=True, env=env, timeout=20)

    def save_commands(self, entries, mode=0o600):
        """Write the saved commands file the session script will read through the CLI."""
        directory = os.path.join(self.config_home, "omassh")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "commands.json")
        with open(path, "w") as fh:
            json.dump({"commands": entries}, fh)
        os.chmod(path, mode)
        return path

    def argv(self):
        if not os.path.exists(self.record):
            return None
        with open(self.record, "rb") as fh:
            return [a.decode() for a in fh.read().split(b"\0")[:-1]]


class SessionTests(SessionCase):
    def test_ssh_gets_double_dash_and_the_alias(self):
        r = self.run_session("ssh", "server")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.argv(), ["--", "server"])

    def test_sftp_gets_double_dash_and_the_alias(self):
        self.run_session("sftp", "web-1")
        self.assertEqual(self.argv(), ["--", "web-1"])

    def test_bad_mode_is_refused(self):
        for mode in ("", "scp", "ssh;id", "../ssh", "-o"):
            r = self.run_session(mode, "server")
            self.assertEqual(r.returncode, 64, mode)
            self.assertIsNone(self.argv())

    def test_hostile_aliases_are_refused_and_nothing_runs(self):
        marker = os.path.join(self.tmp.name, "pwned")
        for alias in (
            "-oProxyCommand=touch " + marker,
            "-J",
            "a@b",
            "server;touch " + marker,
            "$(touch %s)" % marker,
            "`touch %s`" % marker,
            "server\nweb",
            "server web",
            "",
            "server\x1b]0;x\x07",
            "a" * 129,
        ):
            r = self.run_session("ssh", alias, stdin="\n")
            self.assertEqual(r.returncode, 64, repr(alias))
            self.assertIsNone(self.argv(), repr(alias))
        self.assertFalse(os.path.exists(marker))

    def test_custom_config_is_passed_as_dash_F(self):
        cfg = os.path.join(self.tmp.name, "my_config.conf")
        open(cfg, "w").close()
        self.run_session("ssh", "server", "--config", cfg)
        self.assertEqual(self.argv(), ["-F", cfg, "--", "server"])
        self.run_session("sftp", "server", "--config", cfg)
        self.assertEqual(self.argv(), ["-F", cfg, "--", "server"])

    def test_no_config_means_no_dash_F(self):
        self.run_session("ssh", "server")
        self.assertEqual(self.argv(), ["--", "server"])

    def test_unsafe_config_paths_are_refused(self):
        real = os.path.join(self.tmp.name, "real")
        open(real, "w").close()
        spaced = os.path.join(self.tmp.name, "my config")
        open(spaced, "w").close()
        hostile = [real + suffix for suffix in ("\n", "\x1b[0m", ";id", "$(id)", "`id`", " -x", "'", '"', "|x", "&x", "*", "?", "~", "\\")]
        for bad in ["relative/config", "-oProxyCommand=x", os.path.join(self.tmp.name, "missing"), self.tmp.name, spaced] + hostile:
            r = self.run_session("ssh", "server", "--config", bad, stdin="\n")
            self.assertEqual(r.returncode, 64, repr(bad))
            self.assertIsNone(self.argv(), repr(bad))

    def test_missing_alias(self):
        self.assertEqual(self.run_session("ssh").returncode, 64)

    def test_failure_keeps_window_open_until_enter(self):
        self.stub("ssh", 255)
        r = self.run_session("ssh", "server", stdin="\n")
        self.assertEqual(r.returncode, 255)
        self.assertIn("exited with status 255", r.stdout)

    def test_success_closes_immediately(self):
        r = self.run_session("ssh", "server", stdin="")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("Press Enter", r.stdout)

    def test_title_escape_contains_only_whitelisted_text(self):
        r = self.run_session("ssh", "server")
        self.assertIn("\x1b]0;ssh server\x07", r.stdout)


class ModeTests(SessionCase):
    TMUX = "tmux new-session -A -s omassh"

    def test_tmux_runs_ssh_with_a_tty_and_no_remote_command_override(self):
        r = self.run_session("tmux", "server")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.argv(), ["-t", "-o", "RemoteCommand=none", "--", "server", self.TMUX])

    def test_tmux_keeps_config_and_forward_options_before_the_double_dash(self):
        cfg = os.path.join(self.tmp.name, "my_config.conf")
        open(cfg, "w").close()
        self.run_session("tmux", "server", "--config", cfg, "--no-forwards")
        self.assertEqual(self.argv(), ["-t", "-o", "RemoteCommand=none", "-F", cfg, "-o", "ClearAllForwardings=yes", "--", "server", self.TMUX])

    def test_copy_id_runs_ssh_copy_id_with_the_double_dash(self):
        cfg = os.path.join(self.tmp.name, "my_config.conf")
        open(cfg, "w").close()
        self.run_session("copy-id", "server")
        self.assertEqual(self.argv(), ["--", "server"])
        self.run_session("copy-id", "server", "--config", cfg)
        self.assertEqual(self.argv(), ["-F", cfg, "--", "server"])

    def test_no_forwards_adds_the_clear_option_to_every_mode(self):
        cfg = os.path.join(self.tmp.name, "c")
        open(cfg, "w").close()
        for mode in ("ssh", "sftp", "copy-id"):
            self.run_session(mode, "server", "--no-forwards")
            self.assertEqual(self.argv(), ["-o", "ClearAllForwardings=yes", "--", "server"], mode)
            self.run_session(mode, "server", "--no-forwards", "--config", cfg)
            self.assertEqual(self.argv(), ["-F", cfg, "-o", "ClearAllForwardings=yes", "--", "server"], mode)

    def test_forwards_are_left_alone_without_the_flag(self):
        for mode in ("ssh", "sftp", "tmux", "copy-id"):
            self.run_session(mode, "server")
            self.assertNotIn("ClearAllForwardings=yes", self.argv(), mode)

    def test_the_title_names_the_mode_and_host(self):
        self.assertIn("\x1b]0;tmux server\x07", self.run_session("tmux", "server").stdout)

    def test_copy_id_waits_for_enter_even_on_success(self):
        r = self.run_session("copy-id", "server", stdin="\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn("copy-id exited with status 0. Press Enter to close.", r.stdout)
        self.stub("ssh-copy-id", 1)
        r = self.run_session("copy-id", "server", stdin="\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("copy-id exited with status 1", r.stdout)

    def test_ssh_sftp_and_tmux_close_at_once_on_success(self):
        for mode in ("ssh", "sftp", "tmux"):
            r = self.run_session(mode, "server", stdin="")
            self.assertEqual(r.returncode, 0, mode)
            self.assertNotIn("Press Enter", r.stdout, mode)

    def test_failure_of_tmux_keeps_the_window_open(self):
        self.stub("ssh", 3)
        r = self.run_session("tmux", "server", stdin="\n")
        self.assertEqual(r.returncode, 3)
        self.assertIn("tmux exited with status 3", r.stdout)


class RunTests(SessionCase):
    def save(self, name="Disk", command="df -h", **extra):
        """Save one command and return its id."""
        self.save_commands([dict(name=name, command=command, **extra)])
        return hashlib.sha256((name + "\0" + command).encode()).hexdigest()[:16]

    def test_the_command_reaches_ssh_as_one_argument(self):
        cid = self.save()
        r = self.run_session("run", "server", "--command", cid)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.argv(), ["-t", "-o", "RemoteCommand=none", "--", "server", "df -h"])
        self.assertIn("df -h\n", r.stdout)

    def test_the_window_waits_for_enter_even_when_the_command_succeeds(self):
        cid = self.save()
        r = self.run_session("run", "server", "--command", cid, stdin="\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn("run exited with status 0. Press Enter to close.", r.stdout)
        self.stub("ssh", 7)
        r = self.run_session("run", "server", "--command", cid, stdin="\n")
        self.assertEqual(r.returncode, 7)
        self.assertIn("run exited with status 7", r.stdout)

    def test_options_are_placed_before_the_double_dash(self):
        cid = self.save()
        cfg = os.path.join(self.tmp.name, "my_config.conf")
        open(cfg, "w").close()
        self.run_session("run", "server", "--command", cid, "--config", cfg, "--no-forwards")
        self.assertEqual(self.argv(), ["-t", "-o", "RemoteCommand=none", "-F", cfg, "-o", "ClearAllForwardings=yes", "--", "server", "df -h"])

    def test_shell_syntax_in_the_command_is_not_expanded_locally(self):
        marker = os.path.join(self.tmp.name, "pwned")
        text = "$(touch %s); echo x `touch %s` && *" % (marker, marker)
        cid = self.save(command=text)
        r = self.run_session("run", "server", "--command", cid)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.argv(), ["-t", "-o", "RemoteCommand=none", "--", "server", text])
        self.assertFalse(os.path.exists(marker))

    def test_spaces_quotes_and_non_ascii_survive_intact(self):
        text = "echo  'a  b'   \"c\" caf\u00e9 \u65e5\u672c  "
        cid = self.save(command=text)
        self.run_session("run", "server", "--command", cid)
        self.assertEqual(self.argv()[-1], text)

    def test_a_leading_dash_command_stays_after_the_double_dash(self):
        cid = self.save(command="-oProxyCommand=touch x")
        self.run_session("run", "server", "--command", cid)
        argv = self.argv()
        self.assertEqual(argv[argv.index("--") + 1 :], ["server", "-oProxyCommand=touch x"])

    def test_an_unknown_id_is_refused_and_nothing_runs(self):
        self.save()
        r = self.run_session("run", "server", "--command", "0" * 16, stdin="\n")
        self.assertEqual(r.returncode, 64)
        self.assertIsNone(self.argv())

    def test_a_missing_commands_file_is_refused(self):
        r = self.run_session("run", "server", "--command", "0" * 16, stdin="\n")
        self.assertEqual(r.returncode, 64)
        self.assertIsNone(self.argv())

    def test_an_insecure_commands_file_is_refused(self):
        cid = self.save()
        self.save_commands([{"name": "Disk", "command": "df -h"}], mode=0o666)
        r = self.run_session("run", "server", "--command", cid, stdin="\n")
        self.assertEqual(r.returncode, 64)
        self.assertIsNone(self.argv())

    def test_a_command_restricted_to_other_hosts_is_refused(self):
        cid = self.save(hosts=["web"])
        self.assertEqual(self.run_session("run", "server", "--command", cid, stdin="\n").returncode, 64)
        self.assertIsNone(self.argv())
        self.assertEqual(self.run_session("run", "web", "--command", cid).returncode, 0)
        self.assertEqual(self.argv()[-2:], ["web", "df -h"])

    def test_an_edited_command_is_refused_under_the_old_id(self):
        cid = self.save()
        self.save(command="rm -rf ~")
        r = self.run_session("run", "server", "--command", cid, stdin="\n")
        self.assertEqual(r.returncode, 64)
        self.assertIsNone(self.argv())

    def test_malformed_ids_are_refused_before_anything_runs(self):
        cid = self.save()
        for bad in ("", cid.upper(), cid[:15], cid + "0", "../x", "$(id)", cid + "\n", "-oX=y", "g" * 16):
            r = self.run_session("run", "server", "--command", bad, stdin="\n")
            self.assertEqual(r.returncode, 64, repr(bad))
            self.assertIsNone(self.argv(), repr(bad))

    def test_run_without_an_id_is_refused(self):
        self.save()
        self.assertEqual(self.run_session("run", "server", stdin="\n").returncode, 64)
        self.assertIsNone(self.argv())

    def test_an_id_is_refused_for_the_other_modes(self):
        cid = self.save()
        for mode in ("ssh", "sftp", "tmux", "copy-id"):
            self.assertEqual(self.run_session(mode, "server", "--command", cid, stdin="\n").returncode, 64, mode)
            self.assertIsNone(self.argv(), mode)


class OptionTests(SessionCase):
    def test_unknown_options_and_stray_words_are_refused(self):
        for extra in (["--bogus"], ["-F", "x"], ["config"], ["--config=/x"], ["--no-forwards=1"], ["--", "x"], [""]):
            r = self.run_session("ssh", "server", *extra, stdin="\n")
            self.assertEqual(r.returncode, 64, extra)
            self.assertIsNone(self.argv(), extra)

    def test_an_option_missing_its_value_is_refused_instead_of_looping(self):
        for extra in (["--config"], ["--command"], ["--no-forwards", "--config"]):
            r = self.run_session("ssh", "server", *extra, stdin="\n")
            self.assertEqual(r.returncode, 64, extra)
            self.assertIsNone(self.argv(), extra)

    def test_the_old_positional_config_form_is_gone(self):
        cfg = os.path.join(self.tmp.name, "my_config.conf")
        open(cfg, "w").close()
        self.assertEqual(self.run_session("ssh", "server", cfg, stdin="\n").returncode, 64)
        self.assertIsNone(self.argv())

    def test_too_few_arguments_are_refused(self):
        for args in ((), ("ssh",)):
            self.assertEqual(self.run_session(*args, stdin="\n").returncode, 64, args)

    def test_a_refusal_does_not_echo_the_offending_text(self):
        for extra in (["--bogus"], ["\x1b]0;x\x07"]):
            r = self.run_session("ssh", "server", *extra, stdin="\n")
            self.assertNotIn(extra[0], r.stderr)
            self.assertNotIn(extra[0], r.stdout)

    def test_no_mode_accepts_a_hostile_alias(self):
        for mode in ("sftp", "tmux", "run", "copy-id"):
            r = self.run_session(mode, "-oProxyCommand=x", "--command", "0" * 16, stdin="\n")
            self.assertEqual(r.returncode, 64, mode)
            self.assertIsNone(self.argv(), mode)


if __name__ == "__main__":
    unittest.main()
