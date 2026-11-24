import os
import re
import sys
import json
import stat
import shutil
import unittest
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import hostform

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def files(*suffixes, skip=(".git", "tests", "__pycache__")):
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if name.endswith(suffixes):
                yield os.path.join(dirpath, name)


def blocks(source, type_name):
    """Yield the body of every ``<type_name> { ... }`` block (brace matched)."""
    for match in re.finditer(r"\b%s\s*\{" % re.escape(type_name), source):
        depth, i = 1, match.end()
        while i < len(source) and depth:
            depth += {"{": 1, "}": -1}.get(source[i], 0)
            i += 1
        yield source[match.end() : i - 1]


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(read("manifest.json"))

    def test_required_fields(self):
        for key in ("schemaVersion", "id", "name", "version", "author", "license", "description", "kinds", "entryPoints"):
            self.assertIn(key, self.manifest)

    def test_entry_points_exist_and_are_safe(self):
        for path in self.manifest["entryPoints"].values():
            self.assertFalse(os.path.isabs(path))
            self.assertNotIn("..", path)
            self.assertTrue(os.path.isfile(os.path.join(ROOT, path)), path)

    def test_version_matches_changelog(self):
        first = re.search(r"^## (\d+\.\d+\.\d+)", read("CHANGELOG.md"), re.M).group(1)
        self.assertEqual(self.manifest["version"], first)

    def test_no_symlinks_anywhere(self):
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in dirnames + filenames:
                self.assertFalse(os.path.islink(os.path.join(dirpath, name)), name)

    def test_executables(self):
        for rel in ("omassh", os.path.join("scripts", "session.sh")):
            self.assertTrue(os.stat(os.path.join(ROOT, rel)).st_mode & stat.S_IXUSR, rel)

    def test_no_bytecode_anywhere(self):
        found = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            found += [os.path.join(dirpath, n) for n in dirnames + filenames if n == "__pycache__" or n.endswith(".pyc")]
        self.assertEqual(found, [])


class I18nTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(read("i18n", "en.json"))

    def test_plurals_have_one_and_other(self):
        for key, value in self.catalog.items():
            if isinstance(value, dict):
                self.assertIn("one", value, key)
                self.assertIn("other", value, key)

    def test_every_used_key_exists(self):
        used = set()
        for path in files(".qml"):
            with open(path, encoding="utf-8") as fh:
                used |= set(re.findall(r'strings\.tn?\(\s*"([^"]+)"', fh.read()))
        self.assertTrue(used)
        self.assertEqual(sorted(used - set(self.catalog)), [])

    def test_no_unused_keys(self):
        source = "".join(read(os.path.relpath(p, ROOT)) for p in files(".qml"))
        unused = [k for k in self.catalog if '"%s"' % k not in source]
        self.assertEqual(unused, [], "remove or use these strings")


class LocaleTests(unittest.TestCase):

    REQUIRED = {"en": {"one", "other"}, "es": {"one", "other"}, "ja": {"other"}}
    PLURAL_JS = "/usr/share/omarchy/shell/Commons/Plural.js"
    TOKENS = (
        "openssh",
        "sftp",
        "ssh",
        "tmux",
        "ssh-copy-id",
        "vs code",
        "ssh-agent",
        "localforward",
        "remoteforward",
        "dynamicforward",
        "clearallforwardings",
        "omassh.config",
        "proxyjump",
        "identityfile",
        "hostname",
        "include",
    )

    @classmethod
    def setUpClass(cls):
        cls.catalogs = {}
        for name in sorted(os.listdir(os.path.join(ROOT, "i18n"))):
            assert name.endswith(".json"), name
            cls.catalogs[name[: -len(".json")]] = json.loads(read("i18n", name))
        cls.english = cls.catalogs["en"]

    def forms(self, value):
        return list(value.values()) if isinstance(value, dict) else [value]

    def test_the_shipped_languages_are_the_ones_we_know_the_plural_rules_of(self):
        self.assertEqual(set(self.catalogs), set(self.REQUIRED))

    def test_same_keys_as_english(self):
        for code, catalog in self.catalogs.items():
            self.assertEqual(sorted(catalog), sorted(self.english), code)

    def test_plural_entries_have_exactly_the_categories_of_the_language(self):
        for code, catalog in self.catalogs.items():
            for key, value in catalog.items():
                if isinstance(self.english[key], dict):
                    self.assertIsInstance(value, dict, (code, key))
                    self.assertEqual(set(value), self.REQUIRED[code], (code, key))
                else:
                    self.assertIsInstance(value, str, (code, key))

    def test_no_empty_strings(self):
        for code, catalog in self.catalogs.items():
            for key, value in catalog.items():
                for text in self.forms(value):
                    self.assertTrue(text.strip(), (code, key))

    def test_placeholders_are_kept(self):
        for code, catalog in self.catalogs.items():
            for key, value in catalog.items():
                expected = sorted(re.findall(r"%\d", "".join(self.forms(self.english[key])[-1:])))
                for text in self.forms(value):
                    self.assertEqual(sorted(re.findall(r"%\d", text)), expected, (code, key, text))

    def test_command_and_product_names_are_not_translated(self):
        for code, catalog in self.catalogs.items():
            for key, value in catalog.items():
                english = " ".join(self.forms(self.english[key])).lower()
                for token in self.TOKENS:
                    if token in english:
                        for text in self.forms(value):
                            self.assertIn(token, text.lower(), (code, key, token))

    def test_keyboard_shortcuts_in_every_hint_are_the_same_in_every_language(self):
        def keys(text):
            return [segment.strip().split(" ")[0] for segment in text.split(" \u00b7 ")]

        hints = [key for key in self.english if key.endswith(".keys")]
        self.assertGreaterEqual(len(hints), 4)
        for key in hints:
            for code, catalog in self.catalogs.items():
                self.assertEqual(keys(catalog[key]), keys(self.english[key]), (code, key))

    def test_the_host_editor_keys_are_in_the_hints(self):
        def keys(text):
            return [segment.strip().split(" ")[0] for segment in text.split(" \u00b7 ")]

        for code, catalog in self.catalogs.items():
            self.assertLessEqual({"n", "m", "d"}, set(keys(catalog["panel.keys"])), code)
            self.assertLessEqual({"m", "d"}, set(keys(catalog["actions.keys"])), code)
            self.assertEqual(keys(catalog["editor.keys"]), ["Tab", "Shift+Tab", "\u21b5", "Esc"], code)
            self.assertEqual(keys(catalog["setup.keys"]), ["\u21b5", "Esc"], code)

    @unittest.skipUnless(shutil.which("node") and os.path.exists(PLURAL_JS), "needs node and Omarchy's Plural.js")
    def test_plural_categories_match_omarchys_own_rules(self):
        script = "const P=require(%r);console.log(JSON.stringify(Object.fromEntries(%s.map(c=>[c,P.categories(c)]))))" % (
            self.PLURAL_JS,
            json.dumps(sorted(self.REQUIRED)),
        )
        out = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        truth = {code: set(cats) for code, cats in json.loads(out).items()}
        self.assertEqual(truth, self.REQUIRED)


class QmlSafetyTests(unittest.TestCase):

    def test_every_text_element_is_plain_text(self):
        checked = 0
        for path in files(".qml"):
            source = read(os.path.relpath(path, ROOT))
            for body in blocks(source, "Text"):
                checked += 1
                self.assertIn("textFormat: Text.PlainText", body, "%s: a Text without PlainText" % os.path.basename(path))
        self.assertGreater(checked, 10)

    def test_no_shell_strings_in_qml(self):
        for path in files(".qml"):
            source = read(os.path.relpath(path, ROOT))
            for pattern in (r'"(ba|z|da)?sh"\s*,\s*"-c"', r"\bsh -c\b", r"\bbash -c\b", r"\beval\b", r"Qt\.openUrlExternally", r"XMLHttpRequest", r"\bfetch\("):
                self.assertIsNone(re.search(pattern, source), "%s: %s" % (os.path.basename(path), pattern))

    def test_the_only_timer_is_the_guard_that_runs_while_an_editor_command_is_pending(self):
        found = []
        for path in files(".qml"):
            source = read(os.path.relpath(path, ROOT))
            for body in blocks(source, "Timer"):
                found.append((os.path.basename(path), body))
        self.assertEqual(len(found), 1)
        name, body = found[0]
        self.assertEqual(name, "Panel.qml")
        self.assertIn("id: pendingGuard", body)
        self.assertIn("running: root.savePending || root.deletePending || root.includeMode !== \"\"", body)
        self.assertEqual(len(re.findall(r"\brunning:", body)), 1)
        self.assertIn("onTriggered: root.settlePending()", body)
        self.assertNotIn("triggeredOnStart", body)

    def test_qml_never_runs_tools_or_handles_command_text(self):
        launches = r'(?:execDetached\(\s*\[|command:\s*\[)\s*"(?:code|uwsm-app|wl-copy|ssh-copy-id|ssh|sftp|tmux)"'
        for path in files(".qml"):
            source = read(os.path.relpath(path, ROOT))
            self.assertIsNone(re.search(launches, source), os.path.basename(path))
            for word in ("wl-copy", "clipboardText", "command-text"):
                self.assertNotIn(word, source, "%s: %s" % (os.path.basename(path), word))

    def test_the_alias_always_follows_a_double_dash(self):
        lines = [line for line in read("Panel.qml").splitlines() if "host.alias" in line and ("root.cli" in line or "argv" in line)]
        self.assertGreaterEqual(len(lines), 6)
        for line in lines:
            self.assertIn('"--", host.alias', line)

    def test_per_host_objects_are_only_indexed_through_alias_key(self):
        source = read("Panel.qml")
        self.assertIn('return "h:" + alias', source)
        indexed = 0
        for name in ("reach", "tunnelMap", "tunnelErrors"):
            for index in re.findall(r"\b%s\[([^\]]*)\]" % name, source):
                indexed += 1
                self.assertTrue(index == "key" or index.startswith("root.aliasKey("), (name, index))
        for index in re.findall(r"(?<=\w)\[([^\]]*alias[^\]]*)\]", source):
            self.assertTrue(index.startswith("root.aliasKey(") or index == "alias", index)
        self.assertGreater(indexed, 5)

    def test_every_process_that_can_fail_to_start_is_settled(self):
        source = read("Panel.qml")
        for name in ("tunnelProc", "commandsEditProc", "hostSaveProc", "hostDeleteProc", "includeProc"):
            body = next(b for b in blocks(source, "Process") if "id: %s" % name in b)
            self.assertIn("onRunningChanged: if (!running) Qt.callLater(", body, name)

    def test_only_the_save_process_has_a_stdin_and_nothing_else_writes(self):
        sources = {os.path.basename(p): read(os.path.relpath(p, ROOT)) for p in files(".qml")}
        self.assertEqual(sum(s.count("stdinEnabled") for s in sources.values()), 1)
        self.assertEqual(sum(len(re.findall(r"\bwrite\(", s)) for s in sources.values()), 1)
        body = next(b for b in blocks(sources["Panel.qml"], "Process") if "id: hostSaveProc" in b)
        self.assertIn("stdinEnabled: true", body)
        self.assertIn('write(payload + "\\n")', body)
        self.assertIn('command: [root.cli, "host", "save"]', body)
        self.assertEqual(sources["Panel.qml"].count("hostSaveProc.payload = JSON.stringify("), 1)
        for name, source in sources.items():
            for pattern in (r"FileView", r"[\"']-G[\"']", r"\bsetenv\b", r"writeFile"):
                self.assertIsNone(re.search(pattern, source), (name, pattern))
            for line in source.splitlines():
                if "omassh.config" in line:
                    self.assertRegex(line, r"strings\.tn?\(", (name, line))

    def test_the_host_commands_take_their_arguments_as_a_list_with_the_alias_last(self):
        source = read("Panel.qml")
        self.assertEqual(source.count('"host", "delete", "--expect", expect, "--", alias]'), 1)
        self.assertEqual(source.count('"include", "apply", "--confirm", "--expect", expect]'), 1)
        self.assertEqual(source.count('[root.cli, "include", "status"]'), 1)
        self.assertEqual(source.count("/^[0-9a-f]{16}$/.test(expect)"), 2)
        self.assertNotIn('"host", "validate"', source)

    def test_the_catcher_ignores_keys_while_a_form_search_or_confirmation_has_focus(self):
        source = read("Panel.qml")
        self.assertIn("blocked: search.activeFocus || form.activeFocus || confirmKeys.activeFocus || root.deleteConfirmOpen", source)
        self.assertRegex(source, r"onActivateRequested: \{\s*if \(root\.deleteConfirmOpen\) return")
        self.assertRegex(source, r"Item \{\s*id: confirmKeys\s*Keys\.onPressed: function\(event\) \{\s*deleteConfirm\.handleKey\(event\)\s*event\.accepted = true")
        self.assertIn("deleteConfirm.selectedIndex = 0", source)
        self.assertIn('confirmText: Commons.I18n.t("common.delete")', source)
        self.assertRegex(read("HostForm.qml"), re.compile(r"^FocusScope \{", re.M))

    def test_every_code_and_refusal_the_backend_can_send_is_known_to_the_panel(self):
        panel, form = read("Panel.qml"), read("HostForm.qml")
        for word in ("cycle", "managed-foreign", "managed-unsafe", "group", "incomplete"):
            self.assertIn('"%s"' % word, panel, word)
        self.assertIn('code === "cycle"', form)
        self.assertIn("incomplete: value.incomplete === true", panel)
        self.assertIn("onRowRemoved: function(row) { root.dropRowError(row) }", panel)
        self.assertIn("form.rowRemoved(row)", form)

    def test_the_setup_page_never_tells_the_user_to_press_a_key_that_does_nothing_there(self):
        panel = read("Panel.qml")
        page = panel[panel.index("id: setupPage") : panel.index('text: strings.t("setup.unchanged"')]
        self.assertNotIn("editor.late", page)
        self.assertNotIn("editor.scoped", page)
        for name in sorted(os.listdir(os.path.join(ROOT, "i18n"))):
            catalog = json.loads(read("i18n", name))
            for key in ("setup.late", "setup.scoped"):
                for phrase in ("Press n", "Presiona n", "n キー"):
                    self.assertNotIn(phrase, catalog[key], (name, key))

    @unittest.skipUnless(shutil.which("node"), "needs node")
    def test_removing_a_forward_row_realigns_the_errors_of_the_rows_after_it(self):
        source = read("Panel.qml")
        function = source[source.index("function dropRowError(row)") : source.index("/** Ends a save whose process went away")]
        script = "const root = {fieldErrors: JSON.parse(process.argv[1])};\n%s\ndropRowError(Number(process.argv[2]));console.log(JSON.stringify(root.fieldErrors));" % function
        errors = [{"field": "alias", "index": -1, "code": "taken"}, {"field": "forwards", "index": 0, "code": "forward"}, {"field": "forwards", "index": 1, "code": "duplicate"}, {"field": "forwards", "index": 3, "code": "too-long"}]
        out = subprocess.run([shutil.which("node"), "-e", script, json.dumps(errors), "1"], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(
            json.loads(out),
            [{"field": "alias", "index": -1, "code": "taken"}, {"field": "forwards", "index": 0, "code": "forward"}, {"field": "forwards", "index": 2, "code": "too-long"}],
        )

    def test_the_host_keys_are_lowercase_and_only_act_on_the_list_pages(self):
        source = read("Panel.qml")
        body = source[source.index("function pressKey(") : source.index("/** Shows the actions page")]
        self.assertIn("text.toLowerCase()", body)
        self.assertIn('if (root.page !== "hosts" && root.page !== "actions") return', body)
        for key in ("n", "m", "d"):
            self.assertEqual(body.count('key === "%s"' % key), 1, key)
        self.assertLess(body.index('key === "d"'), body.index('"stfy".indexOf(key)'))

    def test_the_form_limits_equal_the_backend_caps(self):
        source = read("HostForm.qml")
        for name in hostform.FIELDS:
            found = re.findall(r'name: "%s"[^}]*?maximumLength: (\d+)' % name, source)
            self.assertEqual(found, [str(hostform.LIMITS[name])], name)
        self.assertEqual(re.findall(r"placeholderText: \"L 8080 localhost:80\"\s*maximumLength: (\d+)", source), [str(hostform.LIMITS["forward"])])
        self.assertIn("readonly property int forwardLimit: %d" % hostform.MAX_FORWARDS, source)
        self.assertIn("Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText", source)

    def test_the_form_sends_nothing_by_itself_and_reads_its_texts_at_save_time(self):
        source = read("HostForm.qml")
        for pattern in (r"\bProcess\b", r"execDetached", r"\bTimer\b", r"\bonTextChanged\b", r"\bonTextEdited\b", r"\bonEditingFinished\b", r"\bonAccepted\b"):
            self.assertIsNone(re.search(pattern, source), pattern)
        self.assertGreaterEqual(source.count("signal "), 2)

    def test_the_open_panel_indicator_spans_the_letters(self):
        source = read("BarWidget.qml")
        self.assertIn("readonly property Item openPanelIndicatorItem: letters", source)
        self.assertIn("width: 11 * icon.px", source)
        self.assertNotIn("openPanelIndicatorWidth", source)

    def test_bar_icon_is_a_pixel_canvas_without_icon_font_glyphs(self):
        source = read("BarWidget.qml")
        self.assertIn("Canvas {", source)
        self.assertIn("antialiasing: false", source)
        self.assertIsNone(re.search("[-\U000f0000-\U0010ffff]", source))

    def test_process_commands_are_argument_lists(self):
        for path in files(".qml"):
            source = read(os.path.relpath(path, ROOT))
            self.assertIsNone(re.search(r"command:\s*\"", source), "a Process command must be an array")
            for call in re.findall(r"execDetached\(([^)]*)\)", source):
                self.assertNotIn('"', call.split(",")[0].strip()[:1], "execDetached takes an array")


class PythonSafetyTests(unittest.TestCase):
    FORBIDDEN = (
        r"shell\s*=\s*True",
        r"\bos\.system\b",
        r"\bos\.popen\b",
        r"\beval\(",
        r"\bexec\(",
        r"\bpickle\b",
        r"\bmarshal\b",
        r"\byaml\.load\b",
        r"\b__import__\b",
        r"\bimportlib\b",
    )

    def test_no_dangerous_calls(self):
        for path in files(".py"):
            source = read(os.path.relpath(path, ROOT))
            for pattern in self.FORBIDDEN:
                self.assertIsNone(re.search(pattern, source), "%s: %s" % (os.path.basename(path), pattern))

    def test_network_code_lives_only_in_probe(self):
        for path in files(".py"):
            name = os.path.basename(path)
            source = read(os.path.relpath(path, ROOT))
            imports = re.findall(r"^\s*(?:import|from)\s+(socket|urllib|http|ssl|requests|asyncio|ftplib|smtplib)\b", source, re.M)
            if name == "probe.py":
                self.assertEqual(set(imports), {"socket"})
            else:
                self.assertEqual(imports, [], name)

    def test_subprocess_lives_only_in_launch(self):
        for path in files(".py"):
            name = os.path.basename(path)
            source = read(os.path.relpath(path, ROOT))
            uses = re.findall(r"subprocess\.(\w+)", source)
            if name == "launch.py":
                self.assertEqual(set(uses), {"Popen", "DEVNULL", "TimeoutExpired"})
                self.assertEqual(source.count("subprocess.Popen("), 1)
            else:
                self.assertEqual(uses, [], name)
                self.assertIsNone(re.search(r"^\s*(import subprocess|from subprocess)", source, re.M), name)

    def test_only_launch_capture_kills_a_child_and_only_after_its_timeout(self):
        found = []
        for path in files(".py"):
            found += [os.path.basename(path)] * read(os.path.relpath(path, ROOT)).count(".kill(")
        self.assertEqual(found, ["launch.py"])
        source = read("backend", "launch.py")
        body = source[source.index("def capture(") :]
        self.assertEqual(body.count(".kill("), 1)
        self.assertLess(body.index("wait(proc, timeout)"), body.index("proc.kill()"))
        self.assertLess(body.index("proc.kill()"), body.index("wait(proc, KILL_WAIT)"))
        self.assertEqual(source.count("subprocess.Popen("), 1)
        self.assertIn("spawn(argv, stdout=out.fileno(), stderr=err.fileno())", body)

    def test_the_host_form_cannot_loosen_its_grammars(self):
        source = read("backend", "hostform.py")
        for pattern in (r"\.match\(", r"\.search\(", r"\.strip\(\)", r"\.lstrip\(", r"\.rstrip\(", r"\\[dswDSW]", r"\bre\.[A-Z]+\b", r"IGNORECASE", r"\.isdigit\(", r"\.isalnum\(", r"\.upper\(", r"\.casefold\("):
            self.assertIsNone(re.search(pattern, source), pattern)
        self.assertGreaterEqual(source.count(".fullmatch("), 10)
        self.assertEqual(source.count(".strip("), 1)
        self.assertIn('value.strip(" \\t")', source)

    def test_the_host_editor_modules_cannot_express_dangerous_keywords(self):
        words = ("proxycommand", "localcommand", "remotecommand", "permitlocalcommand", "match", "include", "setenv", "sendenv", "knownhostscommand", "stricthostkeychecking")
        allowed = {"hostform.py": (), "hostfile.py": ("include",), "mainconfig.py": ("include",)}
        for name, allowance in allowed.items():
            source = read("backend", name).lower()
            for word in words:
                if word not in allowance:
                    self.assertIsNone(re.search(r"\b%s\b" % word, source), (name, word))
        self.assertEqual(read("backend", "mainconfig.py").count('"Include ~/.ssh/omassh.config"'), 1)
        self.assertIn('INCLUDE_LINE = "Include ~/.ssh/omassh.config"', read("backend", "mainconfig.py"))
        source = read("backend", "hostfile.py")
        self.assertEqual(len(re.findall(r"\binclude\b", source, re.I)), source.count('"include"'))

    def test_ssh_dash_g_runs_only_in_hostfile_and_only_on_its_own_candidate_file(self):
        for path in files(".py"):
            name = os.path.basename(path)
            source = read(os.path.relpath(path, ROOT))
            if name == "hostfile.py":
                self.assertEqual(source.count('"-G"'), 1)
                self.assertIn('argv = [ssh_path, "-G", "-F", os.path.join(directory, name), "--", alias]', source)
            else:
                self.assertNotRegex(source, r"[\"']-G[\"']", name)

    def test_files_are_installed_only_by_the_two_editor_modules(self):
        expected = {"hostfile.py": 1, "mainconfig.py": 2}
        for path in files(".py"):
            name = os.path.basename(path)
            source = read(os.path.relpath(path, ROOT))
            if name != "safefile.py":
                self.assertEqual(source.count("safefile.install("), expected.get(name, 0), name)
                self.assertEqual(source.count("safefile.replace("), 1 if name == "hostfile.py" else 0, name)

    def test_signals_are_only_sent_from_tunnels(self):
        for path in files(".py"):
            name = os.path.basename(path)
            source = read(os.path.relpath(path, ROOT))
            self.assertNotIn("os.kill(", source, name)
            if name != "tunnels.py":
                self.assertNotRegex(source, r"killpg|pidfd_send_signal|raise_signal", name)

    def test_tunnels_signal_only_through_a_verified_pidfd_or_their_own_child_group(self):
        source = read("backend", "tunnels.py")
        self.assertEqual(source.count("os.killpg("), 1)
        self.assertEqual(source.count("os.killpg(proc.pid"), 1)
        self.assertEqual(source.count("signal.pidfd_send_signal("), 1)
        start = source.index("def _terminate(")
        terminate = source[start : source.index("\ndef ", start + 1)]
        self.assertLess(terminate.index("os.pidfd_open("), terminate.index("verify(rec, alias, PROC, boot, uid)"))
        self.assertLess(terminate.index("verify(rec, alias, PROC, boot, uid)"), terminate.index("signal.pidfd_send_signal("))
        start = source.index("def _abort(")
        abort = source[start : source.index("\ndef ", start + 1)]
        self.assertLess(abort.index("os.killpg(proc.pid"), abort.index("launch.wait(proc"))
        self.assertEqual(abort.count("launch.wait("), 1)

    def test_the_backend_never_sleeps(self):
        for path in files(".py"):
            self.assertNotIn("time.sleep(", read(os.path.relpath(path, ROOT)), path)

    def test_no_bare_excepts(self):
        for path in files(".py"):
            self.assertIsNone(re.search(r"except\s*:", read(os.path.relpath(path, ROOT))), path)

    def test_scripts_do_not_use_eval_or_unquoted_expansion_tricks(self):
        for rel in ("omassh", os.path.join("scripts", "session.sh")):
            code = "\n".join(l for l in read(rel).splitlines() if not l.lstrip().startswith("#"))
            self.assertIsNone(re.search(r"\beval\b|\bsh -c\b|\bbash -c\b|`", code), rel)

    def test_session_script_always_uses_double_dash(self):
        self.assertIn('-- "$alias_name"', read("scripts", "session.sh"))

    def test_session_script_keeps_remote_command_none_and_quotes_the_saved_command(self):
        source = read("scripts", "session.sh")
        self.assertEqual(source.count("RemoteCommand=none"), 2)
        self.assertIn('-- "$alias_name" "$cmd"', source)
        self.assertIn('command-text --alias "$alias_name" -- "$command_id"', source)

    def test_ssh_never_told_to_skip_host_key_checking(self):
        for path in list(files(".py", ".sh", ".qml")) + [os.path.join(ROOT, "omassh")]:
            source = read(os.path.relpath(path, ROOT))
            self.assertNotRegex(source, r"StrictHostKeyChecking|UserKnownHostsFile|sshpass|\bPassword\b", path)


if __name__ == "__main__":
    unittest.main()
