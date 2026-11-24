import os
import sys
import json
import stat
import fcntl
import tempfile
import unittest
import multiprocessing

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import store


def _worker(path, alias):
    store.modify(path, lambda s: store.record_use(s, alias, 1_700_000_000))


class StatePathTests(unittest.TestCase):
    def test_uses_xdg_state_home(self):
        self.assertEqual(store.state_path({"XDG_STATE_HOME": "/x/state"}), "/x/state/omassh/state.json")

    def test_relative_xdg_is_ignored(self):
        path = store.state_path({"XDG_STATE_HOME": "relative/dir"})
        self.assertTrue(os.path.isabs(path))
        self.assertTrue(path.endswith("/.local/state/omassh/state.json"))

    def test_default(self):
        self.assertTrue(store.state_path({}).endswith("/.local/state/omassh/state.json"))


class SanitizeTests(unittest.TestCase):
    def test_garbage_types(self):
        for raw in (None, 1, "x", [], [1], {"pinned": 5, "recent": "x"}, {"pinned": {"a": 1}, "recent": [1]}):
            self.assertEqual(store.sanitize(raw), store.empty(), raw)

    def test_invalid_aliases_are_dropped(self):
        raw = {"pinned": ["ok", "-oProxyCommand=x", "a@b", 5, None, "ok"], "recent": {"ok": 100, "-J": 100, "a b": 100}}
        s = store.sanitize(raw)
        self.assertEqual(s["pinned"], ["ok"])
        self.assertEqual(s["recent"], {"ok": 100})

    def test_timestamps_are_range_checked(self):
        raw = {"recent": {"a": 0, "b": -5, "c": 10**15, "d": 1.5, "e": "9", "f": True, "g": 100}}
        self.assertEqual(store.sanitize(raw)["recent"], {"g": 100})

    def test_entry_caps(self):
        raw = {
            "pinned": ["p%d" % i for i in range(store.MAX_ENTRIES + 50)],
            "recent": {"r%d" % i: 1000 + i for i in range(store.MAX_ENTRIES + 50)},
        }
        s = store.sanitize(raw)
        self.assertEqual(len(s["pinned"]), store.MAX_ENTRIES)
        self.assertEqual(len(s["recent"]), store.MAX_ENTRIES)
        self.assertIn("r%d" % (store.MAX_ENTRIES + 49), s["recent"])


BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def record(**changes):
    """A tunnel record with valid defaults."""
    rec = {"pid": 12345, "start": 987654321, "boot": BOOT, "since": 1_764_000_000, "config": ""}
    rec.update(changes)
    return rec


class TunnelRecordTests(unittest.TestCase):
    def test_a_valid_record_is_kept_exactly(self):
        for config in ("", "/etc/ssh/ssh_config", "/tmp/a+b@c:d,e=f"):
            raw = {"tunnels": {"web": record(config=config)}}
            self.assertEqual(store.sanitize(raw)["tunnels"], {"web": record(config=config)})

    def test_extra_fields_are_dropped(self):
        rec = record()
        rec["argv"] = ["ssh", "-oProxyCommand=x"]
        self.assertEqual(store.sanitize({"tunnels": {"web": rec}})["tunnels"], {"web": record()})

    def test_every_bad_field_drops_the_record(self):
        bad = [
            {"pid": True},
            {"pid": 1},
            {"pid": 0},
            {"pid": -4},
            {"pid": store.PID_MAX + 1},
            {"pid": 12.0},
            {"pid": "12"},
            {"pid": None},
            {"start": -1},
            {"start": store.START_MAX + 1},
            {"start": True},
            {"start": "5"},
            {"start": 1.5},
            {"boot": ""},
            {"boot": BOOT.upper()},
            {"boot": BOOT + "0"},
            {"boot": BOOT[:-1]},
            {"boot": BOOT + "\n"},
            {"boot": 5},
            {"since": 0},
            {"since": store.TS_MAX + 1},
            {"since": True},
            {"since": "1764000000"},
            {"config": "relative"},
            {"config": "/a b"},
            {"config": "/a;id"},
            {"config": "/a$(id)"},
            {"config": None},
            {"config": 5},
        ]
        for change in bad:
            self.assertEqual(store.sanitize({"tunnels": {"web": record(**change)}})["tunnels"], {}, change)

    def test_missing_fields_drop_the_record(self):
        for key in ("pid", "start", "boot", "since", "config"):
            rec = record()
            del rec[key]
            self.assertEqual(store.sanitize({"tunnels": {"web": rec}})["tunnels"], {}, key)

    def test_bad_aliases_and_shapes_are_dropped(self):
        raw = {"tunnels": {"-oProxyCommand=x": record(), "a b": record(), "ok": record(), "str": "x", "none": None, "list": [record()]}}
        self.assertEqual(list(store.sanitize(raw)["tunnels"]), ["ok"])
        for shape in (None, [record()], "x", 5):
            self.assertEqual(store.sanitize({"tunnels": shape})["tunnels"], {})

    def test_valid_tunnels_are_never_dropped_for_their_number(self):
        raw = {"tunnels": {"t%d" % i: record(since=1000 + i) for i in range(store.MAX_TUNNELS + 10)}}
        self.assertEqual(sorted(store.sanitize(raw)["tunnels"]), sorted(raw["tunnels"]))

    def test_a_version_one_file_loads_with_no_tunnels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            with open(path, "w") as fh:
                json.dump({"version": 1, "pinned": ["a"], "recent": {"a": 100}}, fh)
            state = store.load(path)
        self.assertEqual(state, {"version": 2, "pinned": ["a"], "recent": {"a": 100}, "tunnels": {}})

    def test_the_state_version_is_two(self):
        self.assertEqual(store.STATE_VERSION, 2)
        self.assertEqual(store.empty()["version"], 2)


class TunnelStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "omassh", "state.json")

    def test_set_and_drop_round_trip(self):
        store.modify(self.path, lambda s: store.set_tunnel(s, "web", record()))
        self.assertEqual(store.load(self.path)["tunnels"], {"web": record()})
        store.modify(self.path, lambda s: store.drop_tunnel(s, "web"))
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_drop_with_a_stale_record_leaves_a_newer_one_alone(self):
        old, new = record(pid=100, start=5), record(pid=200, start=9)
        store.modify(self.path, lambda s: store.set_tunnel(s, "web", new))
        store.modify(self.path, lambda s: store.drop_tunnel(s, "web", old))
        self.assertEqual(store.load(self.path)["tunnels"], {"web": new})
        store.modify(self.path, lambda s: store.drop_tunnel(s, "web", record(pid=200, start=8)))
        self.assertEqual(store.load(self.path)["tunnels"], {"web": new})
        store.modify(self.path, lambda s: store.drop_tunnel(s, "web", new))
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_drop_of_a_missing_alias_is_harmless(self):
        store.modify(self.path, lambda s: store.drop_tunnel(s, "ghost"))
        store.modify(self.path, lambda s: store.drop_tunnel(s, "ghost", record()))
        self.assertEqual(store.load(self.path)["tunnels"], {})

    def test_pins_and_recents_keep_the_tunnels(self):
        store.modify(self.path, lambda s: store.set_tunnel(s, "web", record()))
        store.modify(self.path, lambda s: (store.set_pinned(s, "web", True), store.record_use(s, "web", 1_700_000_000)))
        state = store.load(self.path)
        self.assertEqual(state["tunnels"], {"web": record()})
        self.assertEqual(state["pinned"], ["web"])

    def test_a_tampered_tunnel_is_removed_on_the_next_write(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fh:
            json.dump({"tunnels": {"web": record(pid=True), "db": record()}}, fh)
        store.modify(self.path, lambda s: store.record_use(s, "db", 1_700_000_000))
        with open(self.path) as fh:
            self.assertEqual(list(json.load(fh)["tunnels"]), ["db"])

    def test_the_tunnel_lock_is_separate_from_the_state_lock(self):
        with store.tunnel_lock(self.path):
            store.modify(self.path, lambda s: store.set_pinned(s, "a", True))
        names = sorted(os.listdir(os.path.dirname(self.path)))
        self.assertIn("state.json.lock", names)
        self.assertIn("state.json.tunnels.lock", names)
        self.assertEqual(store.load(self.path)["pinned"], ["a"])


class HostEditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "omassh", "state.json")

    def state(self, pinned, recent=None, tunnels=None):
        """A state with the given pins, recent entries and tunnels."""
        state = store.empty()
        state["pinned"] = list(pinned)
        state["recent"] = dict(recent or {})
        state["tunnels"] = dict(tunnels or {})
        return state

    def test_the_hosts_lock_has_its_own_file(self):
        with store.hosts_lock(self.path):
            store.modify(self.path, lambda s: store.set_pinned(s, "a", True))
            with store.tunnel_lock(self.path):
                pass
        names = sorted(os.listdir(os.path.dirname(self.path)))
        self.assertIn("state.json.hosts.lock", names)
        self.assertIn("state.json.tunnels.lock", names)
        self.assertEqual(stat.S_IMODE(os.stat(self.path + ".hosts.lock").st_mode), 0o600)
        self.assertEqual(store.load(self.path)["pinned"], ["a"])

    def test_the_hosts_lock_excludes_a_second_holder(self):
        with store.hosts_lock(self.path):
            fd = os.open(self.path + ".hosts.lock", os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        fd = os.open(self.path + ".hosts.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_forget_unpins_and_drops_the_recent_entry_only(self):
        tunnel = record()
        state = self.state(["a", "b", "c"], {"b": 5, "c": 7}, {"b": tunnel})
        store.forget(state, "b")
        self.assertEqual(state["pinned"], ["a", "c"])
        self.assertEqual(state["recent"], {"c": 7})
        self.assertEqual(state["tunnels"], {"b": tunnel})

    def test_forget_of_an_unknown_alias_is_a_no_op(self):
        state = self.state(["a"], {"a": 5})
        store.forget(state, "ghost")
        self.assertEqual(state, self.state(["a"], {"a": 5}))

    def test_rename_keeps_the_pin_position(self):
        state = self.state(["a", "b", "c"], {"b": 5})
        store.rename(state, "b", "z")
        self.assertEqual(state["pinned"], ["a", "z", "c"])
        self.assertEqual(state["recent"], {"z": 5})

    def test_rename_without_entries_is_a_no_op(self):
        state = self.state(["a"], {"a": 5})
        store.rename(state, "ghost", "z")
        self.assertEqual(state, self.state(["a"], {"a": 5}))

    def test_rename_to_the_same_alias_is_a_no_op(self):
        state = self.state(["a", "b"], {"a": 5})
        store.rename(state, "a", "a")
        self.assertEqual(state, self.state(["a", "b"], {"a": 5}))

    def test_rename_onto_an_already_pinned_alias_keeps_one_pin(self):
        state = self.state(["x", "a", "y"], {"a": 5, "y": 9})
        store.rename(state, "a", "y")
        self.assertEqual(state["pinned"], ["x", "y"])
        self.assertEqual(state["recent"], {"y": 9})
        state = self.state(["a", "x", "y"], {"a": 9, "y": 5})
        store.rename(state, "a", "y")
        self.assertEqual(state["pinned"], ["y", "x"])
        self.assertEqual(state["recent"], {"y": 9})

    def test_rename_moves_only_what_exists(self):
        state = self.state(["a"], {})
        store.rename(state, "a", "z")
        self.assertEqual((state["pinned"], state["recent"]), (["z"], {}))
        state = self.state([], {"a": 4})
        store.rename(state, "a", "z")
        self.assertEqual((state["pinned"], state["recent"]), ([], {"z": 4}))

    def test_rename_leaves_tunnels_alone(self):
        tunnel = record()
        state = self.state(["a"], {"a": 1}, {"a": tunnel})
        store.rename(state, "a", "z")
        self.assertEqual(state["tunnels"], {"a": tunnel})

    def test_the_result_survives_a_save_and_load(self):
        store.modify(self.path, lambda s: (store.set_pinned(s, "a", True), store.set_pinned(s, "b", True), store.record_use(s, "a", 1_700_000_000)))
        store.modify(self.path, lambda s: store.rename(s, "a", "z"))
        state = store.load(self.path)
        self.assertEqual((state["pinned"], state["recent"]), (["z", "b"], {"z": 1_700_000_000}))
        store.modify(self.path, lambda s: store.forget(s, "z"))
        state = store.load(self.path)
        self.assertEqual((state["pinned"], state["recent"]), (["b"], {}))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "omassh", "state.json")

    def test_missing_file_is_empty(self):
        self.assertEqual(store.load(self.path), store.empty())

    def test_round_trip_and_permissions(self):
        store.modify(self.path, lambda s: (store.record_use(s, "server", 1_700_000_000), store.set_pinned(s, "server", True)))
        self.assertEqual(store.load(self.path)["recent"], {"server": 1_700_000_000})
        self.assertEqual(store.load(self.path)["pinned"], ["server"])
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)

    def test_no_temp_files_left_behind(self):
        store.modify(self.path, lambda s: store.record_use(s, "server", 1_700_000_000))
        leftovers = [n for n in os.listdir(os.path.dirname(self.path)) if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_corrupt_json_is_quarantined(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fh:
            fh.write("{not json")
        self.assertEqual(store.load(self.path), store.empty())
        self.assertTrue(os.path.exists(self.path + ".corrupt"))
        self.assertFalse(os.path.exists(self.path))

    def test_oversized_file_is_quarantined(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fh:
            fh.write(" " * (store.MAX_STATE_BYTES + 10))
        self.assertEqual(store.load(self.path), store.empty())
        self.assertTrue(os.path.exists(self.path + ".corrupt"))

    def test_deeply_nested_json_does_not_crash(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fh:
            fh.write("[" * 50_000)
        self.assertEqual(store.load(self.path), store.empty())

    def test_tampered_file_is_cleaned_on_next_write(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fh:
            json.dump({"pinned": ["-oProxyCommand=x", "good"], "recent": {"a b": 5}}, fh)
        store.modify(self.path, lambda s: store.record_use(s, "good", 1_700_000_000))
        with open(self.path) as fh:
            on_disk = json.load(fh)
        self.assertEqual(on_disk["pinned"], ["good"])
        self.assertNotIn("a b", on_disk["recent"])

    def test_pin_and_unpin(self):
        store.modify(self.path, lambda s: store.set_pinned(s, "a", True))
        store.modify(self.path, lambda s: store.set_pinned(s, "b", True))
        store.modify(self.path, lambda s: store.set_pinned(s, "a", False))
        self.assertEqual(store.load(self.path)["pinned"], ["b"])

    def test_concurrent_writers_do_not_lose_updates(self):
        aliases = ["h%d" % i for i in range(12)]
        procs = [multiprocessing.Process(target=_worker, args=(self.path, a)) for a in aliases]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        self.assertEqual(sorted(store.load(self.path)["recent"]), sorted(aliases))


if __name__ == "__main__":
    unittest.main()
