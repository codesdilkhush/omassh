import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import launch

PYTHON = [sys.executable, "-I", "-B", "-c"]


class CaptureTests(unittest.TestCase):
    def test_status_and_both_streams(self):
        status, out, err = launch.capture([*PYTHON, "import sys; sys.stdout.write('out'); sys.stderr.write('err'); sys.exit(3)"], 10, 1000)
        self.assertEqual((status, out, err), (3, b"out", b"err"))

    def test_success(self):
        self.assertEqual(launch.capture([*PYTHON, "pass"], 10, 10), (0, b"", b""))

    def test_output_is_cut_at_the_limit(self):
        status, out, err = launch.capture([*PYTHON, "import sys; sys.stdout.write('a' * 5000); sys.stderr.write('b' * 5000)"], 10, 100)
        self.assertEqual((status, out, err), (0, b"a" * 100, b"b" * 100))

    def test_stdin_is_empty(self):
        self.assertEqual(launch.capture([*PYTHON, "import sys; sys.stdout.write(repr(sys.stdin.read()))"], 10, 100), (0, b"''", b""))

    def test_a_missing_program_raises_instead_of_hanging(self):
        with self.assertRaises(OSError):
            launch.capture(["/nonexistent/omassh-test-binary"], 10, 10)

    def test_a_signal_death_is_a_negative_status(self):
        status, out, err = launch.capture([*PYTHON, "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"], 10, 10)
        self.assertEqual(status, -15)

    def test_a_timeout_kills_and_reaps_the_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pid")
            script = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); sys.stdout.write('late'); sys.stdout.flush(); time.sleep(60)"
            result = launch.capture([*PYTHON, script, marker], 0.5, 100)
            with open(marker) as fh:
                pid = int(fh.read())
        self.assertEqual(result, (None, b"", b""))
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_a_child_that_ignores_sigterm_is_still_killed(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pid")
            script = "import os, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
            result = launch.capture([*PYTHON, script, marker], 0.5, 100)
            with open(marker) as fh:
                pid = int(fh.read())
        self.assertEqual(result[0], None)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


class SpawnTests(unittest.TestCase):
    def test_stdout_can_go_to_a_file(self):
        with tempfile.TemporaryFile() as out:
            proc = launch.spawn([*PYTHON, "print('hello')"], stdout=out.fileno())
            self.assertEqual(launch.wait(proc, 10), 0)
            out.seek(0)
            self.assertEqual(out.read(), b"hello\n")

    def test_stdout_and_stderr_default_to_null(self):
        proc = launch.spawn([*PYTHON, "import sys; print('x'); print('y', file=sys.stderr)"])
        self.assertEqual(launch.wait(proc, 10), 0)

    def test_wait_reports_a_running_process_as_none(self):
        proc = launch.spawn([*PYTHON, "import time; time.sleep(60)"])
        try:
            self.assertIsNone(launch.wait(proc, 0.1))
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
