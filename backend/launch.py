from __future__ import annotations

import os
import tempfile
import subprocess

KILL_WAIT = 5.0


def spawn(argv: list[str], *, stdout: int | None = None, stderr: int | None = None, env: dict | None = None) -> subprocess.Popen:
    """Start argv detached in its own session with null stdin, stdout and stderr unless given; the only place a process is created."""
    return subprocess.Popen(
        argv,
        cwd=os.path.expanduser("~"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL if stdout is None else stdout,
        stderr=subprocess.DEVNULL if stderr is None else stderr,
        env=env,
        start_new_session=True,
        close_fds=True,
    )


def wait(proc: subprocess.Popen, timeout: float) -> int | None:
    """Exit status of proc, or None when it is still running after timeout seconds."""
    try:
        return proc.wait(timeout)
    except subprocess.TimeoutExpired:
        return None


def capture(argv: list[str], timeout: float, limit: int) -> tuple[int | None, bytes, bytes]:
    """Run argv to completion and return its status, stdout and stderr, each cut at limit bytes; on timeout the child is killed and (None, b"", b"") comes back."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = spawn(argv, stdout=out.fileno(), stderr=err.fileno())
        status = wait(proc, timeout)
        if status is None:
            proc.kill()
            wait(proc, KILL_WAIT)
            return None, b"", b""
        out.seek(0)
        err.seek(0)
        return status, out.read(limit), err.read(limit)
