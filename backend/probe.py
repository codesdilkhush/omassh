from __future__ import annotations

import time
import socket
from concurrent.futures import ThreadPoolExecutor, wait

MAX_PROBES = 200
WORKERS = 16
CONNECT_TIMEOUT = 1.5
TOTAL_TIMEOUT = 8.0


def target(host: dict) -> tuple[str, int] | None:
    """Where to connect, or ``None`` when we must not / cannot probe."""
    if host.get("proxy") or host.get("jump") or host.get("noProbe"):
        return None
    alias = host["alias"]
    name = (host.get("hostname") or alias).replace("%h", alias)
    if "%" in name or not name:
        return None
    return name, int(host.get("port") or 22)


def check(host: dict, timeout: float = CONNECT_TIMEOUT) -> dict:
    """The reachability of one host: unknown when it must not be probed, else up with a time, or down."""
    where = target(host)
    if where is None:
        return {"state": "unknown"}
    started = time.monotonic()
    try:
        with socket.create_connection(where, timeout=timeout):
            pass
    except (OSError, UnicodeError, ValueError, OverflowError):
        return {"state": "down"}
    return {"state": "up", "ms": int((time.monotonic() - started) * 1000)}


def probe_all(hosts: list[dict], timeout: float = CONNECT_TIMEOUT, total: float = TOTAL_TIMEOUT) -> dict:
    """Probe hosts concurrently and return {alias: {"state": ...}}."""
    results: dict[str, dict] = {}
    to_probe = []
    for host in hosts[:MAX_PROBES]:
        if target(host) is None:
            results[host["alias"]] = {"state": "unknown"}
        else:
            to_probe.append(host)
    if not to_probe:
        return results
    pool = ThreadPoolExecutor(max_workers=WORKERS)
    futures = {pool.submit(check, host, timeout): host["alias"] for host in to_probe}
    done, pending = wait(futures, timeout=total)
    for future in done:
        results[futures[future]] = future.result()
    for future in pending:
        results[futures[future]] = {"state": "down"}
    pool.shutdown(wait=False, cancel_futures=True)
    return results
