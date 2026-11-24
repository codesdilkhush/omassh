import os
import signal
import hostform
import tempfile
from unittest import mock


def reap(directory):
    """Kill every process whose command line mentions the private directory, rechecking through a pidfd."""
    for name in os.listdir("/proc"):
        if not name.isdecimal():
            continue
        try:
            with open("/proc/%s/cmdline" % name, "rb") as fh:
                if directory.encode() not in fh.read():
                    continue
            fd = os.pidfd_open(int(name))
        except OSError:
            continue
        try:
            with open("/proc/%s/cmdline" % name, "rb") as fh:
                if directory.encode() in fh.read() and int(name) != os.getpid():
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
        except OSError:
            pass
        finally:
            os.close(fd)


def private_home(case):
    """Give case a temporary HOME holding a private .ssh, point HOME and the XDG variables at it for the test, and return the ssh directory."""
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    home = os.path.realpath(tmp.name)
    ssh = os.path.join(home, ".ssh")
    os.mkdir(ssh, 0o700)
    env = {"HOME": home, "XDG_STATE_HOME": os.path.join(home, "state"), "XDG_CONFIG_HOME": os.path.join(home, "xdg")}
    patcher = mock.patch.dict(os.environ, env)
    patcher.start()
    case.addCleanup(patcher.stop)
    return ssh


def anything_exists(path):
    """An existence check for IdentityFile paths that accepts everything."""
    return True


def random_host(rng):
    """Form values for a random valid host."""
    names = ["web", "db", "a.example.com", "192.0.2.10", "h-1", "node_2"]
    jumps = ["bastion", "admin@jump.example.com:2200", "[2001:db8::1]", "u@[2001:db8::2]:22", "192.0.2.1", "j:2"]
    targets = ["localhost:80", "db.example.com:5432", "[::1]:22", "192.0.2.7:1", "h:65535"]
    listens = ["8080", "localhost:8081", "127.0.0.1:8082", "[::1]:8083", "1"]
    rows = []
    for _ in range(rng.randrange(0, 6)):
        kind = rng.choice("LRD")
        row = "%s %s" % (kind, rng.choice(listens))
        if kind == "L" or (kind == "R" and rng.random() < 0.7):
            row += " " + rng.choice(targets)
        rows.append(row)
    raw = {
        "alias": "h" + "".join(rng.choice("abcXYZ019._-") for _ in range(rng.randrange(0, 11))),
        "hostname": rng.choice(["", "", rng.choice(names), "2001:DB8::" + rng.choice(["1", "ABC"]), "Mixed.Case.Example"]),
        "user": rng.choice(["", "admin", "u.1", "_x"]),
        "port": rng.choice(["", "22", "2222", "65535", "1"]),
        "proxyJump": rng.choice(["", ",".join(rng.sample(jumps, rng.randrange(1, 4)))]),
        "identityFile": rng.choice(["", "~/.ssh/id_ed25519", "/home/u/.ssh/key.pub"]),
        "forwards": list(dict.fromkeys(rows)),
    }
    return raw


def random_hosts(rng, count):
    """Count canonical hosts with distinct aliases."""
    hosts = []
    seen = set()
    while len(hosts) < count:
        raw = random_host(rng)
        host, errors = hostform.normalize(raw, anything_exists)
        if host is None:
            if {e["code"] for e in errors} <= {"self", "duplicate"}:
                continue
            raise AssertionError((raw, errors))
        if host["alias"] not in seen:
            seen.add(host["alias"])
            hosts.append(host)
    return hosts


def random_label(rng):
    """A random DNS label made of letters, digits, dots, hyphens and underscores that starts with a letter or digit."""
    label = rng.choice("abcXYZ019") + "".join(rng.choice("abcXYZ019-_.") for _ in range(rng.randrange(0, 8)))
    return label if any(ch not in "0123456789.xXabcdefABCDEF" for ch in label) else label + "z"


def random_address(rng):
    """A random IPv4 or IPv6 address spelling the grammar allows, in documentation ranges where it is a real address."""
    return rng.choice(
        [
            "192.0.2.%d" % rng.randrange(256),
            "203.0.113.%d" % rng.randrange(256),
            "2001:DB8::%X" % rng.randrange(1, 65536),
            "2001:db8:0:0:0:0:0:%x" % rng.randrange(1, 65536),
            "::ffff:192.0.2.%d" % rng.randrange(256),
            "64:ff9b::192.0.2.%d" % rng.randrange(256),
            "::1",
            "FE80::ABCD",
        ]
    )


def random_endpoint(rng, bracket_ipv6):
    """A random host spelling accepted by the grammar: a name or address, bracketed when it is IPv6 and bracket_ipv6 is set."""
    roll = rng.random()
    if roll < 0.35:
        return random_label(rng)
    if roll < 0.5:
        return rng.choice(["a.example.", "a..b", "a-.b", "a_", "A.Example.COM", "x" * 63 + ".example"])
    address = random_address(rng)
    return "[%s]" % address if bracket_ipv6 and ":" in address else address


def random_wild_host(rng, index):
    """Form values for a host with an unusual but valid spelling in every field, avoiding a hop equal to the host itself."""
    alias = "w%d" % index
    hostname = rng.choice(["", random_label(rng), random_address(rng) if rng.random() < 0.7 else "192.0.2.9"])
    jumps = []
    for _ in range(rng.randrange(0, 4)):
        host = random_endpoint(rng, True)
        if host.strip("[]").lower() in (alias.lower(), hostname.lower()):
            continue
        user = rng.choice(["", "", "u@", "_u.1@"])
        port = rng.choice(["", "", ":22", ":65535"])
        jumps.append(user + host + port)
    rows = []
    for _ in range(rng.randrange(0, 5)):
        kind = rng.choice("LRD")
        row = "%s %s" % (kind, rng.choice(["1", "localhost:2", "127.0.0.1:3", "[::1]:4", "65535"]))
        if kind == "L" or (kind == "R" and rng.random() < 0.6):
            row += " %s:%d" % (random_endpoint(rng, True), rng.randrange(1, 65536))
        rows.append(row)
    return {
        "alias": alias,
        "hostname": hostname,
        "user": rng.choice(["", "u", "_x.1-y"]),
        "port": rng.choice(["", "1", "65535"]),
        "proxyJump": ",".join(jumps),
        "identityFile": rng.choice(["", "~/.ssh/id_x"]),
        "forwards": list(dict.fromkeys(rows)),
    }


def random_wild_hosts(rng, count):
    """Count canonical hosts built from random_wild_host; every value must pass normalize."""
    hosts = []
    for index in range(count):
        raw = random_wild_host(rng, index)
        host, errors = hostform.normalize(raw, anything_exists)
        if host is None:
            codes = {(e["field"], e["code"]) for e in errors}
            if codes <= {("forwards", "duplicate")}:
                continue
            raise AssertionError((raw, errors))
        hosts.append(host)
    return hosts
