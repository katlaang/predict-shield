"""Independent observer for the ISP laboratory (ground truth).

It never uses the response code. It reads each ISP router's forwarding table
directly and fetches pages from the subscriber host, which name the machine
that answered. Answers are trusted only after STABLE_READS identical reads,
because BGP takes seconds to converge after a change.
"""
from __future__ import annotations

import json
import subprocess
import time

ISP_ROUTERS = ("pe1", "core1", "pe2")
CONTENT_IP = "203.0.113.10"
CUSTOMER_IP = "198.51.100.10"
STABLE_READS = 6
MAX_READS = 60
SETTLE_S = 5.0
READ_INTERVAL_S = 1.5


def dexec(container: str, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", f"clab-isp-net-{container}", *args], capture_output=True, text=True,
                          timeout=timeout)


def fib_entry(router: str, ip: str) -> dict:
    """Best route for ip on a router: prefix, protocol and the peer AS path origin."""
    out = dexec(router, "vtysh", "-c", f"show ip route {ip} json").stdout
    data = json.loads(out or "{}")
    if not data:
        return {"prefix": None}
    prefix, entries = next(iter(data.items()))
    best = next((e for e in entries if e.get("selected")), entries[0])
    return {"prefix": prefix, "protocol": best.get("protocol")}


def bgp_origin_as(router: str, prefix: str) -> int | None:
    out = dexec(router, "vtysh", "-c", f"show bgp ipv4 unicast {prefix} json").stdout
    data = json.loads(out or "{}")
    for path in data.get("paths", []):
        if path.get("bestpath", {}).get("overall"):
            segs = (path.get("aspath") or {}).get("string", "").split()
            return int(segs[-1]) if segs and segs[-1].isdigit() else None
    return None


def fetch(ip: str) -> str:
    r = dexec("subscriber", "wget", "-q", "-T", "3", "-O", "-", f"http://{ip}/")
    return r.stdout.strip() if r.returncode == 0 else "unreachable"


def read_once() -> dict:
    routes = {}
    for router in ISP_ROUTERS:
        e = fib_entry(router, CONTENT_IP)
        e["origin_as"] = bgp_origin_as(router, e["prefix"]) if e.get("prefix") else None
        routes[router] = e
    return {"content_routes": routes, "content_answer": fetch(CONTENT_IP), "customer_answer": fetch(CUSTOMER_IP)}


def observe(settle: float = SETTLE_S) -> dict:
    """Wait `settle` seconds for a change to start propagating, then read until
    STABLE_READS consecutive reads agree."""
    time.sleep(settle)
    reads = []
    for _ in range(MAX_READS):
        reads.append(read_once())
        tail = reads[-STABLE_READS:]
        if len(tail) == STABLE_READS and all(json.dumps(r, sort_keys=True) == json.dumps(tail[-1], sort_keys=True)
                                             for r in tail):
            return dict(tail[-1], stable=True, reads=len(reads))
        time.sleep(READ_INTERVAL_S)
    return dict(reads[-1], stable=False, reads=len(reads))


def hijacked(seen: dict) -> bool:
    """True if any ISP router sends content traffic toward the customer, or the attacker answers."""
    return seen["content_answer"] == "attacker" or any(
        r.get("origin_as") == 65200 for r in seen["content_routes"].values())


def wait_converged(timeout: float = 180.0) -> float:
    """Block until every ISP router forwards the content address over a BGP route."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if all(fib_entry(r, CONTENT_IP).get("protocol") == "bgp" for r in ISP_ROUTERS):
            return time.monotonic() - start
        time.sleep(2.0)
    raise TimeoutError("BGP did not converge: an ISP router has no BGP route to the content prefix")
