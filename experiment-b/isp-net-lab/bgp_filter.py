"""Inbound BGP prefix filter on an FRR router, as a gated-change target.

The managed content is a small, closed grammar: the prefix-list entries that
decide which routes a customer may announce. Empty content means no filter.

    ip prefix-list CUST-IN seq 10 permit 198.51.100.0/24 le 24

The adapter reads the filter back from the router's running configuration
(never from a local copy), validates candidates against the grammar, writes
them with vtysh and activates them with a soft inbound reset of the session.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import Callable

LIST = "CUST-IN"
ROUTE_MAP = "CUST-IN"
UNATTACHED = "# prefix-list present but not applied"
LINE = re.compile(rf"^ip prefix-list {LIST} seq (\d{{1,4}}) (permit|deny) (\d{{1,3}}(?:\.\d{{1,3}}){{3}}/\d{{1,2}})"
                  r"(?: ge (\d{1,2}))?(?: le (\d{1,2}))?$")

Runner = Callable[[list[str]], str]


def docker_runner(container: str) -> Runner:
    def run(args: list[str]) -> str:
        return subprocess.run(["docker", "exec", container, *args], check=True, capture_output=True,
                              text=True, timeout=30).stdout
    return run


def canonical(lines: list[str]) -> str:
    return "".join(line.strip() + "\n" for line in sorted(lines, key=lambda l: int(LINE.match(l.strip()).group(1))))


def validate(content: str) -> list[str]:
    """Raise ValueError unless every line is a well-formed entry of the managed list."""
    raw = [l.strip() for l in content.splitlines() if l.strip()]
    if UNATTACHED in raw:
        if raw[0] != UNATTACHED or raw.count(UNATTACHED) != 1 or len(raw) < 2:
            raise ValueError("Invalid unattached prefix-list snapshot")
        raw = raw[1:]
    lines = raw
    seqs = set()
    for line in lines:
        m = LINE.match(line)
        if not m:
            raise ValueError(f"not a managed prefix-list entry: {line!r}")
        seq, _, prefix, ge, le = m.groups()
        net = ipaddress.ip_network(prefix, strict=True)
        for bound in (ge, le):
            if bound is not None and not net.prefixlen <= int(bound) <= 32:
                raise ValueError(f"length bound out of range in {line!r}")
        if ge and le and int(ge) > int(le):
            raise ValueError(f"ge greater than le in {line!r}")
        if seq in seqs:
            raise ValueError(f"duplicate sequence {seq}")
        seqs.add(seq)
    return lines


def parse_running(config: str) -> list[str]:
    """Managed prefix-list entries present in a running configuration."""
    return [l.strip() for l in config.splitlines() if LINE.match(l.strip())]


@dataclass
class FrrInboundFilterAdapter:
    run: Runner
    neighbor: str
    asn: int

    def read(self) -> str:
        config = self.run(["vtysh", "-c", "show running-config"])
        entries = parse_running(config)
        applied = f"neighbor {self.neighbor} route-map {ROUTE_MAP} in" in config
        if entries and not applied:
            return UNATTACHED + "\n" + canonical(entries)
        return canonical(entries) if entries else ""

    def validate(self, candidate: str) -> None:
        validate(candidate)

    def write(self, content: str) -> None:
        lines = validate(content)
        restore_unattached = content.startswith(UNATTACHED + "\n")
        config = self.run(["vtysh", "-c", "show running-config"])
        has_list = bool(parse_running(config))
        has_map = f"route-map {ROUTE_MAP} permit" in config
        applied = f"neighbor {self.neighbor} route-map {ROUTE_MAP} in" in config
        cmds = ["configure terminal"]
        if has_list:
            cmds.append(f"no ip prefix-list {LIST}")
        if lines:
            cmds += lines
            if not has_map:
                cmds += [f"route-map {ROUTE_MAP} permit 10", f"match ip address prefix-list {LIST}", "exit"]
            if applied and restore_unattached:
                cmds += [f"router bgp {self.asn}", "address-family ipv4 unicast",
                         f"no neighbor {self.neighbor} route-map {ROUTE_MAP} in", "exit-address-family", "exit"]
            elif not applied and not restore_unattached:
                cmds += [f"router bgp {self.asn}", "address-family ipv4 unicast",
                         f"neighbor {self.neighbor} route-map {ROUTE_MAP} in", "exit-address-family", "exit"]
        else:
            if applied:
                cmds += [f"router bgp {self.asn}", "address-family ipv4 unicast",
                         f"no neighbor {self.neighbor} route-map {ROUTE_MAP} in", "exit-address-family", "exit"]
            if has_map:
                cmds.append(f"no route-map {ROUTE_MAP}")
        args = ["vtysh"]
        for c in cmds:
            args += ["-c", c]
        self.run(args)

    def activate(self) -> None:
        self.run(["vtysh", "-c", f"clear bgp ipv4 unicast {self.neighbor} soft in"])


def received_routes(run: Runner, neighbor: str) -> dict[str, list[int]]:
    """Prefix -> AS path for what the neighbor announces, before inbound policy
    (needs soft-reconfiguration inbound). Paths BGP will discard as loops are kept,
    so the caller can tell them apart."""
    import json
    out = run(["vtysh", "-c", f"show bgp ipv4 unicast neighbors {neighbor} received-routes json"])
    data = json.loads(out or "{}")
    routes = {}
    for prefix, info in (data.get("receivedRoutes") or {}).items():
        path = info.get("path") if isinstance(info, dict) else None
        if path is None and isinstance(info, dict):
            path = (info.get("aspath") or {}).get("string", "")
        routes[prefix] = [int(a) for a in str(path or "").split() if a.isdigit()]
    return dict(sorted(routes.items()))


def received_prefixes(run: Runner, neighbor: str) -> list[str]:
    return list(received_routes(run, neighbor))
