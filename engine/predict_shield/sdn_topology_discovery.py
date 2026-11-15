"""Read-only Open vSwitch topology discovery for a Containernet/Mininet-style SDN lab.

`dependency_graph.build_dependency_graph()` already refuses to infer a
service dependency: every `service_dependencies` entry it accepts must carry
an explicit `evidence_id` naming where the edge came from, and today that
evidence is hand-declared by an operator. This module is a second, honest
source for that same input: it queries the switch's own flow tables for
ports that are actually passing traffic to each other, and only ever reports
an edge between two ports an operator has explicitly named as belonging to a
known service.

An unnamed port is not treated as harmless. A port nobody declared but that
flow evidence shows is actually carrying traffic is exactly what a rogue or
forgotten interface looks like, so `build_topology_report` surfaces every
such port in `active_unnamed_ports`, with the flow evidence behind it. It
never silently drops to an edge instead -- it can't, because an edge
requires a declared service on both ends -- but it is reported as a finding,
not left out of the report.

What this does NOT do:

    * It does not guess which port belongs to which service. A port with no
      entry in the caller-supplied `port_to_service` mapping is never named
      in an edge, no matter what the flow table shows.
    * It does not claim the edge is complete or current beyond the moment of
      the read. A flow table is a live, mutable thing; treat this as one
      observation, not a durable topology fact.
    * It does not touch, configure, or inject into the switch. Every command
      run here is a read command (`list-ports`, `dump-flows`); nothing here
      can change a flow rule or a port.

This targets Open vSwitch specifically because that is the data plane behind
both Mininet/Containernet and ONOS/OpenDaylight-controlled labs, the two
open-source options recommended for exercising PREDICT-SHIELD against
something closer to a real ISP/telecom network than the existing Docker/
Kafka/Java mechanism lab.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from typing import Callable

_BRIDGE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_OFPORT = re.compile(r"^\d+$")
_FLOW_FIELD = re.compile(r"(\w+)=([^, ]+)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_ports(bridge: str, *, runner: Callable = subprocess.run) -> list[str]:
    """The bridge's own port list, read-only (`ovs-vsctl list-ports`).

    Returns interface *names* (e.g. `veth-web`), not the numeric OpenFlow
    port IDs that `dump_flows` reports. The two are different namespaces in
    OVS; `resolve_ofports` is what bridges them.
    """
    if not _BRIDGE_NAME.fullmatch(bridge):
        raise ValueError("Bridge name must be a plain OVS identifier")
    completed = runner(["ovs-vsctl", "list-ports", bridge], capture_output=True,
                       text=True, check=True, timeout=15)
    return sorted({line.strip() for line in completed.stdout.splitlines() if line.strip()})


def resolve_ofports(ports: list[str], *, runner: Callable = subprocess.run) -> dict[str, str]:
    """Map each interface name to the numeric OpenFlow port ID flow entries use
    (`ovs-vsctl get Interface <name> ofport`), read-only, one query per port.

    An interface that OVS cannot resolve to a concrete port (not yet attached,
    or reporting -1/`[]`) is left out rather than guessed at: a missing
    mapping means "we don't know this port's OpenFlow number", never "this
    port doesn't exist".
    """
    resolved = {}
    for port in ports:
        if not _INTERFACE_NAME.fullmatch(port):
            raise ValueError("Interface name must be a plain OVS identifier")
        completed = runner(["ovs-vsctl", "get", "Interface", port, "ofport"],
                           capture_output=True, text=True, check=True, timeout=15)
        value = completed.stdout.strip()
        if _OFPORT.fullmatch(value) and value != "0":
            resolved[value] = port
    return resolved


def dump_flows(bridge: str, *, runner: Callable = subprocess.run) -> list[dict]:
    """Parse `ovs-ofctl dump-flows` output into structured, read-only flow entries.

    Only numeric port identifiers in `in_port=`/`actions=output:` fields are
    kept; anything the parser cannot confidently read is dropped rather than
    guessed at, so a malformed or unexpected line never becomes a false edge.
    """
    if not _BRIDGE_NAME.fullmatch(bridge):
        raise ValueError("Bridge name must be a plain OVS identifier")
    completed = runner(["ovs-ofctl", "dump-flows", bridge], capture_output=True,
                       text=True, check=True, timeout=15)
    entries = []
    for line in completed.stdout.splitlines():
        if "in_port=" not in line or "actions=" not in line:
            continue
        fields = dict(_FLOW_FIELD.findall(line))
        in_port = fields.get("in_port")
        actions = line.rsplit("actions=", 1)[-1].strip()
        out_ports = tuple(sorted({m for m in re.findall(r"output:(\d+)", actions)}))
        try:
            packets = int(fields.get("n_packets", "0"))
            bytes_ = int(fields.get("n_bytes", "0"))
        except ValueError:
            continue
        if in_port is None or not out_ports:
            continue
        entries.append({"in_port": in_port, "out_ports": out_ports,
                        "n_packets": packets, "n_bytes": bytes_})
    return entries


def observed_service_links(bridge: str, port_to_service: dict[str, str],
                           flow_entries: list[dict], *,
                           min_packets: int = 1) -> list[dict]:
    """Edges backed by live flow evidence, limited to operator-named ports.

    `port_to_service` is the trust boundary: it must be supplied by the
    operator (e.g. from the lab's own topology script), never derived from
    anything observed here. A flow between two unnamed ports produces no
    edge; a flow below `min_packets` is not yet evidence of use and is
    skipped, not inverted into "not connected".
    """
    if min_packets < 1:
        raise ValueError("min_packets must be at least 1")
    seen_pairs: set[tuple[str, str]] = set()
    links = []
    for entry in flow_entries:
        if entry["n_packets"] < min_packets:
            continue
        source_service = port_to_service.get(entry["in_port"])
        if not source_service:
            continue
        for out_port in entry["out_ports"]:
            target_service = port_to_service.get(out_port)
            if not target_service or target_service == source_service:
                continue
            pair = (source_service, target_service)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            evidence_id = ("ovs-flow:" + bridge + ":" + entry["in_port"] + "->" + out_port
                          + ":" + hashlib.sha256(
                              json.dumps(entry, sort_keys=True).encode()).hexdigest()[:16])
            links.append({"service": source_service, "depends_on": target_service,
                         "evidence_id": evidence_id})
    return sorted(links, key=lambda link: (link["service"], link["depends_on"]))


def active_unnamed_ports(port_to_service: dict[str, str], flow_entries: list[dict],
                         ofport_to_name: dict[str, str] | None = None, *,
                         min_packets: int = 1) -> list[dict]:
    """Ports that are actually carrying traffic but have no declared owner.

    This is the risk list, distinct from a merely idle unnamed port: a named
    port we have no traffic on is unremarkable, but an *unnamed* port moving
    real packets is exactly what an unlabeled rogue interface, a forgotten
    test link, or a service nobody got around to declaring would look like.
    Each entry carries the flow evidence it was found in, so the finding is
    checkable, not just asserted.
    """
    ofport_to_name = ofport_to_name or {}
    by_port: dict[str, dict] = {}
    for entry in flow_entries:
        if entry["n_packets"] < min_packets:
            continue
        candidates = (entry["in_port"],) + entry["out_ports"]
        for port in candidates:
            if port in port_to_service:
                continue
            record = by_port.setdefault(port, {"ofport": port,
                                               "interface": ofport_to_name.get(port),
                                               "max_packets_observed": 0, "flow_count": 0})
            record["max_packets_observed"] = max(record["max_packets_observed"], entry["n_packets"])
            record["flow_count"] += 1
    return sorted(by_port.values(), key=lambda r: r["ofport"])


def build_topology_report(bridge: str, port_to_service: dict[str, str], *,
                          runner: Callable = subprocess.run, min_packets: int = 1) -> dict:
    """One hashed, read-only snapshot: ports, raw flow entries, the
    service-level links they support under the operator's own port naming,
    and the unnamed ports actually seen carrying traffic (the risk list)."""
    ports = list_ports(bridge, runner=runner)
    ofport_to_name = resolve_ofports(ports, runner=runner)
    flows = dump_flows(bridge, runner=runner)
    unresolved_ports = sorted(p for p in ports if p not in ofport_to_name.values())
    risk = active_unnamed_ports(port_to_service, flows, ofport_to_name, min_packets=min_packets)
    report = {
        "schema": "predict-shield/sdn-topology-report/2",
        "bridge": bridge,
        "collected_at": utc_now(),
        "ports": ports,
        "ofport_to_interface": ofport_to_name,
        "unresolved_ports": unresolved_ports,
        "flow_entries": flows,
        "service_dependencies": observed_service_links(
            bridge, port_to_service, flows, min_packets=min_packets),
        "active_unnamed_ports": risk,
        "live_sdn_evidence": True,
        "complete_topology_verified": False,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["sha256"] = hashlib.sha256(canonical).hexdigest()
    return report
