"""Synthetic unit tests; never interpreted as a live SDN evidence run."""
import subprocess
import unittest
from unittest.mock import patch

from predict_shield.sdn_topology_discovery import (
    active_unnamed_ports, build_topology_report, dump_flows, list_ports,
    observed_service_links, resolve_ofports,
)

FLOW_OUTPUT = (
    " cookie=0x0, duration=12.3s, table=0, n_packets=42, n_bytes=4200, "
    "in_port=1 actions=output:2\n"
    " cookie=0x0, duration=12.3s, table=0, n_packets=0, n_bytes=0, "
    "in_port=3 actions=output:4\n"
    " cookie=0x0, duration=1.0s, table=0, n_packets=5, n_bytes=300, "
    "in_port=6 actions=output:7,output:5\n"
    "NXST_FLOW reply (xid=0x4): garbage line with no actions\n"
)

# veth-web -> ofport 1, veth-db -> ofport 2, veth-unnamed -> ofport 6.
# Ports 3/4/5/7 appear only in flow entries; no interface resolves to them,
# e.g. they belong to another bridge or are internal/trunk ports.
OFPORT_BY_NAME = {"veth-web": "1", "veth-db": "2", "veth-unnamed": "6"}


def fake_runner(commands_log, flow_stdout=FLOW_OUTPUT, ports_stdout="veth-web\nveth-db\nveth-unnamed\n",
                ofport_by_name=None):
    ofport_by_name = OFPORT_BY_NAME if ofport_by_name is None else ofport_by_name

    def runner(command, **kwargs):
        commands_log.append(command)
        if command[:2] == ["ovs-vsctl", "list-ports"]:
            return subprocess.CompletedProcess(command, 0, stdout=ports_stdout)
        if command[:3] == ["ovs-vsctl", "get", "Interface"] and command[-1] == "ofport":
            value = ofport_by_name.get(command[3], "-1")
            return subprocess.CompletedProcess(command, 0, stdout=value + "\n")
        if command[:2] == ["ovs-ofctl", "dump-flows"]:
            return subprocess.CompletedProcess(command, 0, stdout=flow_stdout)
        raise AssertionError("Unexpected command: " + " ".join(command))
    return runner


class SdnTopologyDiscoveryTests(unittest.TestCase):
    def test_bridge_name_is_validated_before_any_command_runs(self):
        for bad in ("br0; rm -rf /", "../etc", "br 0", ""):
            with self.assertRaises(ValueError):
                list_ports(bad, runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError()))

    def test_list_ports_is_read_only_and_sorted(self):
        log = []
        ports = list_ports("br0", runner=fake_runner(log))
        self.assertEqual(ports, ["veth-db", "veth-unnamed", "veth-web"])
        self.assertEqual(log, [["ovs-vsctl", "list-ports", "br0"]])

    def test_dump_flows_parses_ports_and_counters(self):
        flows = dump_flows("br0", runner=fake_runner([]))
        self.assertEqual(len(flows), 3)  # the garbage line is dropped, not guessed at
        self.assertEqual(flows[0], {"in_port": "1", "out_ports": ("2",),
                                    "n_packets": 42, "n_bytes": 4200})
        self.assertEqual(flows[2]["out_ports"], ("5", "7"))

    def test_resolve_ofports_maps_names_to_numeric_ids(self):
        log = []
        resolved = resolve_ofports(["veth-web", "veth-db", "veth-unnamed"], runner=fake_runner(log))
        self.assertEqual(resolved, {"1": "veth-web", "2": "veth-db", "6": "veth-unnamed"})
        self.assertEqual(len(log), 3)  # one read-only query per interface

    def test_resolve_ofports_drops_unbound_interfaces(self):
        resolved = resolve_ofports(["veth-pending"], runner=fake_runner([], ofport_by_name={}))
        self.assertEqual(resolved, {})  # OVS reports -1; never guessed at

    def test_resolve_ofports_rejects_a_hostile_interface_name(self):
        with self.assertRaises(ValueError):
            resolve_ofports(["veth; rm -rf /"], runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError()))

    def test_only_operator_named_ports_produce_an_edge(self):
        # in_port=1 -> out:2 is named on both ends; in_port=3 -> out:4 has
        # neither port named, so it must produce no edge at all.
        flows = [{"in_port": "1", "out_ports": ("2",), "n_packets": 42, "n_bytes": 4200},
                {"in_port": "3", "out_ports": ("4",), "n_packets": 99, "n_bytes": 9900}]
        port_to_service = {"1": "web", "2": "db"}  # ports 3/4 deliberately unnamed
        links = observed_service_links("br0", port_to_service, flows)
        self.assertEqual(len(links), 1)
        self.assertEqual((links[0]["service"], links[0]["depends_on"]), ("web", "db"))
        self.assertTrue(links[0]["evidence_id"].startswith("ovs-flow:br0:1->2:"))

    def test_zero_packet_flow_produces_no_edge(self):
        flows = dump_flows("br0", runner=fake_runner([]))
        port_to_service = {"3": "idle-a", "4": "idle-b"}
        self.assertEqual(observed_service_links("br0", port_to_service, flows), [])

    def test_self_loop_port_naming_produces_no_edge(self):
        flows = [{"in_port": "1", "out_ports": ("2",), "n_packets": 10, "n_bytes": 100}]
        port_to_service = {"1": "same", "2": "same"}
        self.assertEqual(observed_service_links("br0", port_to_service, flows), [])

    def test_min_packets_threshold_is_enforced(self):
        flows = [{"in_port": "1", "out_ports": ("2",), "n_packets": 3, "n_bytes": 100}]
        port_to_service = {"1": "web", "2": "db"}
        self.assertEqual(observed_service_links("br0", port_to_service, flows, min_packets=5), [])
        self.assertEqual(len(observed_service_links("br0", port_to_service, flows, min_packets=3)), 1)

    def test_min_packets_must_be_at_least_one(self):
        with self.assertRaises(ValueError):
            observed_service_links("br0", {}, [], min_packets=0)

    def test_active_unnamed_ports_flags_traffic_on_undeclared_ports(self):
        flows = dump_flows("br0", runner=fake_runner([]))
        port_to_service = {"1": "web", "2": "db"}  # ports 3/4/5/6/7 all undeclared
        ofport_to_name = {"6": "veth-unnamed"}
        risk = active_unnamed_ports(port_to_service, flows, ofport_to_name)
        ports_seen = {r["ofport"] for r in risk}
        # Port 3/4 carried zero packets (below the default min_packets=1): not a risk.
        self.assertNotIn("3", ports_seen)
        self.assertNotIn("4", ports_seen)
        # Port 6 carried 5 packets and is unnamed: flagged, with its interface resolved.
        entry = next(r for r in risk if r["ofport"] == "6")
        self.assertEqual(entry["interface"], "veth-unnamed")
        self.assertEqual(entry["max_packets_observed"], 5)
        self.assertEqual(entry["flow_count"], 1)
        # Ports 5 and 7 also carried that same traffic but resolve to no known interface.
        self.assertIn("5", ports_seen)
        self.assertIn("7", ports_seen)
        self.assertIsNone(next(r for r in risk if r["ofport"] == "5")["interface"])

    def test_active_unnamed_ports_ignores_named_ports_regardless_of_traffic(self):
        flows = [{"in_port": "1", "out_ports": ("2",), "n_packets": 9999, "n_bytes": 1}]
        risk = active_unnamed_ports({"1": "web", "2": "db"}, flows, {})
        self.assertEqual(risk, [])

    def test_active_unnamed_ports_respects_min_packets(self):
        flows = [{"in_port": "9", "out_ports": ("10",), "n_packets": 2, "n_bytes": 1}]
        self.assertEqual(active_unnamed_ports({}, flows, {}, min_packets=5), [])
        self.assertEqual(len(active_unnamed_ports({}, flows, {}, min_packets=2)), 2)

    def test_build_topology_report_surfaces_resolved_ports_and_the_risk_list(self):
        log = []
        report = build_topology_report("br0", {"1": "web", "2": "db"}, runner=fake_runner(log))
        self.assertEqual(report["schema"], "predict-shield/sdn-topology-report/2")
        self.assertEqual(report["ofport_to_interface"], {"1": "veth-web", "2": "veth-db", "6": "veth-unnamed"})
        self.assertEqual(report["unresolved_ports"], [])  # all three listed interfaces resolved
        self.assertEqual(len(report["service_dependencies"]), 1)
        risk_ports = {r["ofport"] for r in report["active_unnamed_ports"]}
        self.assertEqual(risk_ports, {"5", "6", "7"})
        self.assertFalse(report["complete_topology_verified"])
        self.assertIn("sha256", report)
        # One list-ports, one dump-flows, one ofport query per listed interface (3).
        self.assertEqual(len(log), 5)

    def test_build_topology_report_names_an_interface_ovs_cannot_resolve(self):
        log = []
        report = build_topology_report(
            "br0", {}, runner=fake_runner(log, ports_stdout="veth-pending\n", ofport_by_name={}))
        self.assertEqual(report["unresolved_ports"], ["veth-pending"])
        self.assertEqual(report["ofport_to_interface"], {})

    def test_report_hash_covers_its_own_content(self):
        with patch("predict_shield.sdn_topology_discovery.utc_now", return_value="2026-11-15T00:00:00+00:00"):
            report_a = build_topology_report("br0", {"1": "web", "2": "db"}, runner=fake_runner([]))
            report_b = build_topology_report("br0", {"1": "web", "2": "db"}, runner=fake_runner([]))
            different = build_topology_report("br0", {"1": "web"}, runner=fake_runner([]))
        self.assertEqual(report_a["sha256"], report_b["sha256"])
        self.assertNotEqual(report_a["sha256"], different["sha256"])

    def test_dependency_graph_accepts_the_produced_service_dependencies(self):
        from predict_shield.dependency_graph import build_dependency_graph
        discovery = {"schema": "predict-shield/asset-discovery-report/1",
                    "sha256": "x",
                    "assets": [
                        {"asset_id": "docker:" + "a" * 64, "image_id": "sha256:" + "b" * 64,
                         "container_id": "a" * 64, "service": "web", "criticality": "high"},
                        {"asset_id": "docker:" + "c" * 64, "image_id": "sha256:" + "d" * 64,
                         "container_id": "c" * 64, "service": "db", "criticality": "high"},
                    ],
                    "reconciliation": {"scope_status": "RECONCILED_SOURCES",
                                       "matched": ["a" * 64, "c" * 64]}}
        flows = dump_flows("br0", runner=fake_runner([]))
        links = observed_service_links("br0", {"1": "web", "2": "db"}, flows)
        graph = build_dependency_graph(discovery, service_dependencies=links)
        edge = next(e for e in graph["edges"] if e["relation"] == "DEPENDS_ON")
        self.assertEqual((edge["source"], edge["target"]), ("service:web", "service:db"))
        self.assertTrue(edge["evidence"].startswith("ovs-flow:"))


if __name__ == "__main__":
    unittest.main()
