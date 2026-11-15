"""Synthetic unit tests; never interpreted as a live SDN evidence run."""
import subprocess
import unittest
from unittest.mock import patch

from predict_shield.sdn_topology_discovery import (
    build_topology_report, dump_flows, list_ports, observed_service_links,
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


def fake_runner(commands_log, flow_stdout=FLOW_OUTPUT, ports_stdout="veth-web\nveth-db\nveth-unnamed\n"):
    def runner(command, **kwargs):
        commands_log.append(command)
        if command[:2] == ["ovs-vsctl", "list-ports"]:
            return subprocess.CompletedProcess(command, 0, stdout=ports_stdout)
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

    def test_build_topology_report_is_hashed_and_names_unmapped_ports(self):
        log = []
        report = build_topology_report("br0", {"1": "web", "2": "db"}, runner=fake_runner(log))
        self.assertEqual(report["schema"], "predict-shield/sdn-topology-report/1")
        self.assertEqual(report["unnamed_ports"], ["veth-db", "veth-unnamed", "veth-web"])
        self.assertEqual(len(report["service_dependencies"]), 1)
        self.assertFalse(report["complete_topology_verified"])
        self.assertIn("sha256", report)
        # Two read-only commands only: list-ports and dump-flows.
        self.assertEqual(len(log), 2)

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
