"""Live Containernet/Open vSwitch smoke test for sdn_topology_discovery.py.

This builds an actual three-host Containernet topology on a real OVS bridge,
generates real traffic between two of the hosts, then runs the discovery
adapter against the real switch -- no mocked transport, no fake OVS CLI. It
proves two things for real, not against a fake runner:

    1. A service dependency the operator declared (web -> db) is found from
       actual observed flow-table traffic, with a real ovs-flow: evidence ID.
    2. The third host ("shadow"), deliberately left out of the operator's
       declaration, still generates real traffic and is reported in
       active_unnamed_ports with its real interface name resolved -- the
       exact risk-flagging behavior added in PR #107, in response to the
       question "shouldn't we call out ports with no name?".

Must run as root (Containernet/Mininet requirement). Not meant to run
outside CI or a disposable VM: it creates real network namespaces, veth
pairs and an OVS bridge on the host it runs on.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from mininet.net import Containernet
from mininet.node import Controller, OVSSwitch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
from predict_shield.sdn_topology_discovery import build_topology_report, resolve_ofports  # noqa: E402


def main() -> None:
    # A real controller, not OVS's own standalone/NORMAL bridging: standalone
    # mode has no per-port OpenFlow entries to read (one generic priority=0
    # actions=NORMAL catch-all covers everything), which is exactly what the
    # first live run against this script found. A controller-programmed
    # switch is also the realistic target case -- ONOS/Ryu/OpenDaylight all
    # install explicit per-flow rules the same way.
    net = Containernet(controller=Controller, switch=OVSSwitch)
    net.addController("c0")
    switch = net.addSwitch("s1")
    web = net.addDocker("web", ip="10.0.0.1/24", dimage="nicolaka/netshoot:latest")
    db = net.addDocker("db", ip="10.0.0.2/24", dimage="nicolaka/netshoot:latest")
    shadow = net.addDocker("shadow", ip="10.0.0.3/24", dimage="nicolaka/netshoot:latest")
    link_web = net.addLink(web, switch)
    link_db = net.addLink(db, switch)
    link_shadow = net.addLink(shadow, switch)
    net.start()
    try:
        time.sleep(3)  # let OVS, the controller handshake, and the container interfaces settle
        # Real traffic: web<->db a few times (declared pair), shadow pings
        # web once too (undeclared port, but it still shows up on the wire).
        print("=== web -> db ping ===")
        print(web.cmd("ping -c 4 -W 2 10.0.0.2"))
        print("=== shadow -> web ping ===")
        print(shadow.cmd("ping -c 2 -W 2 10.0.0.1"))

        web_switch_port = link_web.intf2.name
        db_switch_port = link_db.intf2.name
        shadow_switch_port = link_shadow.intf2.name
        print("=== ovs-vsctl show ===")
        print(subprocess.run(["ovs-vsctl", "show"], capture_output=True, text=True).stdout)
        print("=== ovs-ofctl dump-flows s1 (raw) ===")
        print(subprocess.run(["ovs-ofctl", "dump-flows", "s1"], capture_output=True, text=True).stdout)

        name_to_ofport = {name: ofport for ofport, name in
                          resolve_ofports([web_switch_port, db_switch_port, shadow_switch_port],
                                         runner=subprocess.run).items()}
        print("=== resolved ofports ===", name_to_ofport)
        for required in (web_switch_port, db_switch_port):
            if required not in name_to_ofport:
                raise RuntimeError(f"OVS never resolved an ofport for {required} -- "
                                   "the link likely never attached to the bridge")
        port_to_service = {name_to_ofport[web_switch_port]: "web",
                           name_to_ofport[db_switch_port]: "db"}
        # shadow is deliberately left out of the declaration.

        report = build_topology_report("s1", port_to_service, runner=subprocess.run)
        print("=== full parsed report ===")
        print(json.dumps(report, indent=2))

        declared_pairs = {(link["service"], link["depends_on"])
                          for link in report["service_dependencies"]}
        assert ("web", "db") in declared_pairs or ("db", "web") in declared_pairs, (
            "Expected a real observed web<->db dependency edge, got: " + json.dumps(report["service_dependencies"]))

        shadow_ofport = name_to_ofport.get(shadow_switch_port)
        flagged_ofports = {entry["ofport"] for entry in report["active_unnamed_ports"]}
        assert shadow_ofport is not None and shadow_ofport in flagged_ofports, (
            "Expected the undeclared shadow port to be flagged in active_unnamed_ports, got: "
            + json.dumps(report["active_unnamed_ports"]))
        flagged_entry = next(e for e in report["active_unnamed_ports"] if e["ofport"] == shadow_ofport)
        assert flagged_entry["interface"] == shadow_switch_port, "Risk entry did not resolve the real interface name"

        print("LIVE SDN SMOKE TEST PASSED")
        print("Bridge:", report["bridge"], "sha256:", report["sha256"])
        print("Declared service_dependencies:", json.dumps(report["service_dependencies"], indent=2))
        print("active_unnamed_ports (risk list):", json.dumps(report["active_unnamed_ports"], indent=2))
        Path("/tmp/predict-shield-sdn-live-report.json").write_text(json.dumps(report, indent=2))
    finally:
        net.stop()


if __name__ == "__main__":
    main()
