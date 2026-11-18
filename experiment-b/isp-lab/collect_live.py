"""Real SNMPv3 physical-agent lab inventory reconciliation.

Compares actual agent sysName observations with a deliberately incomplete
declared inventory. Does not assume Docker network implies router forwarding.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from predict_shield.telecom_collectors import snmpv3_sysname
from predict_shield.telecom_graph import build_graph,compare_inventory_observations

def run(output: Path):
    declared={"schema":"predict-shield/telecom-source-export/1",
       "source_kind":"inventory","source_id":"lab-oss-preregistered",
       "collected_at":"2026-11-14T00:00:00Z",
       "assets":[{"asset_id":n,"type":"router","attributes":{"source":"incomplete-lab-register"}}
                 for n in ("edge-a","aggregation-b")],
       "links":[]}
    exports=[declared]
    for name,port in (("edge-a",11611),("aggregation-b",11612),("forgotten-c",11613)):
        observed=snmpv3_sysname(device_id=name,port=port,user="reader",
          auth_passphrase=os.environ["LAB_SNMP_AUTH"],
          privacy_passphrase=os.environ["LAB_SNMP_PRIV"])
        if observed["assets"][0]["attributes"]["name"]!=name:
            raise ValueError("Unexpected SNMPv3 agent returned inconsistent sysName")
        exports.append(observed)
    graph=build_graph(exports)
    drift=compare_inventory_observations(graph)
    if drift["observed_not_registered"]!=["forgotten-c"]:
        raise ValueError("Expected actual SNMPv3 observation of unregistered agent")
    report={"schema":"predict-shield/real-snmp-lab-observation/1",
       "lab_scope":"disposable-linux-snmp-agents-on-docker-not-real-router-firmware",
       "live_snmpv3_authpriv_agents":3,
       "declared_oss_agents":2,
       "observed_unregistered_agents":drift["observed_not_registered"],
       "declared_minus_observed":drift["registered_not_observed"],
       "graph_digest":graph["sha256"],
       "physical_topology_verified":False,
       "real_isp_validated":False}
    if output.exists():
        raise FileExistsError("Evidence file exists")
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    result=run(args.output)
    print("LIVE SNMPV3 OBSERVATIONS:",result["live_snmpv3_authpriv_agents"],
          "unregistered:",result["observed_unregistered_agents"])
