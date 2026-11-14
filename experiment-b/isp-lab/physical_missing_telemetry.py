"""Physical partial-telemetry benchmark with AI versus graph-closure rules.

Measurements: actual authenticated SNMPv3 GETs on isolated Docker bridge
topologies. Before each GET, a fixed deterministic masking protocol decides
whether the observation is missing. Ground truth comes from host Docker
network membership ONLY AFTER model-input collection. No synthetic labels.

These are *reconfigurations of the same devices*, not independent ISP sites.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from measured_topology_lab import (
    NODES, TRAIN_GROUPS, HELDOUT_GROUPS, partition_protocol, command,
    source_probe, oracle_membership
)
from blindspot_model import fit_blindspot_model

SEED = "missing-telemetry-study-v1-20261114"
MISSING_THRESHOLD = 40  # percent; fixed before observing any network


def observation_available(group: str, src: str, dst: str) -> bool:
    """Independent deterministic missingness, frozen before actual probes."""
    digest=hashlib.sha256(f"{SEED}:{group}:{src}:{dst}".encode()).digest()
    return int.from_bytes(digest[:8],"big") % 100 >= MISSING_THRESHOLD


def assemble_pretruth_graph(group: str, observations: dict) -> dict:
    """Build evidence graph using only actual pre-oracle management responses."""
    valid_nodes=set(NODES)
    evidence=({node:[] for node in NODES})
    edges=[]
    for (src,dst), reply in observations.items():
        if src not in valid_nodes or dst not in valid_nodes or src==dst:
            raise ValueError("Unexpected management observation")
        if reply is None:
            continue
        evidence[src].append({"source_kind":"telemetry",
                              "source_id":"real-snmp-v3:"+group+":"+src})
        if reply:
            edges.append({"source":src,"target":dst,"relation":"ROUTES_TO",
                          "status":"OBSERVED",
                          "evidence":[{"source_kind":"telemetry",
                                       "source_id":"snmp-v3:"+group+":"+src+"->"+dst}]})
    nodes=[{"asset_id":n,"type":"router",
            "evidence_sources":evidence[n] or [{"source_kind":"inventory",
                                                 "source_id":"lab-registered-endpoints"}]}
            for n in NODES]
    return {"schema":"predict-shield/asset-evidence-graph/1",
            "nodes":nodes,"edges":edges,"unresolved_links":[],
            "complete_inventory_verified":False,
            "physical_link_verified":False,
            "source_kind":"pre-oracle-snmpv3-only"}


def run(project: str, output: Path) -> dict:
    if project!="psblindspot":
        raise ValueError("Disposable psblindspot project only")
    if output.exists():
        raise FileExistsError("Refuse to overwrite prior evidence")
    configurations=partition_protocol()
    if len(configurations)!=TRAIN_GROUPS+HELDOUT_GROUPS:
        raise ValueError("Wrong preregistered topology count")
    containers={}
    for name in NODES:
        identifier=command("docker","compose","-p",project,"ps","-q",name).stdout.strip()
        if len(identifier)<12:
            raise ValueError("Missing physical management agent: "+name)
        containers[name]=identifier
    original=project+"_isp"
    segments=[project+"-masked-segment"+str(i) for i in range(3)]
    for segment in segments:
        command("docker","network","create","--internal",segment)
    previous={n:None for n in NODES}
    records=[]
    source_digests=[]
    counts={"attempted":0,"masked":0,"positive_observation":0,"negative_observation":0}
    try:
        for index,configuration in enumerate(configurations):
            group=f"blindspot-physical-topology-{index:02d}"
            split="train" if index<TRAIN_GROUPS else "test"
            for node,segment_number in zip(NODES,configuration):
                destination=segments[segment_number]
                if previous[node]==destination:
                    continue
                command("docker","network","connect","--alias",node,destination,containers[node])
                command("docker","network","disconnect",
                        previous[node] if previous[node] else original,containers[node])
                previous[node]=destination
            observations={}
            for src in NODES:
                for dst in NODES:
                    if src==dst:
                        continue
                    counts["attempted"]+=1
                    if not observation_available(group,src,dst):
                        observations[(src,dst)]=None
                        counts["masked"]+=1
                        continue
                    response=source_probe(containers[src],dst)
                    observations[(src,dst)]=response
                    counts["positive_observation" if response else "negative_observation"]+=1
            # No ground truth is touched until all pre-action features are fixed.
            graph=assemble_pretruth_graph(group,observations)
            before_truth_digest=hashlib.sha256(
                json.dumps(graph,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            oracle=oracle_membership(containers,study_networks=segments)
            oracle_digest=hashlib.sha256(
                json.dumps(oracle,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            source_digests.append({"group":group,"pretruth_graph_sha256":before_truth_digest,
                                   "independent_docker_oracle_sha256":oracle_digest})
            for i,src in enumerate(NODES):
                for dst in NODES[i+1:]:
                    records.append({"topology_group":group,"split":split,"graph":graph,
                                    "source":src,"target":dst,
                                    "verified_reachable":oracle[src]==oracle[dst],
                                    "truth_evidence_id":"separate-docker-oracle:"+group+":"+src+":"+dst})
    finally:
        for node,identity in containers.items():
            old=previous[node]
            if old:
                try:
                    command("docker","network","connect","--alias",node,original,identity)
                    command("docker","network","disconnect",old,identity)
                except (subprocess.SubprocessError,OSError):
                    pass
        for segment in segments:
            try:command("docker","network","rm",segment)
            except (subprocess.SubprocessError,OSError):pass
    if len(records)!=280 or counts["attempted"]!=560 or counts["masked"]<=0:
        raise ValueError("Incomplete real masked-network experiment")
    model,comparison=fit_blindspot_model(records)
    if comparison["heldout_records"]!=80 or comparison["heldout_topology_groups"]!=8:
        raise ValueError("Incomplete heldout case coverage")
    report={
        "schema":"predict-shield/physical-missing-telemetry-ai-v-rule/1",
        "experimental_condition":"preregistered 40% directional SNMP GET missingness",
        "real_snmp_management_probes":counts,
        "train_network_reconfigurations":TRAIN_GROUPS,
        "heldout_network_reconfigurations":HELDOUT_GROUPS,
        "source_digest_pairs":source_digests,
        "all_280_labeled_candidate_records_digest":hashlib.sha256(
            json.dumps(records,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        "trained_model":model,
        "heldout_ai_and_rule_comparison":comparison,
        "disposable_linux_agents_reused":True,
        "independent_external_isp_sites":0,
        "model_accuracy_99_9_verified":False,
        "model_superiority_on_independent_isp_sites":False,
        "ground_truth":"separate host Docker bridge membership, not physical link cabling",
        "interpretation":"Real software-network observations; exploratory model comparison on reused agents",
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("REAL BLINDSPOT COMPARISON",
          "AI",comparison["ai"],"strong graph baseline",comparison["strong_graph_closure_baseline"],
          "independent ISP superiority:",False)
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--project",default="psblindspot")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    run(args.project,args.output)
