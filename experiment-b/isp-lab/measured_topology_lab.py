"""Twenty-eight preregistered rewired Linux/SNMP virtual-network topologies.

Uses *actual SNMPv3 management reachability* for pre-truth model inputs.
Docker network membership is read separately afterwards for an independent
same-bridge oracle. A bridge is NOT proof of a physical telecom cable.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import subprocess
from pathlib import Path

from link_learning import FEATURES,train_evaluate
from independent_discovery_eval import evaluate_locked

NODES=("edge-a","aggregation-b","forgotten-c","core-d","radio-e")
SYSNAME="1.3.6.1.2.1.1.5.0"
SEED=20261114
TRAIN_GROUPS=20
HELDOUT_GROUPS=8


def partition_protocol():
    """Generate canonical distinct network partitions before any probing."""
    configurations=[]
    def visit(prefix,maximum):
        if len(prefix)==len(NODES):
            configurations.append(tuple(prefix))
            return
        for value in range(min(maximum+2,3)):
            visit(prefix+[value],max(maximum,value))
    visit([0],0)
    if len(configurations)<TRAIN_GROUPS+HELDOUT_GROUPS:
        raise ValueError("Not enough distinct predeclared testbed topologies")
    random.Random(SEED).shuffle(configurations)
    return configurations[:TRAIN_GROUPS+HELDOUT_GROUPS]


def command(*args,check=True,timeout=15):
    return subprocess.run(list(args),check=check,text=True,
                          capture_output=True,timeout=timeout)


def source_probe(container_id, target):
    """A real read-only SNMPv3 GET run from a separate Docker network member."""
    result=command("docker","exec",container_id,"snmpget","-v3","-l","authPriv",
        "-u","reader","-a","SHA","-x","AES","-Oqv",
        "-t","1","-r","0",f"udp:{target}:161",SYSNAME,
        check=False,timeout=8)
    return result.returncode==0 and result.stdout.strip().strip('"')==target


def oracle_membership(container_ids, *, study_networks):
    """Read independent host Docker network state, never return to the model."""
    result={}
    for name,identity in container_ids.items():
        doc=json.loads(command("docker","inspect",identity).stdout)
        if not isinstance(doc,list) or len(doc)!=1:
            raise ValueError("Incomplete physical network oracle")
        membership=set(doc[0]["NetworkSettings"]["Networks"]) & set(study_networks)
        if len(membership)!=1:
            raise ValueError("Oracle source saw ambiguous network membership")
        result[name]=next(iter(membership))
    return result


def assemble_candidates(group, partition, probes, oracle):
    """Join model inputs to independent labels only after all probes completed."""
    result=[]
    for src,dst in itertools.combinations(NODES,2):
        reachable=probes[(src,dst)] and probes[(dst,src)]
        label=oracle[src]==oracle[dst]
        result.append({
            "topology_id":group,"source":src,"target":dst,
            "split":partition,
            "features":{
                "lldp_seen":False,
                "routing_adjacency_seen":False,
                "bidirectional_flow_seen":bool(reachable),
                "same_site":True,
                "interface_type_compatible":True,
                "inventory_edge_declared":False,
            },
            "verified_link":bool(label),
            "truth_evidence_id":"docker-bridge-membership:"+group+":"+src+":"+dst,
        })
    return result


def run(project:str, output:Path):
    if output.exists():
        raise FileExistsError("Refusing to overwrite measured result")
    if project!="psispstudy":
        raise ValueError("Only a disposable psispstudy Compose project is authorized")
    configs=partition_protocol()
    container_ids={}
    for name in NODES:
        response=command("docker","compose","-p",project,"ps","-q",name)
        identity=response.stdout.strip()
        if len(identity)<12:raise ValueError("Missing real SNMP lab container "+name)
        container_ids[name]=identity
    network_prefix=project+"-probe-segment"
    networks=[network_prefix+str(i) for i in range(3)]
    original=project+"_isp"
    for network in networks:
        command("docker","network","create","--internal",network)
    current={name:None for name in NODES}
    rows=[]
    graph_truth_digests=[]
    try:
        for index,configuration in enumerate(configs):
            group=f"physical-isolated-topology-{index:02d}"
            partition="train" if index<TRAIN_GROUPS else "test"
            for name,segment in zip(NODES,configuration):
                destination=networks[segment]
                previous=current[name]
                if previous==destination:continue
                command("docker","network","connect","--alias",name,
                        destination,container_ids[name])
                command("docker","network","disconnect",
                        previous if previous else original,container_ids[name])
                current[name]=destination
            probes={}
            for src,dst in itertools.permutations(NODES,2):
                probes[(src,dst)]=source_probe(container_ids[src],dst)
            # The oracle is read only AFTER all the model-input measurements.
            truth=oracle_membership(container_ids,study_networks=networks)
            digest=hashlib.sha256(json.dumps(truth,sort_keys=True).encode()).hexdigest()
            graph_truth_digests.append({"group":group,"docker_network_state_sha256":digest})
            rows.extend(assemble_candidates(group,partition,probes,truth))
    finally:
        for name,identity in container_ids.items():
            previous=current[name]
            if previous:
                try:
                    command("docker","network","connect","--alias",name,original,identity)
                    command("docker","network","disconnect",previous,identity)
                except (subprocess.SubprocessError,OSError):
                    pass
        for network in networks:
            try:command("docker","network","rm",network)
            except (subprocess.SubprocessError,OSError):pass
    if len(rows)!=280:
        raise ValueError("Incomplete physical topology observations")
    model,comparison=train_evaluate(rows)
    test_rows=comparison["paired_test_predictions"]
    if len(test_rows)!=80:
        raise ValueError("Heldout physical pair coverage incomplete")
    registered=[f"physical-isolated-topology-{i:02d}"
                for i in range(TRAIN_GROUPS,TRAIN_GROUPS+HELDOUT_GROUPS)]
    # The Docker oracle is independent of SNMP model inputs, but multiple
    # virtual configurations on one host are NOT independently audited ISP sites.
    evaluation=evaluate_locked(test_rows,registered_groups=registered,
                   independent_provenance_attested=False,bootstrap_repeats=5000)
    report={
        "schema":"predict-shield/real-virtual-network-link-discovery-experiment/1",
        "source_kind":"real-snmpv3-probes-and-separate-docker-bridge-membership-oracle",
        "disposable_physical_agent_count":len(NODES),
        "preregistered_topology_reconfigurations":len(configs),
        "original_train_groups":TRAIN_GROUPS,
        "heldout_reconfigured_groups":HELDOUT_GROUPS,
        "actual_candidate_pairs":len(rows),
        "heldout_candidate_pairs":len(test_rows),
        "measured_truth_source_digests":graph_truth_digests,
        "measured_rows_sha256":hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest(),
        "trained_model":model,
        "heldout_metrics":comparison,
        "paired_adjudication":evaluation,
        "no_actual_lldp_or_bgp_observations":True,
        "management_probe_is_not_telemetry_netflow":True,
        "reconfigured_groups_reuse_same_five_agents":True,
        "independently_audited_operator_sites":0,
        "real_isp_or_telecom_equipment_tested":False,
        "external_ai_superiority_established":False,
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("REAL REWIRED NETWORK HELDOUT:",len(configs),"topologies, paired delta",
           evaluation["mean_accuracy_delta"],"CI",
           evaluation["paired_bootstrap_95_percent_interval"],
           "external superiority:",False)
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--project",default="psispstudy")
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    run(args.project,args.output)
