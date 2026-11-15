"""Prospectively frozen, actually executed Kafka/JVM policy comparison.

Three disjoint runners each execute eight NEW configurations, two repeats
and four physical actions (64 actions/shard). All outcome truth comes from
existing audited four-stream physical collector, not from this script.
No AI training, labeling tricks or test-driven action choices.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path

from audit import inspect_trial, audit_campaign, plan_fingerprint
from campaign import run_batch
from collect import source_commit
from plan import create_plan, ACTIONS
from train import summarize_operator_telemetry

SEED=20261115071
SCHEMA="predict-shield/fresh-paired-action-physical-shard/1"
REGISTRATION="predict-shield/prospective-action-benefit-physical-plan/1"
SHARDS=3
CONFIGS_PER_SHARD=8
REPEATS=2
ACTIONS_PER_SHARD=CONFIGS_PER_SHARD*REPEATS*len(ACTIONS)
# Exactly 2 configurations per each of 4 fault families in each distinct
# complexity stratum: simple, interacting and partial visibility.
SOURCE_INDICES=((0,1,2,3,4,5,6,7),
                (12,13,14,15,16,17,18,19),
                (24,25,26,27,28,29,30,31))


def manifest(shard:int):
    if type(shard) is not int or not 0<=shard<SHARDS:
        raise ValueError("Unknown physical shard")
    orig_configs,orig_trials=create_plan(seed=SEED)
    indexes=SOURCE_INDICES[shard]
    renamed={}
    configurations=[]
    for i in indexes:
        original=orig_configs[i]
        name="fresh-benefit-"+str(i).zfill(3)
        renamed[original["configuration_id"]]=name
        new={**original,"configuration_id":name,
             "partition":"test",
             "prospective_protocol":REGISTRATION,
             "research_frozen_model_retrain_permitted":False}
        configurations.append(new)
    trials=[]
    for trial in orig_trials:
        if trial["configuration_id"] not in renamed or trial["repeat"] not in (0,1):
            continue
        name=renamed[trial["configuration_id"]]
        identity=hashlib.sha256(f"{SEED}|{name}|{trial['repeat']}|{trial['action_id']}".encode()).hexdigest()[:20]
        trials.append({**trial,"run_id":"fresh-benefit-run-"+identity,
                       "configuration_id":name,"partition":"test",
                       "prospective_protocol":REGISTRATION})
    if (len(configurations)!=CONFIGS_PER_SHARD
            or len(trials)!=ACTIONS_PER_SHARD
            or len({x["run_id"] for x in trials})!=ACTIONS_PER_SHARD):
        raise ValueError("Incomplete prospectively frozen physical registration")
    faults=Counter(c["fault_mode"] for c in configurations)
    if faults!=Counter({"loss":2,"delay":2,"duplicate":2,"reorder":2}):
        raise ValueError("Fault families not balanced in new lab")
    if len({c["complexity_stratum"] for c in configurations})!=1:
        raise ValueError("Shard mixes declared complexity stratum")
    if any(t["partition"]!="test" for t in trials):
        raise ValueError("Future physical test must not be used for training")
    return configurations,trials


def _export_actual_rows(configs:list[dict],trials:list[dict],records:Path):
    indexed={c["configuration_id"]:c for c in configs}
    observations=[]
    revisions=set()
    for trial in trials:
        status,reason=inspect_trial(trial,records)
        if status!="complete":
            raise ValueError("Missing independently audited real physical action: "+reason)
        names=("pre_action","verification","operations","oracle")
        streams={name:json.loads((records/name/(trial["run_id"]+".json")).read_text())
                 for name in names}
        pre,ver,op,oracle=(streams[k] for k in names)
        if (len({s["source_commit"] for s in streams.values()})!=1
                or pre.get("model_prediction_recorded") is not False
                or pre.get("oracle_features_excluded") is not True
                or ver.get("verification_did_not_read_oracle") is not True):
            raise ValueError("Oracle leakage or untrusted mixed physical source")
        revisions.add(pre["source_commit"])
        cfg=indexed[trial["configuration_id"]]
        conditions=pre["experimental_conditions"]
        if (conditions["fault_mode"]!=cfg["fault_mode"]
                or conditions["fault_target"]!=cfg["fault_target"]
                or pre["decision_policy_metadata"]["restart_permitted"] != cfg["restart_permitted"]):
            raise ValueError("Unregistered physically injected conditions")
        timeline=ver["timed_gateway_exposure"]
        if timeline["method"]!="monotonic_http_step_integral" or timeline["valid_probe_count"]<2:
            raise ValueError("No actual time-integrated security measurement")
        truth=oracle["after"].get("all_revoked_access_denied")
        if type(truth) is not bool or oracle["after"].get("inventory_complete") is not True:
            raise ValueError("Incomplete independent physical authorization oracle")
        attempts=op["observed_requests"];failed=op["failed_requests"]
        if (type(attempts) is not int or type(failed) is not int
                or not 0<=failed<=attempts or attempts<1):
            raise ValueError("No independently measured legitimate request failures")
        gateway=pre["external_deny_observations"]
        if not gateway or any(x.get("http_status") not in (200,403) for x in gateway):
            raise ValueError("No complete observed pre-action gateway")
        features={
            **summarize_operator_telemetry(pre["operator_observations"]),
            "routing_profile":pre.get("routing_profile","balanced"),
            "cache_ttl_ms":pre["features"]["cache_ttl_ms"],
            "requested_rps":pre["features"]["requested_rps"],
            "gateway_visible_enforcer_count":pre["features"]["visible_enforcement_processes"],
            "initial_gateway_allowed_fraction":sum(x["http_status"]==200 for x in gateway)/len(gateway),
        }
        if set(features) & {"fault_mode","fault_target","oracle","post_action","event_delay_ms"}:
            raise ValueError("Privileged experimental truth leaked into AI inputs")
        observations.append({
            "group":pre["configuration_id"],"partition":"test",
            "repeat":trial["repeat"],"action":trial["action_id"],
            "fault":conditions["fault_mode"],"target":conditions["fault_target"],
            "complexity_stratum":pre["complexity_stratum"],
            "restart_permitted":cfg["restart_permitted"],
            "absolute_error_budget_requests":cfg["absolute_error_budget_requests"],
            "pre_action":features,
            "label_security_exposure":float(not truth),
            "label_path_exposure":float(timeline["exposure_fraction_upper_bound"]),
            "label_absolute_failed_requests":float(failed),
            "label_service_failure_fraction":failed/attempts,
        })
    if len(observations)!=ACTIONS_PER_SHARD or len(revisions)!=1:
        raise ValueError("Incomplete real physical shard or mixed source commits")
    return observations


def run(shard:int,root:Path,output:Path):
    if root.exists() or output.exists():
        raise FileExistsError("Refuse to overwrite real physics research evidence")
    control,oracle,internal=(os.environ.get(x,"") for x in
                             ("LAB_CONTROL_TOKEN","LAB_ORACLE_TOKEN","LAB_INTERNAL_TOKEN"))
    if min(map(len,(control,oracle,internal)))<24 or len({control,oracle,internal})!=3:
        raise ValueError("Three distinct disposable control/independent oracle tokens required")
    cfg,trials=manifest(shard)
    records=root/"raw-four-streams-private"
    for start in range(0,len(trials),8):
        result=run_batch(cfg,trials,records,control,oracle,start=start,max_trials=8)
        if (result["newly_executed_trials"]!=8
                or result["partial"] or result["invalid"]):
            raise RuntimeError("Incomplete real physical batch; do not promote result")
        print("FRESH PHYSICAL",shard,result["total_completed"],"of",ACTIONS_PER_SHARD,flush=True)
    status=audit_campaign(cfg,trials,records)
    if (status["complete"]!=ACTIONS_PER_SHARD or status["partial"] or
            status["invalid"] or status["missing"] or status["unexpected_files"] or
            status["single_source_revision"] is not True):
        raise ValueError("Independent full four-stream physical integrity audit failed")
    samples=_export_actual_rows(cfg,trials,records)
    encoded=json.dumps(samples,sort_keys=True,separators=(",",":")).encode()
    report={
        "schema":SCHEMA,
        "prospective_protocol":REGISTRATION,
        "registration_sha256":plan_fingerprint(cfg,trials),
        "source_commit_sha":source_commit(),
        "shard_id":shard,
        "independent_new_configurations":CONFIGS_PER_SHARD,
        "actual_physical_action_replays":ACTIONS_PER_SHARD,
        "repeats_per_configuration":REPEATS,
        "physical_four_stream_audit":True,
        "model_prediction_made_before_oracle_labels":False,
        "decision_policy_frozen_before_new_measurements":True,
        "pre_action_model_features_exclude_private_oracle":True,
        "sanitized_new_measured_rows":samples,
        "sanitized_rows_sha256":hashlib.sha256(encoded).hexdigest(),
        "raw_privileged_oracle_data_uploaded":False,
        "already_used_for_training":False,
        "real_critical_infrastructure_operator":False,
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,sort_keys=True,separators=(",",":"))+"\n")
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--execute-disposable-lab",action="store_true")
    p.add_argument("--shard",type=int,required=True)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    if not args.execute_disposable_lab:
        p.error("No real network mutations without explicit disposable-lab opt-in")
    r=run(args.shard,args.root,args.output)
    print(json.dumps({"physical_actions":r["actual_physical_action_replays"],
                      "shard":r["shard_id"],"ai_superiority_claim":False}))
