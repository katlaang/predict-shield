"""Second fresh measured decision-value test: FIVE physical Kafka fault families.

Do not fit, recalibrate or tune the AI model on these measured outcomes.
Each of five CI runners physically executes 12 new configurations (one fault
family, four per stratum), two repetitions and four different intervention
arms, 96 actions in each independent disposable Kafka/JVM laboratory.
Consumer-pause trials require actual listener-pause witness and full resume
between every action; no invented scalar for unsupported authority outages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from collections import Counter
from pathlib import Path

from plan import create_plan, ACTIONS
from audit import inspect_trial, audit_campaign, plan_fingerprint
from campaign import exclusive_lock, register_plan, register_source
from collect import separate_records, source_commit, write_trial_records
from pilot import run_case, wait_ready
from run_v31_subset import resume_all
from train import summarize_operator_telemetry

SEED=20261115312
SCHEMA="predict-shield/five-family-frozen-ai-new-physical-shard/1"
REGISTRATION="predict-shield/five-family-frozen-ai-plan/1"
FAULTS=("loss","delay","duplicate","reorder","consumer_paused")
STRATA=("SIMPLE","INTERACTION","PARTIAL_VISIBILITY")
SHARDS=5
CONFIGS_PER_SHARD=12
REPEATS=2
ACTIONS_PER_SHARD=96


def complete_plan():
    """Freeze configurations before physical results, balanced across strata."""
    original,_=create_plan(seed=SEED)
    shuffled={}
    for stratum in STRATA:
        candidates=[c for c in original if c["complexity_stratum"]==stratum]
        random.Random(SEED+STRATA.index(stratum)).shuffle(candidates)
        if len(candidates)<20:
            raise ValueError("Missing enough independently configured source cases")
        shuffled[stratum]=candidates
    configs=[]
    trials=[]
    for fault_index,fault in enumerate(FAULTS):
        for stratum_index,stratum in enumerate(STRATA):
            subset=shuffled[stratum][4*fault_index:4*(fault_index+1)]
            for source in subset:
                number=len(configs)
                config={**source,
                    "configuration_id":f"new-five-family-{number:03d}",
                    "partition":"test",
                    "fault_mode":fault,
                    "fault_target":(
                        "enforcer-a" if fault=="consumer_paused" and
                        source["fault_target"]=="enforcer-hidden"
                        else source["fault_target"]
                    ),
                    "cache_ttl_ms":max(6500,source["cache_ttl_ms"]),
                    "measurement_seconds":5,
                    "prospective_registration":REGISTRATION,
                    "source_seed":SEED,
                }
                configs.append(config)
                for repeat in range(REPEATS):
                    order=list(ACTIONS)
                    rng=random.Random(int(hashlib.sha256(
                        f"{SEED}|{number}|{repeat}|action-order".encode()
                    ).hexdigest()[:16],16))
                    rng.shuffle(order)
                    shared_seed=int(hashlib.sha256(
                        f"{SEED}|{number}|{repeat}|initial-state".encode()
                    ).hexdigest()[:16],16)
                    for action in order:
                        digest=hashlib.sha256(
                            f"{SEED}|{number}|{repeat}|{action}".encode()
                        ).hexdigest()[:20]
                        trials.append({
                            "run_id":"new-five-family-"+digest,
                            "configuration_id":config["configuration_id"],
                            "partition":"test",
                            "action_id":action,
                            "repeat":repeat,
                            "initial_state_seed":shared_seed,
                            "execution_status":"PLANNED_NOT_EXECUTED",
                            "prospective_registration":REGISTRATION,
                        })
    if len(configs)!=60 or len(trials)!=480 or len({t["run_id"] for t in trials})!=480:
        raise ValueError("Plan must contain 60 new configurations and 480 distinct actions")
    if Counter((c["fault_mode"],c["complexity_stratum"]) for c in configs)!={
            (fault,stratum):4 for fault in FAULTS for stratum in STRATA}:
        raise ValueError("Five-family × three-stratum balance failed")
    if len({c["configuration_id"] for c in configs})!=60:
        raise ValueError("Duplicate configuration")
    if any(c["partition"]!="test" or c["fault_mode"]=="authority_outage" for c in configs):
        raise ValueError("Unvalidated authority outage or non-test partition")
    if len({t["initial_state_seed"] for t in trials})!=120:
        raise ValueError("Repeated physical initial state across matched groups")
    return configs,trials


def manifest(shard:int):
    if type(shard) is not int or not 0<=shard<SHARDS:
        raise ValueError("Invalid physical shard")
    configs,trials=complete_plan()
    selected=[c for c in configs if c["fault_mode"]==FAULTS[shard]]
    names={c["configuration_id"] for c in selected}
    arms=[t for t in trials if t["configuration_id"] in names]
    if (len(selected)!=CONFIGS_PER_SHARD or len(arms)!=ACTIONS_PER_SHARD
            or Counter(c["complexity_stratum"] for c in selected)!=
                Counter({stratum:4 for stratum in STRATA})
            or set(c["fault_mode"] for c in selected)!={FAULTS[shard]}):
        raise ValueError("Incomplete frozen five-family physical shard")
    for cfg in selected:
        for rep in range(REPEATS):
            group=[t for t in arms if t["configuration_id"]==cfg["configuration_id"] and t["repeat"]==rep]
            if len(group)!=4 or {t["action_id"] for t in group}!=set(ACTIONS):
                raise ValueError("Incomplete matched real action arms")
    return selected,arms


def measured_rows(cfgs, trials, records):
    configs={c["configuration_id"]:c for c in cfgs}
    output=[]
    sources=set()
    for t in trials:
        status,reason=inspect_trial(t,records)
        if status!="complete":
            raise ValueError("Missing real complete physical action: "+reason)
        files={name:json.loads((records/name/(t["run_id"]+".json")).read_text())
               for name in ("pre_action","verification","operations","oracle")}
        pre,ver,ops,oracle=[files[name] for name in ("pre_action","verification","operations","oracle")]
        if (len({item["source_commit"] for item in files.values()})!=1
                or pre.get("model_prediction_recorded") is not False
                or pre.get("oracle_features_excluded") is not True
                or ver.get("verification_did_not_read_oracle") is not True):
            raise ValueError("Model/oracle feature isolation or source integrity failed")
        sources.add(pre["source_commit"])
        cfg=configs[t["configuration_id"]]
        conditions=pre["experimental_conditions"]
        if (conditions["fault_mode"]!=cfg["fault_mode"]
                or conditions["fault_target"]!=cfg["fault_target"]
                or pre["decision_policy_metadata"]["restart_permitted"] is not cfg["restart_permitted"]):
            raise ValueError("Unregistered actual physical operating conditions")
        if cfg["fault_mode"]=="consumer_paused":
            witness=oracle.get("physical_fault_evidence")
            if (not isinstance(witness,dict)
                    or witness.get("listener_pause_physically_observed") is not True
                    or witness.get("target_http_status")!=200
                    or oracle["before"].get("all_revoked_access_denied") is not False):
                raise ValueError("No independently witnessed real Kafka consumer pause")
        timeline=ver["timed_gateway_exposure"]
        if (timeline.get("method")!="monotonic_http_step_integral"
                or timeline.get("valid_probe_count",0)<2):
            raise ValueError("Missing real predeclared timed security observation")
        truth=oracle["after"].get("all_revoked_access_denied")
        if type(truth) is not bool or oracle["after"].get("inventory_complete") is not True:
            raise ValueError("Missing full independent authorization oracle")
        attempts,failed=ops.get("observed_requests"),ops.get("failed_requests")
        if (type(attempts) is not int or type(failed) is not int
                or attempts<1 or not 0<=failed<=attempts):
            raise ValueError("Missing measured legitimate-service failures")
        gateway=pre["external_deny_observations"]
        if not gateway or any(x.get("http_status") not in (200,403) for x in gateway):
            raise ValueError("Incomplete pre-action gateway observations")
        features={
            **summarize_operator_telemetry(pre.get("operator_observations",[])),
            "routing_profile":pre.get("routing_profile","balanced"),
            "cache_ttl_ms":pre["features"]["cache_ttl_ms"],
            "requested_rps":pre["features"]["requested_rps"],
            "gateway_visible_enforcer_count":pre["features"]["visible_enforcement_processes"],
            "initial_gateway_allowed_fraction":sum(x["http_status"]==200 for x in gateway)/len(gateway),
        }
        if set(features)&{"fault_mode","fault_target","oracle","post_action","event_delay_ms"}:
            raise ValueError("Hidden laboratory truth leaked into prediction input")
        output.append({
            "group":pre["configuration_id"],
            "repeat":t["repeat"],"action":t["action_id"],
            "partition":"test",
            "fault":conditions["fault_mode"],
            "target":conditions["fault_target"],
            "complexity_stratum":pre["complexity_stratum"],
            "restart_permitted":cfg["restart_permitted"],
            "absolute_error_budget_requests":cfg["absolute_error_budget_requests"],
            "pre_action":features,
            "label_security_exposure":float(not truth),
            "label_path_exposure":float(timeline["exposure_fraction_upper_bound"]),
            "label_absolute_failed_requests":float(failed),
            "label_service_failure_fraction":failed/attempts,
            "consumer_pause_physically_witnessed":(
                True if cfg["fault_mode"]=="consumer_paused" else None),
        })
    if len(output)!=ACTIONS_PER_SHARD or len(sources)!=1:
        raise ValueError("Partial measured shard or source revision mixture")
    return output


def execute(shard:int,root:Path,output:Path):
    if root.exists() or output.exists():
        raise FileExistsError("Do not overwrite real physical outcome records")
    credentials=[os.getenv(x,"") for x in
                 ("LAB_CONTROL_TOKEN","LAB_ORACLE_TOKEN","LAB_INTERNAL_TOKEN")]
    if any(len(token)<24 for token in credentials) or len(set(credentials))!=3:
        raise ValueError("Distinct private disposable control/oracle/internal credentials required")
    configs,trials=manifest(shard)
    records=root/"private-physical-four-streams"
    index={cfg["configuration_id"]:cfg for cfg in configs}
    with exclusive_lock(records):
        register_plan(records,configs,trials)
        register_source(records,source_commit())
        wait_ready()
        for number,trial in enumerate(trials):
            cfg=index[trial["configuration_id"]]
            status,reason=inspect_trial(trial,records)
            if status!="missing":
                raise RuntimeError("Real physical observation already recorded: "+reason)
            resume_all(credentials[0])
            try:
                result=run_case(
                    trial["action_id"],credentials[0],credentials[1],
                    ttl_ms=cfg["cache_ttl_ms"],rps=cfg["requested_rps"],
                    fault_mode=cfg["fault_mode"],fault_target=cfg["fault_target"],
                    delay_ms=cfg["event_delay_ms"],
                    duration_seconds=cfg["measurement_seconds"],
                    gateway_includes_hidden=cfg["gateway_includes_hidden"],
                    routing_profile=cfg["routing_profile"],
                    complexity_stratum=cfg["complexity_stratum"],
                    node_service_latency_ms=tuple(cfg["node_service_latency_ms"]))
                separate=separate_records(cfg,trial,result)
                write_trial_records(records,separate)
                result_state,why=inspect_trial(trial,records)
                if result_state!="complete":
                    raise RuntimeError("Four-stream independent post-action audit: "+why)
            finally:
                resume_all(credentials[0])
            if (number+1)%8==0:
                print(json.dumps({"shard":shard,"real_physical_actions_completed":number+1,
                                  "planned_actions":ACTIONS_PER_SHARD}),flush=True)
        audit=audit_campaign(configs,trials,records)
        if (audit["complete"]!=ACTIONS_PER_SHARD or audit["missing"] or
                audit["invalid"] or audit["partial"] or audit["unexpected_files"] or
                audit["single_source_revision"] is not True):
            raise RuntimeError("No complete four-stream physical campaign evidence")
        data=measured_rows(configs,trials,records)
        raw=json.dumps(data,sort_keys=True,separators=(",",":")).encode()
        report={
            "schema":SCHEMA,"prospective_registration":REGISTRATION,
            "shard_id":shard,"fault_family":FAULTS[shard],
            "independent_new_configuration_groups":CONFIGS_PER_SHARD,
            "physical_replays_completed":ACTIONS_PER_SHARD,
            "repeats_per_configuration":REPEATS,
            "original_frozen_training_run_id":43682077804,
            "frozen_model_not_retrained":True,
            "original_24_group_test_not_reused":True,
            "registered_source_sha256":plan_fingerprint(configs,trials),
            "physical_source_commit":source_commit(),
            "independent_four_stream_audit_passed":True,
            "privileged_oracle_data_uploaded":False,
            "consumer_pause_requires_separate_witness":True,
            "physical_measured_rows_sha256":hashlib.sha256(raw).hexdigest(),
            "measured_physical_rows":data,
            "critical_infrastructure_field_deployment":False,
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
        p.error("Physical defensive action replay requires explicit isolated-lab opt-in")
    result=execute(args.shard,args.root,args.output)
    print(json.dumps({"shard":result["shard_id"],
                      "real_physical_action_count":result["physical_replays_completed"],
                      "report_only_not_field_effectiveness":True}))
