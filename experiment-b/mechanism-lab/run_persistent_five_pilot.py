"""Real five-family physical decision-diversity pilot before learned-policy test.

Runs 30 independent Kafka configurations x 2 repeats x 4 actions. Adds
actual consumer-paused persistent faults, while the externally stopped
authority is excluded because its live oracle outcome is UNKNOWN.
No simulated outcome, cherry-picked winner or unapproved full campaign.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from audit import inspect_trial, audit_campaign, plan_fingerprint
from campaign import exclusive_lock, register_plan, register_source
from collect import separate_records, source_commit, write_trial_records
from decision_eval import ACTIONS, observed_utility
from persistent_ai_plan import build, save, FAULTS
from pilot import run_case, wait_ready
from run_v31_subset import resume_all


def evaluate_results(configs: list[dict], trials: list[dict], records: Path) -> dict:
    indexed=defaultdict(dict)
    commits=set()
    byid={c["configuration_id"]:c for c in configs}
    for trial in trials:
        state,reason=inspect_trial(trial,records)
        if state!="complete":
            raise ValueError("Unverified physical action: "+reason)
        files={name:json.loads((records/name/(trial["run_id"]+".json")).read_text())
               for name in ("pre_action","verification","operations","oracle")}
        pre,ver,op,oracle=[files[k] for k in
                           ("pre_action","verification","operations","oracle")]
        commits.add(pre["source_commit"])
        cfg=byid[trial["configuration_id"]]
        if (len({x["source_commit"] for x in files.values()})!=1 or
                pre["oracle_features_excluded"] is not True or
                ver["verification_did_not_read_oracle"] is not True):
            raise ValueError("Four stream source or oracle boundary failure")
        if cfg["fault_mode"]=="consumer_paused":
            witness=oracle.get("physical_fault_evidence")
            if (not isinstance(witness,dict) or
                witness.get("listener_pause_physically_observed") is not True or
                witness.get("target_http_status")!=200 or
                oracle["before"]["all_revoked_access_denied"] is not False):
                raise ValueError("Consumer listener pause was not independently physically witnessed")
        exposure=ver["timed_gateway_exposure"]
        if exposure["valid_probe_count"]<2:
            raise ValueError("No independent physical gateway exposure probes")
        truth=oracle["after"]["all_revoked_access_denied"]
        if type(truth) is not bool or oracle["after"]["inventory_complete"] is not True:
            raise ValueError("Independent four-node authoritative verdict unavailable")
        failures=op["failed_requests"]
        if not type(failures) is int or not 0<=failures<=op["observed_requests"]:
            raise ValueError("Missing actual authorized request failure measurement")
        utility=observed_utility({
            "label_path_exposure":exposure["exposure_fraction_upper_bound"],
            "label_security_exposure":float(not truth),
            "label_absolute_failed_requests":failures,
            "absolute_error_budget_requests":cfg["absolute_error_budget_requests"],
        })
        key=(trial["configuration_id"],trial["repeat"])
        if trial["action_id"] in indexed[key]:
            raise ValueError("Duplicate physical action in paired replay")
        indexed[key][trial["action_id"]]=utility
    if len(commits)!=1 or len(indexed)!=60:
        raise ValueError("Missing independent physical configurations/repeats")
    group_result=[];physical_optima=Counter();groups_not_resync=0
    for cfg in configs:
        ident=cfg["configuration_id"]
        rows=[indexed[(ident,r)] for r in (0,1)]
        if any(set(x)!=set(ACTIONS) for x in rows):
            raise ValueError("Missing real measured physical action")
        allowed=[a for a in ACTIONS if cfg["restart_permitted"] or a!="restart_enforcer"]
        means={a:sum(x[a] for x in rows)/2 for a in ACTIONS}
        best=min(means[a] for a in allowed)
        near=[a for a in allowed if means[a]<=best+.001]
        winners=[a for a in allowed if abs(means[a]-best)<1e-9]
        if "resync_policy" not in near:
            groups_not_resync+=1
        if len(near)==1:physical_optima[near[0]]+=1
        group_result.append({
            "group":ident,"partition":cfg["partition"],"fault_family":cfg["fault_mode"],
            "complexity_stratum":cfg["complexity_stratum"],
            "restart_permitted":cfg["restart_permitted"],
            "eligible_actions":allowed,"measured_mean_action_costs":means,
            "within_0p001_best_actions":near,
            "strict_physical_mean_minima":winners,
            "fixed_resync_regret":means["resync_policy"]-best,
            "source":"independently_audited_disposable_physical_Kafka_JVM_lab",
        })
    return {
        "schema":"predict-shield/persistent-five-family-physical-feasibility/1",
        "source_commit_sha":next(iter(commits)),
        "plan_sha256":plan_fingerprint(configs,trials),
        "physical_action_replays":240,
        "independent_configuration_groups":30,
        "four_streams_per_action_audited":True,
        "fault_family_group_counts":dict(Counter(c["fault_mode"] for c in configs)),
        "group_optima_excluding_resync":groups_not_resync,
        "group_optima_resync_mismatch_fraction":groups_not_resync/30,
        "unique_near_optimal_action_counts":dict(physical_optima),
        "per_group_results":group_result,
        "learned_AI_model_trained":False,
        "full_six_family_v31_feasibility_established":False,
        "field_critical_infrastructure_benefit_established":False,
        "status":"PHYSICAL_PERSISTENT_FAULT_HEADROOM_EXPLORATORY_ONLY",
        "limitations":[
            "Two physical repeats within one configuration do not count as two independent configs",
            "This measures physical action headroom before fitting any model or accessing future heldout labels",
            "A fifth consumer pause family is physical, but authority-outage UNKNOWN outcomes are not scored",
            "This does not justify AI superiority, prospective confirmatory power or national field impact",
        ],
    }


def execute(root:Path,report_path:Path,control:str,oracle:str) -> dict:
    if root.exists() or report_path.exists():
        raise FileExistsError("Never overwrite an executed research experiment")
    if min(len(control),len(oracle))<24 or control==oracle:
        raise ValueError("Distinct disposable lab control and oracle credentials required")
    configs,trials=build()
    plan_dir=root/"registration";save(plan_dir)
    records=root/"private-four-streams"
    with exclusive_lock(records):
        register_plan(records,configs,trials)
        register_source(records,source_commit())
        wait_ready()
        for index,trial in enumerate(trials):
            cfg=next(c for c in configs if c["configuration_id"]==trial["configuration_id"])
            state,_=inspect_trial(trial,records)
            if state!="missing":raise RuntimeError("Pilot would overwrite or accept partial physical record")
            resume_all(control)
            try:
                result=run_case(
                    trial["action_id"],control,oracle,
                    ttl_ms=cfg["cache_ttl_ms"],rps=cfg["requested_rps"],
                    fault_mode=cfg["fault_mode"],fault_target=cfg["fault_target"],
                    delay_ms=cfg["event_delay_ms"],
                    duration_seconds=cfg["measurement_seconds"],
                    gateway_includes_hidden=cfg["gateway_includes_hidden"],
                    routing_profile=cfg["routing_profile"],
                    complexity_stratum=cfg["complexity_stratum"],
                    node_service_latency_ms=tuple(cfg["node_service_latency_ms"]))
                record=separate_records(cfg,trial,result)
                write_trial_records(records,record)
                complete,reason=inspect_trial(trial,records)
                if complete!="complete":
                    raise RuntimeError("Raw Kafka physical replay failed four-stream audit: "+reason)
            finally:
                resume_all(control)
            if (index+1)%12==0:
                print(json.dumps({"actual_physical_action_replays":index+1,
                                  "planned_physical_action_replays":240}),flush=True)
        audit=audit_campaign(configs,trials,records)
        if (audit["complete"]!=240 or audit["partial"] or audit["invalid"]
                or audit["missing"] or audit["unexpected_files"]):
            raise RuntimeError("Incomplete 240 physical measured action records")
        report=evaluate_results(configs,trials,records)
        report["audit"]={key:audit[key] for key in
                         ("complete","missing","partial","invalid","unexpected_files")}
        report_path.parent.mkdir(parents=True,exist_ok=True)
        with report_path.open("x") as f:
            json.dump(report,f,indent=2,sort_keys=True);f.write("\n")
        return report


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--execute-lab",action="store_true")
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    args=p.parse_args()
    if not args.execute_lab:p.error("Physical Docker mutation requires --execute-lab")
    env=[os.getenv(n,"") for n in ("LAB_CONTROL_TOKEN","LAB_ORACLE_TOKEN","LAB_INTERNAL_TOKEN")]
    if any(len(x)<24 for x in env) or len(set(env))!=3:
        p.error("Require three distinct disposable credentials")
    report=execute(args.root,args.report,env[0],env[1])
    print(json.dumps({"actual_physical_actions":report["physical_action_replays"],
                      "new_fault_family":"consumer_paused",
                      "mismatched_configurations":report["group_optima_excluding_resync"],
                      "ai_model_tested":False,"confirmatory":False}))
