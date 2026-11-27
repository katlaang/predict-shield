"""Strictly measured, offline defense-selection study for registered PR #196.

The pilot estimates sample size; it never tests H1/H2. Main accepts only a
pre-outcome committed size lock and evaluates three repeats per configuration.
A green workflow does not imply AI superiority or autonomous execution.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from statistics import NormalDist

from confirmatory_196_plan import (REGISTRATION_COMMIT, REGISTERED_SEED,
                                   make_plan, selected)
from collect import load_plan
from train import _read_stream, summarize_operator_telemetry, to_features, ROUTING_PROFILES
from paired_defense_eval import make_trusted_lab_model_policy, ACTIONS

MODEL_SHA = "87208240dbea19b34c4a5ac067639ac9cdb484b2de8f1985dbbcd143d4fe3b39"
BOOTSTRAP_SEED = 2026112701
NON_INFERIORITY_MARGIN = .10
REPEATS = 3
EXPOSURE_LABEL = "label_security_exposure"


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
                 separators=(",", ":")).encode()).hexdigest()


def read_measured(plan: Path, records: Path, *, phase: str, shard: int):
    expected_c,expected_t=make_plan(phase=phase,shard=shard)
    configs,trials=load_plan(plan)
    if digest([configs,trials]) != digest([expected_c,expected_t]):
        raise ValueError("Unfrozen or unregistered cohort plan")
    choice={c["configuration_id"]:c for c in selected(configs,phase=phase)}
    wanted={t["run_id"]:t for t in trials if t["configuration_id"] in choice}
    # A main shard may be restricted by a committed lock to a subset of
    # selected groups; never silently infer a missing action is a success.
    sources={k:_read_stream(records/k) for k in ("pre_action","verification","operations","oracle")}
    for k,v in sources.items():
        if not set(v).issubset(wanted):
            raise ValueError("Unregistered or unexpected physical "+k+" records")
    ids=set(sources["pre_action"])
    if not ids or any(set(v)!=ids for v in sources.values()):
        raise ValueError("INCONCLUSIVE: missing or conflicting four-stream physical records")
    # The pilot requires all 16 configurations. Main shards are explicit and
    # never accept a partial configuration, but may include fewer than 20.
    if phase=="pilot" and len(ids)!=16*12:
        raise ValueError("INCONCLUSIVE: pilot requires all 192 action arms")
    rows,source_revisions=[],set()
    for run_id in sorted(ids):
        t=wanted[run_id]
        pre,verify,ops,oracle=(sources[k][run_id] for k in
                              ("pre_action","verification","operations","oracle"))
        for r in (pre,verify,ops,oracle):
            if any(r.get(k)!=v for k,v in (
                ("run_id",run_id),("configuration_id",t["configuration_id"]),
                ("repeat",t["repeat"]),("action_id",t["action_id"]),
                ("partition","test"),("initial_state_seed",t["initial_state_seed"]),
                ("experiment_type","real_kafka_multijvm_lab")):
                raise ValueError("Cross-stream trial identity mismatch")
        revisions={r.get("source_commit") for r in (pre,verify,ops,oracle)}
        if len(revisions)!=1:
            raise ValueError("Source revisions disagree within a physical arm")
        revision=revisions.pop()
        if not isinstance(revision,str) or len(revision)!=40:
            raise ValueError("Invalid physical source fingerprint")
        source_revisions.add(revision)
        if pre.get("model_prediction_recorded") is not False or pre.get("oracle_features_excluded") is not True:
            raise ValueError("Untrusted pre-action feature provenance")
        features=pre.get("features",{})
        if any(x in features for x in ("fault_mode","fault_target","oracle_truth","event_delay_ms")):
            raise ValueError("Private injected fault leaked into model features")
        readings=pre.get("operator_observations")
        expected_nodes={"enforcer-a","enforcer-b","enforcer-c","enforcer-hidden"}
        if (not isinstance(readings,list) or len(readings)!=4
                or {r.get("node") for r in readings if isinstance(r,dict)}!=expected_nodes
                or any(r.get("observed") is not True
                       or r.get("operator_schema")!="operator_pre_action_v2"
                       for r in readings)):
            raise ValueError("VOID: incomplete source-verified operator telemetry")
        truth=oracle.get("after",{})
        if (oracle.get("oracle_role")!="separate_process_admin_plus_direct_probe"
                or truth.get("inventory_complete") is not True
                or type(truth.get("all_revoked_access_denied")) is not bool):
            raise ValueError("VOID: independent post-action oracle incomplete")
        timeline=verify.get("timed_gateway_exposure",{})
        if (timeline.get("method")!="monotonic_http_step_integral"
                or timeline.get("valid_probe_count",0)<2
                or not 0<=timeline.get("exposure_fraction_lower_bound",-1)
                     <=timeline.get("exposure_fraction_upper_bound",-1)<=1):
            raise ValueError("VOID: verified gateway exposure missing")
        attempts,failures=ops.get("observed_requests"),ops.get("failed_requests")
        if (type(attempts) is not int or attempts<1 or type(failures) is not int
                or not 0<=failures<=attempts):
            raise ValueError("VOID: legitimate request denominator absent")
        policy=pre.get("decision_policy_metadata",{})
        if (type(policy.get("restart_permitted")) is not bool
                or type(policy.get("absolute_error_budget_requests")) is not int
                or policy["absolute_error_budget_requests"]<1):
            raise ValueError("VOID: missing authorization/budget")
        probes=pre.get("external_deny_observations")
        if not isinstance(probes,list) or not probes or any(
                x.get("http_status") not in (200,403) for x in probes):
            raise ValueError("VOID: pre-action gateway observation incomplete")
        if pre.get("routing_profile") not in ROUTING_PROFILES:
            raise ValueError("VOID: invalid observed routing profile")
        rows.append({
            "group":t["configuration_id"],"repeat":t["repeat"],
            "action":t["action_id"],"partition":"test",
            "restart_permitted":policy["restart_permitted"],
            "absolute_error_budget_requests":policy["absolute_error_budget_requests"],
            "pre_action": {
                **summarize_operator_telemetry(readings),
                "routing_profile":pre["routing_profile"],
                "cache_ttl_ms":features["cache_ttl_ms"],
                "requested_rps":features["requested_rps"],
                "gateway_visible_enforcer_count":features["visible_enforcement_processes"],
                "initial_gateway_allowed_fraction":
                    sum(p["http_status"]==200 for p in probes)/len(probes),
            },
            "label_security_exposure":float(not truth["all_revoked_access_denied"]),
            "label_path_exposure":float(timeline["exposure_fraction_upper_bound"]),
            "label_absolute_failed_requests":float(failures),
            "raw_source_sha256":hashlib.sha256(json.dumps(
                [pre,verify,ops,oracle],sort_keys=True).encode()).hexdigest(),
        })
    if len(source_revisions)!=1:
        raise ValueError("VOID: mixed physical collector source revisions")
    episodes=defaultdict(set)
    for r in rows:
        episodes[(r["group"],r["repeat"])].add(r["action"])
    if any(x!=set(ACTIONS) for x in episodes.values()):
        raise ValueError("INCONCLUSIVE: action arm missing from physical episode")
    groups={g for g,_ in episodes}
    if len(episodes)!=REPEATS*len(groups):
        raise ValueError("INCONCLUSIVE: group lacks 3 action episodes")
    if phase=="pilot" and len(groups)!=16:
        raise ValueError("VOID: incomplete 16-group pilot")
    return rows, {
        "phase":phase,"shard":shard,"source_commit":next(iter(source_revisions)),
        "groups":len(groups),"physical_arms":len(rows),
        "four_stream_digest_sha256":digest(sources),
        "plan_digest_sha256":digest([configs,trials]),
        "registered_seed":REGISTERED_SEED,
        "registration_commit_sha":REGISTRATION_COMMIT,
        "no_model_action_executed":True,
        "raw_outcomes_not_used_for_model_fit":True,
    }


def expert_ladder(ctx,eligible):
    pre=ctx["pre_action"]
    if pre["operator_missing_count"]>0:
        return "escalate"
    if pre["cache_ttl_ms"]<=4000 and pre["operator_pending_callback_count"]>0:
        return "monitor_only"
    return "restart_enforcer" if "restart_enforcer" in eligible else "escalate"


def ai_escalation(ctx,eligible,proposed):
    pre=ctx["pre_action"]
    if (proposed in ("monitor_only","resync_policy")
            and not (pre["cache_ttl_ms"]<=4000 and pre["operator_pending_callback_count"]>0)
            and pre["initial_gateway_allowed_fraction"]>0):
        return "escalate"
    return proposed


def transparency_rule(ctx,eligible):
    pre=ctx["pre_action"]
    if pre["operator_missing_count"]>0:
        return "escalate"
    if pre["initial_gateway_allowed_fraction"]==0:
        return "monitor_only"
    if pre["cache_ttl_ms"]<=4000 and pre["operator_pending_callback_count"]>0:
        return "monitor_only"
    if ("restart_enforcer" in eligible and pre["requested_rps"]<=30
            and pre["operator_max_service_latency_ms"]<=55):
        return "restart_enforcer"
    if pre["requested_rps"]<=20:
        return "gateway_restrict"
    return "resync_policy"


def group_summary(rows,bundle,training_metrics):
    episodes=defaultdict(dict)
    for r in rows:
        episodes[(r["group"],r["repeat"])][r["action"]]=r
    selector=make_trusted_lab_model_policy(bundle)
    per_group=defaultdict(lambda:defaultdict(list))
    records=[]
    calibrated_by_group=defaultdict(list)
    for (group,repeat),actions in sorted(episodes.items()):
        if set(actions)!=set(ACTIONS):
            raise ValueError("INCONCLUSIVE: incomplete physical action arms")
        base=actions["monitor_only"]
        eligible=tuple(a for a in ACTIONS if a!="restart_enforcer" or base["restart_permitted"])
        ctx={"pre_action":dict(base["pre_action"]),
             "absolute_error_budget_requests":base["absolute_error_budget_requests"],
             "restart_permitted":base["restart_permitted"]}
        ai=selector(ctx,eligible)
        choices={
            "ai":ai if ai in eligible else "escalate",
            "ai_escalation":ai_escalation(ctx,eligible,ai) if ai in eligible else "escalate",
            "expert_E":expert_ladder(ctx,eligible),
            "restart_if_authorized":"restart_enforcer" if "restart_enforcer" in eligible else "monitor_only",
            "monitor_only":"monitor_only",
            "resync_policy":"resync_policy",
            "transparent_heuristic":transparency_rule(ctx,eligible),
        }
        best_eligible=any(actions[a]["label_security_exposure"]==0 and
                          actions[a]["label_absolute_failed_requests"]<=base["absolute_error_budget_requests"]
                          for a in eligible)
        choices["oracle_best_authorized"]="oracle_upper_bound"
        results={}
        for name,action in choices.items():
            if action=="oracle_upper_bound":
                success=best_eligible
                failures=min((actions[a]["label_absolute_failed_requests"]
                              for a in eligible if actions[a]["label_security_exposure"]==0
                              and actions[a]["label_absolute_failed_requests"]<=base["absolute_error_budget_requests"]),
                             default=0)
                actual_action="hindsight_analysis_only"
                cost=None
            else:
                # Preregistered H2 escalation rule: escalation requests human
                # review and performs no mutation. The measured monitor-only
                # arm represents continued traffic during the review window.
                actual_action=action if action in eligible else "monitor_only"
                observed=actions[actual_action]
                failures=observed["label_absolute_failed_requests"]
                success=(action in eligible and observed["label_security_exposure"]==0
                         and failures<=base["absolute_error_budget_requests"])
                cost=(.5*observed["label_path_exposure"]
                      +.25*observed["label_security_exposure"]
                      +.25*failures/base["absolute_error_budget_requests"])
            entry={"chosen_action":action,"measured_arm":actual_action,
                   "resolved_within_budget_authorized":bool(success),
                   "failed_legitimate_requests":failures,
                   "escalation_correct":(not best_eligible) if action=="escalate" else None,
                   "cost_descriptive":cost}
            results[name]=entry
            per_group[group][name].append(entry)
        # Recalculate security interval coverage on heldout newly measured arms
        # using the frozen model and its original grouped calibration radius.
        model=bundle["models"][EXPOSURE_LABEL]
        rad=bundle["radii"][EXPOSURE_LABEL]
        for a,row in actions.items():
            predicted=max(0,min(1,float(model.predict([to_features(row)])[0])))
            correct=max(0,predicted-rad)<=row[EXPOSURE_LABEL]<=min(1,predicted+rad)
            calibrated_by_group[group].append(bool(correct))
        records.append({"group":group,"repeat":repeat,"allowed":list(eligible),
                        "choices":results,"model_abstention_reason":
                            getattr(selector,"last_abstention_reason",None)})
    summaries={}
    for name in ("ai","ai_escalation","expert_E","restart_if_authorized","monitor_only",
                 "resync_policy","transparent_heuristic","oracle_best_authorized"):
        summaries[name]={"per_configuration":{}}
        for group in sorted(per_group):
            vals=per_group[group][name]
            summaries[name]["per_configuration"][group]={
                "success_fraction":sum(x["resolved_within_budget_authorized"] for x in vals)/len(vals),
                "verified_successes":sum(x["resolved_within_budget_authorized"] for x in vals),
                "failed_legitimate_requests":sum(x["failed_legitimate_requests"] for x in vals),
                "correct_escalations":sum(x["escalation_correct"] is True for x in vals),
                "wrong_escalations":sum(x["escalation_correct"] is False for x in vals),
            }
        summaries[name]["all_verified_successes"]=sum(d["verified_successes"]
            for d in summaries[name]["per_configuration"].values())
        summaries[name]["all_failed_requests"]=sum(d["failed_legitimate_requests"]
            for d in summaries[name]["per_configuration"].values())
    return summaries,records,{g:all(v) for g,v in calibrated_by_group.items()}


def summarize_pilot(policies,provenance,calibration):
    a=policies["ai"]["per_configuration"]
    e=policies["expert_E"]["per_configuration"]
    if set(a)!=set(e) or len(a)!=16:
        raise ValueError("Pilot requires 16 complete paired configuration groups")
    discordant=sum(a[g]["success_fraction"]!=e[g]["success_fraction"] for g in a)
    p=discordant/16
    z=NormalDist().inv_cdf(.8)
    denom=1+z*z/16
    high=(p+z*z/(2*16)+z*math.sqrt(p*(1-p)/16+z*z/(4*16*16)))/denom
    raw=math.ceil(6.18*high/.01)
    n=max(40,min(150,raw))
    return {
        "schema":"predict-shield/confirmatory-196-pilot-size/1",
        "status":"PILOT_ONLY_NO_CONFIRMATORY_HYPOTHESIS_TEST",
        "pilot_configurations":16,"pilot_discordant_configurations":discordant,
        "discordance_rate":p,"upper_one_sided_80pct_wilson":high,
        "registration_sample_formula":"ceil(6.18 * upper80_discordance / 0.01)",
        "unbounded_required_n":raw,"registered_main_n":n,
        "main_underpowered_by_registration_rule":raw>150,
        "independent_families_in_pilot":5,
        "physical_arms":provenance["physical_arms"],
        "pilot_data_excluded_from_main":True,
        "sample_size_must_be_committed_before_main":True,
        "pilot_dataset_sha256":provenance["four_stream_digest_sha256"],
        "observed_security_interval_group_coverage":
            sum(calibration.values())/len(calibration),
        "ai_superiority_established":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--phase",choices=("pilot","main"),required=True)
    p.add_argument("--shard",type=int,default=0)
    p.add_argument("--plan",type=Path,required=True)
    p.add_argument("--records",type=Path,required=True)
    p.add_argument("--model",type=Path,required=True)
    p.add_argument("--model-sha256",required=True)
    p.add_argument("--training-report",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():
        p.error("Original physical evidence cannot be overwritten")
    if a.model_sha256!=MODEL_SHA:
        p.error("Frozen model SHA differs from #196 registration")
    from model_adapter import load_local_bundle
    bundle=load_local_bundle(a.model,trusted_sha256=a.model_sha256)
    rows,provenance=read_measured(a.plan,a.records,phase=a.phase,shard=a.shard)
    prior=json.loads(a.training_report.read_text())
    policies,choices,coverage=group_summary(rows,bundle,prior)
    report={
        "schema":"predict-shield/confirmatory-196-physical/1",
        "phase":a.phase,"status":"DEVELOPMENT_PILOT_NOT_CONFIRMATORY" if a.phase=="pilot" else
                  "MAIN_SHARD_MEASURED_ANALYSIS_PENDING",
        "provenance":provenance,"policies":policies,"choices":choices,
        "new_cohort_security_interval_group_coverage":sum(coverage.values())/len(coverage),
        "historical_security_interval_heldout_coverage":
            prior["metrics"][EXPOSURE_LABEL]["heldout_configuration_group_coverage"],
        "ai_superiority_established":False,"critical_infrastructure_effectiveness_established":False,
        "not_autonomous_ai_execution":True,
    }
    if a.phase=="pilot":
        report["pilot_sizing"]=summarize_pilot(policies,provenance,coverage)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("Phase",a.phase,"groups",provenance["groups"],
          "physical arms",provenance["physical_arms"],
          "AI verified resolutions",policies["ai"]["all_verified_successes"],
          "expert_E",policies["expert_E"]["all_verified_successes"])
    if a.phase=="pilot":
        print("Proposed main N",report["pilot_sizing"]["registered_main_n"],
              "underpowered",report["pilot_sizing"]["main_underpowered_by_registration_rule"])
    print("Do not claim confirmatory success from this individual run")


if __name__=="__main__":
    main()
