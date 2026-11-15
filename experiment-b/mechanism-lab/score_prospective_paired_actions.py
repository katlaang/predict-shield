"""Score a FROZEN AI against a real NEW physical campaign without retraining.

All 192 physical action outcomes are collected and independently audited first
using three different disposable Java/Kafka runners. No new labels affect model
training, action threshold, regression settings, baseline choice or bootstrap
seed. The paired replay optimum is not a production causal counterfactual.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

from paired_action_value_training import _choose, _grouped_arms, SCHEMA as MODEL_SCHEMA
from decision_eval import eligible_actions, observed_utility
from decision_superiority_audit import COMPARATOR_NAMES, baseline_action
from prospective_action_physical_shard import SCHEMA as SHARD_SCHEMA, REGISTRATION

MODEL_SHA256="35a040b26a935bfb529f6247dbd0be1a01288294f8fb7089d4de60366adf3f92"
FROZEN_TRAINING_RUN=43682077804
MODEL_ARTIFACT_NAME="paired-real-physical-action-value-model-and-historical-validation"
BOOTSTRAP_SEED=20261115077
BOOTSTRAP_DRAWS=5000
FAMILYWISE_ALPHA=.05/len(COMPARATOR_NAMES)
# Fitted only to historical training data, originally recorded by full-v3
# evaluation and frozen BEFORE executing these newly seeded physical runs.
OLD_TRAIN_RULE={
    "gateway_threshold_rps":55,
    "load_threshold_rps":65,
    "revision_spread_threshold":0,
    "ttl_threshold_ms":10000,
}
LOCKED_STRONG_RULE="fixed_monitor"
IMPROVEMENT_TARGET=.10


def load_physical(shards:list[Path]):
    if len(shards)!=3:
        raise ValueError("Exactly three independent physical measurement shards required")
    reports=[];rows=[];sources=set()
    for path in shards:
        data=json.loads(path.read_text())
        if (data.get("schema")!=SHARD_SCHEMA
                or data.get("prospective_protocol")!=REGISTRATION
                or data.get("physical_four_stream_audit") is not True
                or data.get("raw_privileged_oracle_data_uploaded") is not False
                or data.get("already_used_for_training") is not False
                or data.get("pre_action_model_features_exclude_private_oracle") is not True
                or data.get("actual_physical_action_replays")!=64
                or data.get("independent_new_configurations")!=8
                or data.get("repeats_per_configuration")!=2):
            raise ValueError("Unaudited or incomplete prospective physical measurements")
        sanitized=data["sanitized_new_measured_rows"]
        if len(sanitized)!=64:
            raise ValueError("Missing actual independent action replays")
        canonical=json.dumps(sanitized,sort_keys=True,separators=(",",":")).encode()
        if hashlib.sha256(canonical).hexdigest()!=data["sanitized_rows_sha256"]:
            raise ValueError("Physical measured row digest does not match")
        if len(str(data.get("source_commit_sha","")) )!=40:
            raise ValueError("Invalid physical source commit")
        reports.append({"shard_id":data["shard_id"],
                        "registration_sha256":data["registration_sha256"],
                        "physical_source_commit":data["source_commit_sha"],
                        "rows_sha256":data["sanitized_rows_sha256"]})
        sources.add(data["source_commit_sha"])
        rows.extend(sanitized)
    if (set(r["shard_id"] for r in reports)!={0,1,2}
            or len(sources)!=1 or len(rows)!=192):
        raise ValueError("Partial campaign, repeated shards or source code changed mid-study")
    ids={(r["group"],r["repeat"],r["action"]) for r in rows}
    if len(ids)!=192 or len({r["group"] for r in rows})!=24:
        raise ValueError("Duplicate or missing new config-action pair")
    if any(r["partition"]!="test" or not r["group"].startswith("fresh-benefit-")
           for r in rows):
        raise ValueError("Old training/calibration observations mixed into fresh test")
    _grouped_arms(rows,"test")
    return rows,sorted(reports,key=lambda d:d["shard_id"])


def verified_model(path:Path,training_report:Path):
    if not path.is_file() or path.is_symlink() or not training_report.is_file():
        raise ValueError("Expected trusted local trained-model and source evidence")
    sha=hashlib.sha256(path.read_bytes()).hexdigest()
    if sha!=MODEL_SHA256:
        raise ValueError("Frozen model bytes differ from prepublished SHA-256")
    recorded=json.loads(training_report.read_text())
    if (recorded.get("schema")!=MODEL_SCHEMA
            or recorded.get("source_run_id")!=43629488209
            or recorded.get("model_artifact_sha256")!=MODEL_SHA256
            or recorded.get("historical_train_groups")!=60
            or recorded.get("original_test_labels_scored") is not False
            or recorded.get("claims",{}).get("model_calibrated_for_autonomous_execution") is not False):
        raise ValueError("Original audited training provenance not verified")
    # joblib is pickle-derived: load ONLY AFTER exact independently frozen digest.
    import joblib
    bundle=joblib.load(path)
    if (bundle.get("schema")!="predict-shield/exploratory-paired-action-model/1"
            or bundle.get("training_fingerprint")!=recorded.get("training_fingerprint")
            or bundle.get("can_authorize_actions") is not False
            or bundle.get("settings",{}).get("minimum_predicted_advantage_to_intervene")!=.01):
        raise ValueError("Model identity or decision policy changed after freezing")
    return bundle["estimator"],sha


def _quantile(values:list[float],p:float)->float:
    v=sorted(values)
    i=(len(v)-1)*p
    lo=math.floor(i);hi=math.ceil(i)
    return v[lo]+(v[hi]-v[lo])*(i-lo)


def bootstrap_groups(by_group:dict[str,dict],baseline:str)->dict:
    names=sorted(by_group)
    if len(names)!=24:
        raise ValueError("Preregistered 24 groups required")
    pairs=[(by_group[k][baseline],by_group[k]["trained_paired_ai"]) for k in names]
    rng=random.Random(BOOTSTRAP_SEED)
    absolute=[];relative=[]
    for _ in range(BOOTSTRAP_DRAWS):
        selected=[pairs[rng.randrange(24)] for _ in range(24)]
        base=sum(x for x,_ in selected)/24
        ai=sum(y for _,y in selected)/24
        delta=base-ai
        absolute.append(delta)
        relative.append(delta/base if base>1e-12 else -1.0)
    meanbase=sum(x for x,_ in pairs)/24
    meanai=sum(y for _,y in pairs)/24
    lower_abs=_quantile(absolute,FAMILYWISE_ALPHA)
    lower_relative=_quantile(relative,FAMILYWISE_ALPHA)
    return {
        "baseline":baseline,
        "ai_mean_regret":meanai,
        "baseline_mean_regret":meanbase,
        "absolute_paired_regret_reduction":meanbase-meanai,
        "relative_regret_reduction":(meanbase-meanai)/meanbase if meanbase>0 else None,
        "familywise_one_sided_lower_absolute":lower_abs,
        "familywise_one_sided_lower_relative":lower_relative,
        "raw_two_sided_absolute_95":[_quantile(absolute,.025),_quantile(absolute,.975)],
        "improvement_over_10_percent_supported":
            bool(lower_relative>IMPROVEMENT_TARGET),
    }


def evaluate(shards:list[Path],model_path:Path,training_report:Path,output:Path):
    if output.exists():
        raise FileExistsError("Refuse to overwrite fresh experiment observations")
    model,fingerprint=verified_model(model_path,training_report)
    rows,provenance=load_physical(shards)
    grouped=_grouped_arms(rows,"test")
    groups=defaultdict(list)
    choices=Counter()
    budget_violations=0
    all_decisions=[]
    for (group,rep),arms in grouped.items():
        before=arms["monitor_only"]
        selected,scores=_choose(model,before)
        allowed=eligible_actions(before)
        if selected not in allowed:
            raise ValueError("Frozen AI selected ineligible action")
        measured_cost={action:observed_utility(arms[action]) for action in allowed}
        optimum=min(measured_cost.values())
        others={name:baseline_action(name,before,OLD_TRAIN_RULE)
                for name in COMPARATOR_NAMES}
        if others[LOCKED_STRONG_RULE]!="monitor_only":
            raise ValueError("Original strongest monitored comparator changed")
        policies={"trained_paired_ai":selected,**others}
        costs={}
        for name,action in policies.items():
            if action not in allowed:
                raise ValueError("Ineligible comparator action")
            costs[name]=measured_cost[action]-optimum
        groups[group].append(costs)
        choices[selected]+=1
        excessive=arms[selected]["label_absolute_failed_requests"] > before["absolute_error_budget_requests"]
        budget_violations+=excessive
        all_decisions.append({
            "group":group,"repeat":rep,
            "chosen_ai_action":selected,
            "ai_predicted_action_benefits":scores,
            "baseline_actions":others,
            "independent_measured_action_costs":measured_cost,
            "observed_utility_ai":measured_cost[selected],
            "observed_utility_monitor":measured_cost["monitor_only"],
            "ai_legitimate_failure_budget_exceeded":bool(excessive),
        })
    if set(len(repeats) for repeats in groups.values())!={2} or len(groups)!=24:
        raise ValueError("Incomplete 24x2 prospective physical replays")
    mean_by_group={
        group:{name:sum(r[name] for r in repeats)/2 for name in repeats[0]}
        for group,repeats in groups.items()
    }
    contrasts={rule:bootstrap_groups(mean_by_group,rule) for rule in COMPARATOR_NAMES}
    # No favorable a posteriori comparator selection; the strongest old
    # calibration monitor-only policy was locked before collecting this data.
    locked=contrasts[LOCKED_STRONG_RULE]
    assert LOCKED_STRONG_RULE in contrasts
    positive=(locked["improvement_over_10_percent_supported"]
              and all(v["improvement_over_10_percent_supported"] for v in contrasts.values())
              and budget_violations==0)
    summary={
        "schema":"predict-shield/prospective-physical-paired-action-evaluation/1",
        "frozen_training_workflow_run_id":FROZEN_TRAINING_RUN,
        "frozen_model_sha256":fingerprint,
        "new_physical_source_shards":provenance,
        "independent_new_lab_configurations":24,
        "physical_action_replays":192,
        "physical_repetitions_per_configuration":2,
        "frozen_decision_margin":0.01,
        "locked_strong_non_ai_baseline":LOCKED_STRONG_RULE,
        "training_test_config_ids_disjoint":True,
        "test_labels_used_for_training_model_threshold_or_rule_selection":False,
        "research_decision_objective":"0.50*path_exposure+0.25*remaining_exposure+0.25*failed_legitimate_requests/budget",
        "ai_action_counts":dict(choices),
        "ai_selected_actions_over_error_budget":budget_violations,
        "observed_paired_test_decisions":all_decisions,
        "paired_config_bootstrap_draws":BOOTSTRAP_DRAWS,
        "familywise_alpha_per_comparator":FAMILYWISE_ALPHA,
        "comparisons_against_seven_registered_rules":contrasts,
        "lab_paired_action_benefit_superiority_supported_under_frozen_protocol":bool(positive),
        "external_critical_infrastructure_effectiveness":False,
        "autonomous_actions_executed_by_ai":False,
        "accuracy_99_9_claimed":False,
        "limitations":[
            "All arms physically replayed; the AI chose a policy offline from pre-action telemetry, not autonomous execution.",
            "New configurations share the same disposable 4-JVM Kafka topology and may not generalize to different operators.",
            "Two repeated actions under one condition are not two independent infrastructure deployments.",
            "Safety budgets are experimental denominators, not independently assured remaining operator service budgets.",
            "The learned model's train-group exploration occurred before freezing; external effectiveness needs separate field trials.",
        ]
    }
    summary["sha256"]=hashlib.sha256(json.dumps(summary,sort_keys=True,
                           separators=(",",":")).encode()).hexdigest()
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print(json.dumps({
        "physical_measured_actions":192,
        "new_configuration_groups":24,
        "ai_mean_regret":locked["ai_mean_regret"],
        "previously_locked_best_rule_mean_regret":locked["baseline_mean_regret"],
        "absolute_regret_reduction":locked["absolute_paired_regret_reduction"],
        "familywise_95_lower_relative":locked["familywise_one_sided_lower_relative"],
        "measured_service_budget_violations":budget_violations,
        "lab_superiority_supported":bool(positive),
        "field_superiority_claimed":False,
    },sort_keys=True))
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--shards",nargs=3,type=Path,required=True)
    p.add_argument("--frozen-model",type=Path,required=True)
    p.add_argument("--training-report",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    evaluate(args.shards,args.frozen_model,args.training_report,args.output)


if __name__=="__main__":
    main()
