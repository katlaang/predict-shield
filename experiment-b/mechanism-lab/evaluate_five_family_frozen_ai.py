"""Independent second physical replication of the frozen action-value policy.

Model weights and action threshold are imported unchanged from the completed
training artifact, verified with the previously published exact SHA256.
Every case is scored (including model decisions that exceed lab error budgets).
New five-family scenarios are neither used for training nor action selection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

from decision_eval import eligible_actions, observed_utility
from decision_superiority_audit import COMPARATOR_NAMES, baseline_action
from paired_action_value_training import _choose, _grouped_arms
from score_prospective_paired_actions import (
    verified_model, MODEL_SHA256, OLD_TRAIN_RULE, LOCKED_STRONG_RULE,
)
from five_family_frozen_physical import (
    SCHEMA as SHARD_SCHEMA, REGISTRATION, FAULTS, STRATA,
    manifest,
)

REPORT_SCHEMA="predict-shield/frozen-five-family-physical-ai-v-seven-rules/1"
REGRESSION_RUN=43682077804
DRAW_SEED=20261115321
DRAW_COUNT=5000
RELATIVE_TARGET=.10
FAMILYWISE_ALPHA=.05/len(COMPARATOR_NAMES)
EXPECTED_GROUPS=60


def load_shards(paths:list[Path]):
    if len(paths)!=5:
        raise ValueError("All five physical fault-family shards required")
    seen=set()
    sources=set()
    rows=[]
    evidence=[]
    for file in paths:
        doc=json.loads(file.read_text())
        shard=doc.get("shard_id")
        if (type(shard) is not int or shard not in range(5) or shard in seen
                or doc.get("schema")!=SHARD_SCHEMA
                or doc.get("prospective_registration")!=REGISTRATION
                or doc.get("fault_family")!=FAULTS[shard]
                or doc.get("independent_new_configuration_groups")!=12
                or doc.get("physical_replays_completed")!=96
                or doc.get("repeats_per_configuration")!=2
                or doc.get("independent_four_stream_audit_passed") is not True
                or doc.get("privileged_oracle_data_uploaded") is not False
                or doc.get("consumer_pause_requires_separate_witness") is not True
                or doc.get("frozen_model_not_retrained") is not True
                or doc.get("original_24_group_test_not_reused") is not True
                or doc.get("critical_infrastructure_field_deployment") is not False):
            raise ValueError("Unverified or incomplete measured physical fault-family shard")
        seen.add(shard)
        configs,trials=manifest(shard)
        from audit import plan_fingerprint
        if doc.get("registered_source_sha256")!=plan_fingerprint(configs,trials):
            raise ValueError("Physical measurements do not match frozen registered case plan")
        items=doc["measured_physical_rows"]
        if len(items)!=96:
            raise ValueError("Incomplete source-specific physical action observations")
        canonical=json.dumps(items,sort_keys=True,separators=(",",":")).encode()
        if hashlib.sha256(canonical).hexdigest()!=doc.get("physical_measured_rows_sha256"):
            raise ValueError("Physical source outcome integrity hash mismatch")
        if any(x["fault"]!=FAULTS[shard] or x["partition"]!="test" for x in items):
            raise ValueError("Physical fault identity mismatch or train data leak")
        if shard==4 and any(x.get("consumer_pause_physically_witnessed") is not True for x in items):
            raise ValueError("Missing required actual persistent Kafka pause witness")
        accepted={(t["configuration_id"],t["repeat"],t["action_id"]) for t in trials}
        actual={(x["group"],x["repeat"],x["action"]) for x in items}
        if actual!=accepted or len(actual)!=96:
            raise ValueError("Missing, substituted or duplicated physical replay")
        source=doc.get("physical_source_commit")
        if type(source) is not str or len(source)!=40 or any(c not in "0123456789abcdef" for c in source):
            raise ValueError("Invalid pinned source commit")
        sources.add(source)
        rows.extend(items)
        evidence.append({"shard":shard,"fault_family":FAULTS[shard],
            "registration_sha256":doc["registered_source_sha256"],
            "outcomes_sha256":doc["physical_measured_rows_sha256"],
            "physical_source_commit":source})
    if seen!=set(range(5)) or len(sources)!=1 or len(rows)!=480:
        raise ValueError("Incomplete independent five-family execution")
    if len({r["group"] for r in rows})!=EXPECTED_GROUPS:
        raise ValueError("Sixty distinct pre-registered new configurations required")
    _grouped_arms(rows,"test")
    return rows, sorted(evidence,key=lambda x:x["shard"])


def quantile(samples:list[float],p:float)->float:
    ordered=sorted(samples)
    index=(len(ordered)-1)*p
    lo=math.floor(index)
    hi=math.ceil(index)
    return ordered[lo]*(hi-index)+ordered[hi]*(index-lo) if hi!=lo else ordered[lo]


def bootstrap(by_group:dict[str,dict],baseline:str,*,seed=DRAW_SEED):
    if baseline not in COMPARATOR_NAMES or len(by_group)!=EXPECTED_GROUPS:
        raise ValueError("Invalid predeclared baseline or missing independent groups")
    groups=sorted(by_group)
    pairs=[(by_group[g][baseline],by_group[g]["trained_paired_ai"]) for g in groups]
    rng=random.Random(seed)
    abss=[]
    rel=[]
    for i in range(DRAW_COUNT):
        picks=[pairs[rng.randrange(EXPECTED_GROUPS)] for _ in range(EXPECTED_GROUPS)]
        b=sum(t[0] for t in picks)/EXPECTED_GROUPS
        a=sum(t[1] for t in picks)/EXPECTED_GROUPS
        diff=b-a
        abss.append(diff)
        rel.append(diff/b if b>1e-12 else -1.)
    avg_b=sum(x for x,_ in pairs)/EXPECTED_GROUPS
    avg_a=sum(x for _,x in pairs)/EXPECTED_GROUPS
    lower=quantile(rel,FAMILYWISE_ALPHA)
    return {
        "baseline":baseline,
        "mean_ai_hindsight_regret":avg_a,
        "mean_baseline_hindsight_regret":avg_b,
        "absolute_regret_reduction":avg_b-avg_a,
        "relative_regret_reduction":(avg_b-avg_a)/avg_b if avg_b>0 else None,
        "two_sided_95_absolute":[quantile(abss,.025),quantile(abss,.975)],
        "familywise_one_sided_lower_absolute":quantile(abss,FAMILYWISE_ALPHA),
        "familywise_one_sided_lower_relative":lower,
        "predeclared_more_than_10pct_supported":bool(lower>RELATIVE_TARGET),
    }


def evaluate(shards:list[Path],model_file:Path,training_report:Path,output:Path):
    if output.exists():
        raise FileExistsError("Never overwrite an executed research assessment")
    model,model_hash=verified_model(model_file,training_report)
    if model_hash!=MODEL_SHA256:
        raise ValueError("Model was not frozen before the physical experiment")
    rows,provenance=load_shards(shards)
    grouped=_grouped_arms(rows,"test")
    config_costs=defaultdict(list)
    actions=Counter()
    decisions=[]
    by_fault=defaultdict(list)
    violations=0
    errors_per_fault=Counter()
    for (group,rep),arms in grouped.items():
        reference=arms["monitor_only"]
        chosen,scores=_choose(model,reference)
        permitted=eligible_actions(reference)
        if chosen not in permitted:
            raise ValueError("AI action violates preregistered independent restart freeze")
        actual={a:observed_utility(arms[a]) for a in permitted}
        best=min(actual.values())
        alternatives={name:baseline_action(name,reference,OLD_TRAIN_RULE)
                      for name in COMPARATOR_NAMES}
        if alternatives[LOCKED_STRONG_RULE]!="monitor_only":
            raise ValueError("Previously strongest baseline silently changed")
        choices={"trained_paired_ai":chosen,**alternatives}
        regret={}
        for policy,action in choices.items():
            if action not in permitted:
                raise ValueError("Rule selected prohibited action")
            regret[policy]=max(0.,actual[action]-best)
        config_costs[group].append(regret)
        fault=reference["fault"]
        by_fault[fault].append((regret["trained_paired_ai"],regret[LOCKED_STRONG_RULE],
                               chosen,rep,group))
        actions[chosen]+=1
        failed=arms[chosen]["label_absolute_failed_requests"]
        exceeded=failed>reference["absolute_error_budget_requests"]
        violations+=int(exceeded)
        errors_per_fault[fault]+=int(exceeded)
        decisions.append({
            "group":group,"repeat":rep,"fault_family_for_posthoc_stratification":fault,
            "complexity_stratum_for_posthoc_stratification":reference["complexity_stratum"],
            "model_chosen_action":chosen,
            "model_predicted_benefit_of_eligible_actions":scores,
            "strong_rule_chosen_actions":alternatives,
            "actual_independently_measured_utility_by_action":actual,
            "posthoc_ai_hindsight_regret":regret["trained_paired_ai"],
            "posthoc_monitor_hindsight_regret":regret[LOCKED_STRONG_RULE],
            "ai_selected_action_failed_legitimate_requests":failed,
            "ai_selected_action_exceeded_laboratory_error_allowance":bool(exceeded),
        })
    if len(config_costs)!=60 or set(len(x) for x in config_costs.values())!={2}:
        raise ValueError("Missing two measured repetitions in 60 distinct configurations")
    per_configuration={
        group:{name:sum(x[name] for x in reps)/2 for name in reps[0]}
        for group,reps in config_costs.items()
    }
    comparisons={name:bootstrap(per_configuration,name) for name in COMPARATOR_NAMES}
    selected=comparisons[LOCKED_STRONG_RULE]
    superiority=(
        violations==0 and
        all(v["predeclared_more_than_10pct_supported"] for v in comparisons.values())
    )
    fault_metrics={
        fault:{
            "physical_configurations":12,
            "physical_decision_instances":len(items),
            "ai_mean_regret":sum(x[0] for x in items)/len(items),
            "previously_strongest_monitor_mean_regret":sum(x[1] for x in items)/len(items),
            "ai_action_selected_over_budget":errors_per_fault[fault],
        }
        for fault,items in by_fault.items()
    }
    if set(fault_metrics)!=set(FAULTS) or any(x["physical_decision_instances"]!=24 for x in fault_metrics.values()):
        raise ValueError("Missing one entire fault family from actual physical evidence")
    record={
        "schema":REPORT_SCHEMA,
        "original_physical_training_workflow_id":REGRESSION_RUN,
        "frozen_model_sha256":model_hash,
        "frozen_model_minimum_predicted_advantage":0.01,
        "frozen_source_plan_seed":20261115312,
        "five_actual_fault_families":list(FAULTS),
        "new_physical_configuration_groups":60,
        "new_physical_action_replays":480,
        "new_physical_decisions_scored":120,
        "case_actions_per_repeat":4,
        "same_trained_model_as_first_fresh_24_group_comparison":True,
        "old_24_group_results_reused_for_training_or_tuning":False,
        "new_experimental_outcomes_used_for_training_or_rule_selection":False,
        "model_chose_all_actions_before_scoring_actual_labels":True,
        "model_executed_no_real_online_production_defensive_actions":True,
        "strong_rule_locked_from_prior_historical_calibration":LOCKED_STRONG_RULE,
        "fixed_non_ai_rule_parameters":OLD_TRAIN_RULE,
        "decision_utility":"0.50*path_exposure+0.25*remaining_authorization_exposure+0.25*observed_failed_legitimate_requests/declared_lab_allowance",
        "paired_configuration_bootstrap_count":DRAW_COUNT,
        "familywise_one_sided_alpha_per_comparison":FAMILYWISE_ALPHA,
        "minimum_relative_improvement_for_statistical_lab_claim":RELATIVE_TARGET,
        "actual_ai_choices":dict(actions),
        "ai_actions_exceeding_experimental_error_allowance":violations,
        "five_fault_family_diagnostics":fault_metrics,
        "all_seven_prespecified_comparator_statistics":comparisons,
        "main_preselected_comparator_statistics":selected,
        "lab_superiority_supported_under_all_predeclared_tests":bool(superiority),
        "per_case_full_physical_decision_record":decisions,
        "independently_audited_physical_shard_provenance":provenance,
        "production_critical_infrastructure_effectiveness_established":False,
        "ai_accuracy_99_9_proven":False,
        "limitations":[
            "The original trained model has seen only four fault families; the fifth consumer-paused mechanism tests generalization rather than training.",
            "All five runners use the same disposable four-JVM Kafka testbed, not different independent operators or infrastructure sectors.",
            "120 decisions correspond to 60 independent configured groups with two dependent repeats, not 120 independent sites.",
            "Although each action was physically executed in a matched lab replay, the frozen AI policy was evaluated offline rather than given live production actuation authority.",
            "Operator error allowances, rollback and independent production service budgets were not tested.",
            "This replication follows a prior exploratory study and does not amount to independent organization-level blinded validation.",
        ],
    }
    record["sha256"]=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
    print("FIVE FAMILY PHYSICAL RESULTS:",json.dumps({
        "groups":60,"physical_actions":480,
        "ai_mean_regret":selected["mean_ai_hindsight_regret"],
        "locked_monitor_mean_regret":selected["mean_baseline_hindsight_regret"],
        "relative_point_estimate":selected["relative_regret_reduction"],
        "familywise_lower_relative":selected["familywise_one_sided_lower_relative"],
        "budget_exceedances":violations,
        "lab_superiority_supported":bool(superiority),
        "critical_infrastructure_effectiveness_proven":False,
    },sort_keys=True))
    return record


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--shards",nargs=5,type=Path,required=True)
    p.add_argument("--frozen-model",type=Path,required=True)
    p.add_argument("--training-report",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    evaluate(args.shards,args.frozen_model,args.training_report,args.output)


if __name__=="__main__":
    main()
