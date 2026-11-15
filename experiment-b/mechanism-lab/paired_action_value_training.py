"""Train a real measured *paired action-benefit* model, without test-set tuning.

This is a bounded research development exercise on archived, actually executed
Java/Kafka action replays. The outcome target is benefit over monitor-only for
the same configured fault and repeat, not a raw CVE or a synthetic score.

Only 60 historical train configuration groups may fit the policy. Five-fold
train-group CV is developmental and uses repeated groups, not five independent
external validations. Twenty earlier calibration groups provide a SECONDARY
historical check, never confirmatory superiority because past work inspected
their outcomes. The original 20 test groups are not read into evaluation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from train import ACTIONS, to_features
from train_group_stability import training_rows
from decision_eval import (
    eligible_actions, observed_utility, tune_rule_on_training_groups,
)
from decision_superiority_audit import COMPARATOR_NAMES, baseline_action

SCHEMA="predict-shield/paired-measured-action-benefit-training/1"
SEED=221
MARGIN=0.01
NON_MONITOR=tuple(a for a in ACTIONS if a!="monitor_only")
REPLICATES=5000
BOOTSTRAP_SEED=2026111501


def _grouped_arms(rows:list[dict],partition:str)->dict[tuple[str,int],dict[str,dict]]:
    if not rows or any(r.get("partition")!=partition for r in rows):
        raise ValueError("Mixed partition or empty measured action set")
    grouped=defaultdict(dict)
    for row in rows:
        group,rep,action=row["group"],row["repeat"],row["action"]
        if not isinstance(group,str) or type(rep) is not int or action not in ACTIONS:
            raise ValueError("Invalid measured group, repeat or action")
        key=(group,rep)
        if action in grouped[key]:
            raise ValueError("Duplicated measured action")
        grouped[key][action]=row
    if any(set(x)!=set(ACTIONS) for x in grouped.values()):
        raise ValueError("Partial four-arm physical action replays")
    for arms in grouped.values():
        ref=arms["monitor_only"]
        if any(r["absolute_error_budget_requests"]!=ref["absolute_error_budget_requests"]
               or r["restart_permitted"]!=ref["restart_permitted"]
               for r in arms.values()):
            raise ValueError("Inconsistent matched-action intervention constraints")
    return dict(sorted(grouped.items()))


def read_previous_calibration(shards:list[Path],training:list[dict])->tuple[list[dict],dict]:
    """Read only existing calibration rows; never return any test rows."""
    original_shas=set()
    calibration=[]
    shard_ids=set()
    for archive in shards:
        with zipfile.ZipFile(archive) as z:
            names=[n for n in z.namelist() if n.endswith(".json")]
            if len(names)!=1:
                raise ValueError("Unexpected archive JSON contents")
            source=json.loads(z.read(names[0]))
        if (source.get("schema")!="predict-shield/full-v3-exploratory-physical-shard/1"
                or source.get("all_four_physical_record_streams_audited") is not True
                or source.get("physical_replays_completed")!=240
                or source.get("raw_oracle_records_published") is not False):
            raise ValueError("Source archive lacks physical four-stream audit")
        shard_ids.add(source["shard_id"])
        blob=json.dumps(source["sanitized_measured_training_rows"],
                        sort_keys=True,separators=(",",":")).encode()
        if hashlib.sha256(blob).hexdigest()!=source["sanitized_rows_sha256"]:
            raise ValueError("Measured shard row digest mismatch")
        original_shas.add(source["source_commit_sha"])
        # Deliberately DISCARD test partition without fitting or scoring.
        calibration.extend(r for r in source["sanitized_measured_training_rows"]
                           if r.get("partition")=="calibration")
    if shard_ids!=set(range(5)) or len(original_shas)!=1:
        raise ValueError("Missing source shard or mixed revisions")
    if len(calibration)!=240 or len({r["group"] for r in calibration})!=20:
        raise ValueError("Incomplete separate historical calibration")
    if {r["group"] for r in training}&{r["group"] for r in calibration}:
        raise ValueError("Historical train/calibration configuration leakage")
    _grouped_arms(calibration,"calibration")
    return calibration,{
        "historical_source_commit":next(iter(original_shas)),
        "calibration_configurations":20,
        "calibration_replays":240,
        "original_test_rows_used_for_training_or_selection":False,
    }


def paired_rows(rows:list[dict],partition:str):
    """Create action-benefit labels from matched, independently measured arms."""
    paired=[]
    for (group,repeat),arms in _grouped_arms(rows,partition).items():
        ref=arms["monitor_only"]
        start_cost=observed_utility(ref)
        for action in NON_MONITOR:
            # Use the SAME one pre-action monitor-side observation for every
            # candidate; do not peek at the action-specific future or oracle.
            features=to_features({"pre_action":ref["pre_action"],"action":action})
            benefit=start_cost-observed_utility(arms[action])
            if not math.isfinite(benefit):
                raise ValueError("Invalid observed action benefit")
            paired.append({"group":group,"repeat":repeat,"action":action,
                           "features":features,"actual_benefit":float(benefit)})
    return paired


def build_estimator():
    from sklearn.ensemble import HistGradientBoostingRegressor
    return HistGradientBoostingRegressor(
        max_iter=120,max_leaf_nodes=10,learning_rate=0.05,
        l2_regularization=1,random_state=SEED,
    )


def _choose(model, reference:dict)->tuple[str,dict]:
    """Predict from one actual pre-action snapshot; never use observed labels."""
    eligible=set(eligible_actions(reference))
    score={}
    for action in NON_MONITOR:
        if action in eligible:
            vector=to_features({"pre_action":reference["pre_action"],"action":action})
            value=float(model.predict([vector])[0])
            if not math.isfinite(value):
                raise ValueError("Non-finite AI action prediction")
            score[action]=value
    if not score:
        return "monitor_only",score
    best=max(sorted(score),key=lambda a:score[a])
    return (best if score[best]>MARGIN else "monitor_only"),score


def observed_policy(records:list[dict],partition:str,model,rule_parameters:dict):
    """Evaluate only after all model choices are fixed from pre-action data."""
    grouped=_grouped_arms(records,partition)
    groups=defaultdict(list)
    selections=Counter()
    for (group,repeat),arms in grouped.items():
        reference=arms["monitor_only"]
        action,pred=_choose(model,reference)
        permitted=eligible_actions(reference)
        if action not in permitted:
            raise ValueError("Model suggested a prohibited restart")
        true_cost={a:observed_utility(arms[a]) for a in permitted}
        minimum=min(true_cost.values())
        policies={"trained_paired_ai":action,"fixed_monitor":"monitor_only"}
        for name in COMPARATOR_NAMES:
            policies[name]=baseline_action(name,reference,rule_parameters)
        result={}
        for name,choice in policies.items():
            if choice not in permitted:
                raise ValueError("Conventional policy selected a prohibited action")
            result[name]=true_cost[choice]-minimum
        groups[group].append(result)
        selections[action]+=1
    if set(len(x) for x in groups.values())!={3}:
        raise ValueError("Three independent physical replays required per group")
    by_group={
        group:{name:sum(x[name] for x in runs)/3 for name in runs[0]}
        for group,runs in groups.items()
    }
    return by_group,dict(selections)


def _bootstrap(per_group:dict[str,dict],baseline:str,repeats=REPLICATES)->dict:
    if baseline not in COMPARATOR_NAMES and baseline!="fixed_monitor":
        raise ValueError("Unrecognized reference policy")
    names=sorted(per_group)
    if len(names)<5:
        raise ValueError("Too few separate configuration groups")
    if not 1000<=repeats<=50000:
        raise ValueError("Invalid preregistered bootstrap count")
    diffs=[per_group[n][baseline]-per_group[n]["trained_paired_ai"] for n in names]
    rng=random.Random(BOOTSTRAP_SEED)
    draws=sorted(sum(diffs[rng.randrange(len(diffs))] for _ in names)/len(names)
                 for _ in range(repeats))
    mean=sum(diffs)/len(diffs)
    return {"comparator":baseline,
            "mean_regret_reduction":mean,
            "paired_config_bootstrap_95":[draws[int(.025*repeats)],
                 draws[min(repeats-1,int(.975*repeats))]],
            "positive_configuration_fractions":sum(d>1e-9 for d in diffs)/len(diffs),
            "negative_configuration_fractions":sum(d< -1e-9 for d in diffs)/len(diffs),
            "statistically_supported":draws[int(.025*repeats)]>0}


def cross_validate_train_only(rows:list[dict])->dict:
    import numpy as np
    from sklearn.model_selection import GroupKFold
    if len(rows)!=720 or len({r["group"] for r in rows})!=60:
        raise ValueError("Historical 60 training groups / 720 physical rows required")
    paired=paired_rows(rows,"train")
    X=np.asarray([r["features"] for r in paired],dtype=float)
    y=np.asarray([r["actual_benefit"] for r in paired],dtype=float)
    ids=np.asarray([r["group"] for r in paired])
    fold_reports=[]
    for index,(i_train,i_val) in enumerate(
            GroupKFold(n_splits=5).split(X,y,groups=ids)):
        model=build_estimator()
        model.fit(X[i_train],y[i_train])
        train_groups=set(ids[i_train])
        valid_groups=set(ids[i_val])
        if train_groups & valid_groups:
            raise ValueError("Cross-validation grouped leakage")
        # The rule is also trained solely within this fold.
        fit_rows=[r for r in rows if r["group"] in train_groups]
        rules=tune_rule_on_training_groups(fit_rows)["parameters"]
        hold_rows=[r for r in rows if r["group"] in valid_groups]
        costs,counts=observed_policy(hold_rows,"train",model,rules)
        ref=_bootstrap(costs,"fixed_monitor",repeats=1000)
        fold_reports.append({
            "fold":index,"fit_groups":len(train_groups),
            "validation_groups":len(valid_groups),
            "mean_regret_ai":sum(c["trained_paired_ai"] for c in costs.values())/len(costs),
            "mean_regret_monitor":sum(c["fixed_monitor"] for c in costs.values())/len(costs),
            "ai_minus_monitor_regret":-ref["mean_regret_reduction"],
            "monitor_minus_ai_regret":ref["mean_regret_reduction"],
            "selected_actions":counts,
        })
    return {
        "frozen_model_settings":{
            "type":"HistGradientBoostingRegressor","max_iter":120,
            "max_leaf_nodes":10,"learning_rate":0.05,
            "l2_regularization":1,"random_state":SEED,
            "minimum_predicted_advantage_to_intervene":MARGIN},
        "five_grouped_training_folds":fold_reports,
        "folds_positive":sum(f["monitor_minus_ai_regret"]>1e-8 for f in fold_reports),
        "folds_negative":sum(f["monitor_minus_ai_regret"]<-1e-8 for f in fold_reports),
        "folds_tied":sum(abs(f["monitor_minus_ai_regret"])<=1e-8 for f in fold_reports),
        "mean_train_cv_monitor_minus_ai_regret":
            sum(f["monitor_minus_ai_regret"] for f in fold_reports)/len(fold_reports),
        "only_train_group_labels_used_for_model_development":True,
        "folds_not_independent_external_field_studies":True,
    }


def run(archives:list[Path],report_path:Path,model_path:Path)->dict:
    if report_path.exists() or model_path.exists():
        raise FileExistsError("Refuse to overwrite scientific observations")
    train,provenance=training_rows(archives)
    cal,cal_provenance=read_previous_calibration(archives,train)
    # Hyperparameters and intervention margin are fixed before this run.
    # This is a *development* study after prior train experiments.
    development=cross_validate_train_only(train)
    import numpy as np
    import joblib
    examples=paired_rows(train,"train")
    model=build_estimator()
    model.fit(np.asarray([r["features"] for r in examples]),
              np.asarray([r["actual_benefit"] for r in examples]))
    rules=tune_rule_on_training_groups(train)["parameters"]
    recorded,actions=observed_policy(cal,"calibration",model,rules)
    rule_means={name:sum(r[name] for r in recorded.values())/len(recorded)
                for name in next(iter(recorded.values()))}
    best_rule=min(COMPARATOR_NAMES,key=lambda name:(rule_means[name],name))
    comparisons={name:_bootstrap(recorded,name) for name in COMPARATOR_NAMES}
    summary={
        "schema":SCHEMA,
        "source_run_id":43629488209,
        "original_measured_action_replays":1200,
        "model_development_partition":"train",
        "historical_train_groups":60,
        "historical_train_action_rows":720,
        "matched_action_improvement_samples":len(examples),
        "validation_partition":"previously_inspected_calibration",
        "historical_calibration_groups":20,
        "historical_calibration_actions":240,
        "original_test_labels_scored":False,
        "preaction_operator_signals_only":True,
        "hidden_fault_name_and_target_excluded_as_features":True,
        "training_fingerprint":hashlib.sha256(json.dumps(examples,sort_keys=True,
                     separators=(",",":")).encode()).hexdigest(),
        "source":provenance,"calibration_source":cal_provenance,
        "development":development,
        "calibration_research_diagnostics":{
            "regret_by_policy":rule_means,
            "retrospectively_strongest_rule_on_same_calibration":best_rule,
            "policy_choices":actions,
            "paired_comparisons":comparisons,
            "calibration_model_selection_and_claim_using_same_groups_forbidden":True,
        },
        "claims":{
            "train_only_cv_generalization":False,
            "independent_confirmatory_ai_superiority":False,
            "external_critical_infrastructure_effectiveness":False,
            "model_calibrated_for_autonomous_execution":False,
            "accuracy_99_9_established":False,
        },
        "limitations":[
            "Original physical 20 test groups have already been examined in prior research; not an untouched confirmatory test.",
            "Prior exploratory training inspired the chosen candidate; even grouped cross-validation is model development.",
            "The 20 calibration groups have been used for previous baselines; historical check is descriptive, not newly independent validation.",
            "Four action replays under one configured condition are proxy counterfactuals, not randomized real-world causal observations.",
            "Objective: exposure plus legitimate failures. Runtime safety approvals and actual remaining budgets are separate.",
            "The learned model has not been calibrated for safe autonomous production decisions.",
        ],
    }
    report_path.parent.mkdir(parents=True,exist_ok=True)
    model_path.parent.mkdir(parents=True,exist_ok=True)
    # Pickle-derived joblib is UNSAFE to deserialize without a separately
    # trusted hash and origin. This file is never autoloaded or executed.
    joblib.dump({"schema":"predict-shield/exploratory-paired-action-model/1",
                 "estimator":model,"settings":development["frozen_model_settings"],
                 "training_fingerprint":summary["training_fingerprint"],
                 "can_authorize_actions":False},model_path)
    summary["model_artifact_sha256"]=hashlib.sha256(model_path.read_bytes()).hexdigest()
    summary["report_sha256"]=hashlib.sha256(json.dumps(summary,sort_keys=True,
                         separators=(",",":")).encode()).hexdigest()
    report_path.write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print(json.dumps({
        "physical_replays_reused_for_development":1200,
        "train_only_cv_monitor_minus_ai_regret":
            development["mean_train_cv_monitor_minus_ai_regret"],
        "historical_calibration_monitor_regret":rule_means["fixed_monitor"],
        "historical_calibration_ai_regret":rule_means["trained_paired_ai"],
        "locked_historical_rule_name":best_rule,
        "confirmed_superiority":False,
        "needs_new_physical_confirmatory_trial":True,
    },sort_keys=True))
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--shard-zips",nargs=5,type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--model-bundle",type=Path,required=True)
    args=p.parse_args()
    run(args.shard_zips,args.report,args.model_bundle)


if __name__=="__main__":
    main()
