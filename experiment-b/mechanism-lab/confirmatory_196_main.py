"""Frozen #196 main evaluation. Reject absent pilot size lock or incomplete shards.

This does not create labels, execute actions, train models or choose N.
The primary/H2 equations and limits are the merged protocol #196.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import random
from pathlib import Path
from statistics import NormalDist

from confirmatory_196_plan import REGISTRATION_COMMIT
from confirmatory_196_score import BOOTSTRAP_SEED, NON_INFERIORITY_MARGIN, MODEL_SHA


def digest(path):
    d=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1048576),b""):
            d.update(chunk)
    return d.hexdigest()


def check_lock(lock):
    if (lock.get("schema")!="predict-shield/confirmatory-196-main-lock/1"
            or lock.get("registration_commit_sha")!=REGISTRATION_COMMIT
            or type(lock.get("main_n")) is not int or
            not 40<=lock["main_n"]<=150
            or type(lock.get("unbounded_n")) is not int
            or lock["unbounded_n"]<1
            or lock["main_n"]!=max(40,min(150,lock["unbounded_n"]))
            or lock.get("pilot_groups")!=16
            or lock.get("pilot_physical_arms")!=192
            or len(lock.get("pilot_measured_dataset_sha256",""))!=64
            or lock.get("model_sha256")!=MODEL_SHA
            or lock.get("pilot_run_status")!="completed_valid_physical"
            or not lock.get("pilot_run_id")
            or lock.get("pilot_data_excluded_from_main") is not True):
        raise ValueError("No valid preregistered *committed* pilot-derived main lock")
    return lock


def evaluate(shards,lock):
    check_lock(lock)
    expected_n=lock["main_n"]
    needed=(expected_n+19)//20
    if len(shards)!=needed:
        raise ValueError("Missing or extra physical main shards")
    groups={}
    seen_digests=set()
    for index, report in enumerate(shards):
        p=report.get("provenance",{})
        if (report.get("phase")!="main" or p.get("shard")!=index
                or p.get("phase")!="main" or
                report.get("status")!="MAIN_SHARD_MEASURED_ANALYSIS_PENDING"):
            raise ValueError("Unexpected or unverified main cohort shard")
        want=min(20,expected_n-20*index)
        if p.get("groups")!=want or p.get("physical_arms")!=want*12:
            raise ValueError("Incomplete physical four-arm/group evidence")
        if p.get("registration_commit_sha")!=REGISTRATION_COMMIT:
            raise ValueError("Shard registration differs from locked protocol")
        if p.get("four_stream_digest_sha256") in seen_digests:
            raise ValueError("Reused physical oracle dataset across shards")
        seen_digests.add(p["four_stream_digest_sha256"])
        policies=report.get("policies",{})
        if "ai" not in policies or "expert_E" not in policies:
            raise ValueError("Missing frozen AI or expert policy")
        ai=policies["ai"]["per_configuration"]
        exp=policies["expert_E"]["per_configuration"]
        if len(ai)!=want or set(ai)!=set(exp):
            raise ValueError("Incomplete paired configurations")
        for name in ai:
            if name in groups:
                raise ValueError("A configuration ID reused across main shards")
            groups[name]={
                "ai":ai[name],"expert_E":exp[name],
                "shard":index,
                "success_diff":ai[name]["success_fraction"]-exp[name]["success_fraction"],
                "failed_requests_diff":ai[name]["failed_legitimate_requests"]-
                                       exp[name]["failed_legitimate_requests"],
            }
    if len(groups)!=expected_n:
        raise ValueError("Wrong number of independent configurations")
    diffs=[row["success_diff"] for _,row in sorted(groups.items())]
    rng=random.Random(BOOTSTRAP_SEED)
    boot=sorted(sum(rng.choices(diffs,k=len(diffs)))/len(diffs)
                for _ in range(10000))
    one_sided_lower=boot[499]
    ni=one_sided_lower > -NON_INFERIORITY_MARGIN
    disruption_diffs=[row["failed_requests_diff"] for _,row in sorted(groups.items())]
    p_value=None
    h2=False
    if ni:
        if any(x!=0 for x in disruption_diffs):
            from scipy.stats import wilcoxon
            p_value=float(wilcoxon(disruption_diffs,alternative="less",
                                   zero_method="wilcox").pvalue)
            h2=p_value<.05
        else:
            p_value=1.
    return {
        "schema":"predict-shield/confirmatory-196-main-aggregate/1",
        "status":"MEASURED_CONFIRMATORY_LAB_RESULT",
        "registered_n":expected_n,"pilot_separate_from_main":True,
        "groups":groups,
        "security_primary":{
            "primary_endpoint":"verified_authorized_within_budget_resolution_per_configuration",
            "mean_ai_minus_expert":sum(diffs)/len(diffs),
            "margin":NON_INFERIORITY_MARGIN,
            "bootstrap_configurations":10000,
            "bootstrap_seed":BOOTSTRAP_SEED,
            "one_sided_95pct_lower_bound":one_sided_lower,
            "H1_noninferiority_passed":ni,
        },
        "disruption_secondary":{
            "Wilcoxon_one_sided_p_value":p_value,
            "H2_superiority_tested":ni,
            "H2_superiority_passed":h2 if ni else False,
            "AI_minus_expert_failed_requests_total":sum(disruption_diffs),
        },
        "underpowered_by_registered_formula":lock["unbounded_n"]>150,
        "critical_infrastructure_field_effectiveness_established":False,
        "caveat":"Every physical arm is a separate reset, not live AI dispatch. "
                 "Check independent failure, coverage, and authorization outcomes.",
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--committed-lock",type=Path,required=True)
    p.add_argument("--shard-report",type=Path,nargs="+",required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if a.output.exists() or a.committed_lock.is_symlink():
        p.error("Refuse overwritten output or symlinked evidence lock")
    lock=check_lock(json.loads(a.committed_lock.read_text()))
    shards=[json.loads(f.read_text()) for f in a.shard_report]
    result=evaluate(shards,lock)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("Main confirmatory N",result["registered_n"],
          "H1",result["security_primary"]["H1_noninferiority_passed"],
          "H2",result["disruption_secondary"]["H2_superiority_passed"],
          "underpowered",result["underpowered_by_registered_formula"])


if __name__=="__main__":
    main()
