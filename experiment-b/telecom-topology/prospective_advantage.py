"""Prospective 99.9% AI advantage gate for critical-infrastructure discovery.

The target is difficult by design: 99.9% point accuracy is insufficient
without rigorous group-independent evidence, positive/negative coverage,
reliability, and a statistically supported improvement over strong rules.
Unobserved cases and abstentions are never silently counted as successes.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from collections import defaultdict

SCHEMA = "predict-shield/prospective-ai-advantage/1"
TARGET = .999
Z = 1.959963984540054
MIN_CASES = 10000
MIN_EACH_CLASS = 4000
MIN_GROUPS = 20


def wilson_lower(success: int, total: int) -> float:
    if total <= 0 or not 0 <= success <= total:
        raise ValueError("Invalid binomial outcomes")
    p = success / total
    d = 1 + Z*Z/total
    return (p + Z*Z/(2*total) -
            Z*math.sqrt((p*(1-p)+Z*Z/(4*total))/total)) / d


def _classification(y, p):
    tp=sum(a and b for a,b in zip(y,p))
    fp=sum(not a and b for a,b in zip(y,p))
    fn=sum(a and not b for a,b in zip(y,p))
    tn=sum(not a and not b for a,b in zip(y,p))
    return {
        "tp":tp,"tn":tn,"fp":fp,"fn":fn,
        "accuracy":(tp+tn)/(tp+tn+fp+fn),
        "recall":tp/(tp+fn) if tp+fn else None,
        "specificity":tn/(tn+fp) if tn+fp else None,
        "precision":tp/(tp+fp) if tp+fp else None,
        "accuracy_wilson_95_lower":wilson_lower(tp+tn,len(y)),
        "recall_wilson_95_lower":wilson_lower(tp,tp+fn) if tp+fn else None,
        "specificity_wilson_95_lower":wilson_lower(tn,tn+fp) if tn+fp else None,
        "coverage":len(y),
    }


def judge(rows: list[dict], *, preregistered_groups: list[str],
          external_truth_audit: bool = False,
          locked_model_fingerprint: str = "",
          locked_baseline_fingerprint: str = "",
          seed: int = 20261114, repeats: int = 5000) -> dict:
    if not isinstance(rows,list) or not rows:
        raise ValueError("Full prospective evaluation rows required")
    if not isinstance(preregistered_groups,list) or not preregistered_groups or len(set(preregistered_groups))!=len(preregistered_groups):
        raise ValueError("Unique preregistered independent groups required")
    if not 1000 <= repeats <= 100000:
        raise ValueError("Bootstrap count outside preregistration bounds")
    if any(not isinstance(fp,str) or not fp
           for fp in (locked_model_fingerprint,locked_baseline_fingerprint)):
        raise ValueError("Two preregistered frozen model/baseline fingerprints required")
    groups=defaultdict(list)
    pairs=set()
    for r in rows:
        if not isinstance(r,dict):
            raise ValueError("Invalid record")
        group=r.get("group")
        a,b=r.get("source"),r.get("target")
        if group not in preregistered_groups or not all(isinstance(x,str) and x for x in (a,b)) or a==b:
            raise ValueError("Unregistered group or invalid endpoints")
        pair=(group,*sorted((a,b)))
        if pair in pairs:
            raise ValueError("Duplicate candidate pair")
        pairs.add(pair)
        if type(r.get("verified_link")) is not bool:
            raise ValueError("Unknown adjudication is not a negative label")
        if not isinstance(r.get("independent_truth_evidence_id"),str) or not r["independent_truth_evidence_id"]:
            raise ValueError("Missing independent truth evidence")
        if r.get("ai_abstained") is not False:
            raise ValueError("Abstentions are unsupported, not successes")
        if type(r.get("ai_prediction")) is not bool or type(r.get("baseline_prediction")) is not bool:
            raise ValueError("Explicit binary AI and strong-rule predictions required")
        if r.get("model_fingerprint") != locked_model_fingerprint or r.get("baseline_fingerprint") != locked_baseline_fingerprint:
            raise ValueError("Mixed post-hoc models or baselines")
        if r.get("training_group_member") is not False:
            raise ValueError("Evidence leakage or unverified group isolation")
        groups[group].append(r)
    if set(groups)!=set(preregistered_groups):
        raise ValueError("Missing or selectively omitted preregistered group")

    labels=[r["verified_link"] for r in rows]
    positives=sum(labels)
    negatives=len(labels)-positives
    ai=_classification(labels,[r["ai_prediction"] for r in rows])
    baseline=_classification(labels,[r["baseline_prediction"] for r in rows])

    per_group=[]
    for group in preregistered_groups:
        cases=groups[group]
        delta=(sum(r["ai_prediction"]==r["verified_link"] for r in cases)
               -sum(r["baseline_prediction"]==r["verified_link"] for r in cases))/len(cases)
        per_group.append(delta)
    rng=random.Random(seed)
    samples=sorted(sum(per_group[rng.randrange(len(per_group))] for _ in per_group)/len(per_group)
                   for _ in range(repeats))
    ci=[samples[int(.025*repeats)],samples[min(repeats-1,int(.975*repeats))]]
    enough=len(rows)>=MIN_CASES and positives>=MIN_EACH_CLASS and negatives>=MIN_EACH_CLASS and len(groups)>=MIN_GROUPS
    class_reliable=all(value is not None and value>=TARGET for value in (
        ai["accuracy_wilson_95_lower"], ai["recall_wilson_95_lower"],
        ai["specificity_wilson_95_lower"]))
    better=ci[0]>0
    # A boolean is an explicit external verifier's assertion, not
    # automatically authenticated. Any scientific publication must attach
    # independently auditable ground-truth artifacts.
    achieved=bool(enough and external_truth_audit and class_reliable and better)
    report={
        "schema":SCHEMA,"registered_groups":len(groups),"evaluated_cases":len(rows),
        "positive_cases":positives,"negative_cases":negatives,
        "ai":ai,"strong_deterministic_baseline":baseline,
        "per_group_accuracy_difference":dict(zip(preregistered_groups,per_group)),
        "paired_group_bootstrap_95_interval":ci,
        "target_accuracy_recall_specificity":TARGET,
        "minimum_coverage_met":enough,
        "independent_truth_audited_externally":bool(external_truth_audit),
        "all_three_ai_wilson_lower_bounds_meet_target":class_reliable,
        "paired_ai_superiority_lower_bound_positive":better,
        "ai_advantage_99_9_confirmed":achieved,
        "conclusion":"SUPPORTED_WITHIN_REGISTERED_EVALUATION" if achieved else "NOT_ESTABLISHED",
        "model_fingerprint":locked_model_fingerprint,
        "baseline_fingerprint":locked_baseline_fingerprint,
        "bootstrap_seed":seed,"bootstrap_repeats":repeats,
        "external_isp_generalization_verified":False,
    }
    report["sha256"]=hashlib.sha256(json.dumps(report,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return report
