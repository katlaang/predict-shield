"""Prospective paired evaluation of AI topology discovery versus strong rules.

This is an audit/measurement gate, not a model training loop. Never pick the
best seed, change thresholds after observing held-out outcomes, or invent
independence. A label without externally checkable evidence is not certified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path


def _accuracy(cases, key):
    return sum((float(r[key]) >= .5) == r["verified_link"] for r in cases)/len(cases)


def evaluate_locked(cases:list[dict], *, registered_groups:list[str],
                    independent_provenance_attested:bool=False, seed:int=20261114,
                    bootstrap_repeats:int=10000) -> dict:
    if not 1000 <= bootstrap_repeats <= 100000:
        raise ValueError("Bootstrap count must be preregistered and bounded")
    if not cases or not registered_groups or len(set(registered_groups))!=len(registered_groups):
        raise ValueError("Predeclared topology groups and cases required")
    groups=defaultdict(list)
    pairs=set()
    for row in cases:
        group=row.get("topology_id")
        a,b=row.get("source"),row.get("target")
        if group not in registered_groups or not isinstance(a,str) or not isinstance(b,str) or a==b:
            raise ValueError("Unregistered topology or invalid candidate")
        pair=(group,*sorted((a,b)))
        if pair in pairs:raise ValueError("Duplicate pair or replay")
        pairs.add(pair)
        if type(row.get("verified_link")) is not bool:
            raise ValueError("Missing independently adjudicated binary label")
        for score in ("model_score","baseline_score"):
            v=row.get(score)
            if isinstance(v,bool) or not isinstance(v,(int,float)) or not 0<=v<=1:
                raise ValueError("Invalid fixed prediction score")
        if not isinstance(row.get("truth_evidence_id"),str) or not row["truth_evidence_id"]:
            raise ValueError("Independent link-label evidence ID required")
        groups[group].append(row)
    if set(groups)!=set(registered_groups):
        raise ValueError("Missing preregistered topology group, no selective exclusion")
    diffs=[_accuracy(groups[g],"model_score")-_accuracy(groups[g],"baseline_score")
           for g in registered_groups]
    rng=random.Random(seed)
    draws=[]
    for _ in range(bootstrap_repeats):
        sample=[diffs[rng.randrange(len(diffs))] for _ in diffs]
        draws.append(sum(sample)/len(sample))
    draws.sort()
    lower=draws[int(.025*bootstrap_repeats)]
    upper=draws[min(bootstrap_repeats-1,int(.975*bootstrap_repeats))]
    delta=sum(diffs)/len(diffs)
    # Deliberately cannot assert real independent provenance from a self
    # reported text label. The attestation flag is explicitly externally
    # supplied and must refer to a separate verifiable oracle audit.
    sufficient=len(registered_groups)>=8
    superior=bool(sufficient and independent_provenance_attested and lower>0)
    report={
        "schema":"predict-shield/independent-discovery-superiority/1",
        "registered_topologies":list(registered_groups),
        "paired_topology_count":len(diffs),
        "candidate_count":len(cases),
        "per_topology_accuracy_delta":{k:v for k,v in zip(registered_groups,diffs)},
        "mean_accuracy_delta":delta,
        "paired_bootstrap_95_percent_interval":[lower,upper],
        "model_accuracy":sum((r["model_score"]>=.5)==r["verified_link"] for r in cases)/len(cases),
        "strong_rule_accuracy":sum((r["baseline_score"]>=.5)==r["verified_link"] for r in cases)/len(cases),
        "independent_truth_provenance_attested":bool(independent_provenance_attested),
        "minimum_8_topologies_met":sufficient,
        "ai_superiority_established":superior,
        "conclusion":"SUPPORTED_ON_REGISTERED_HELDOUT_TOPOLOGIES" if superior else "NOT_ESTABLISHED",
        "threshold":.5,"bootstrap_seed":seed,"bootstrap_repeats":bootstrap_repeats,
        "research_caveat":"Conditional on authenticity of independently labeled unseen topologies",
    }
    report["sha256"]=hashlib.sha256(json.dumps(report,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--cases",required=True,type=Path)
    parser.add_argument("--registered-groups",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    # Attestation deliberately not inferred from data or defaults.
    parser.add_argument("--externally-attested-truth",action="store_true")
    args=parser.parse_args()
    if args.output.exists():
        parser.error("Evidence output exists")
    report=evaluate_locked(json.loads(args.cases.read_text()),
       registered_groups=json.loads(args.registered_groups.read_text()),
       independent_provenance_attested=args.externally_attested_truth)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("AI discovery superiority:",report["conclusion"],
          "mean paired delta:",report["mean_accuracy_delta"])


if __name__=="__main__":
    main()
