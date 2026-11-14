"""Research-only learned ranking of candidate telecom topology edges.

Training labels are independently verified links. Model inputs are only
pre-verification evidence indicators. Group isolation prevents a topology
appearing in both training and evaluation. Model output is ALWAYS INFERRED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

FEATURES = (
    "lldp_seen", "routing_adjacency_seen", "bidirectional_flow_seen",
    "same_site", "interface_type_compatible", "inventory_edge_declared",
)
KEYS = ("topology_id", "source", "target", "features", "verified_link", "split")
SPLITS = ("train", "test")


def validate_rows(rows: list[dict]) -> dict:
    if not isinstance(rows, list) or not rows:
        raise ValueError("Nonempty labeled topology candidate rows required")
    groups = {}
    pair_keys = set()
    counts = Counter()
    for row in rows:
        if not isinstance(row, dict) or not set(KEYS).issubset(row):
            raise ValueError("Missing candidate identifiers, labels or features")
        top, a, b = row["topology_id"], row["source"], row["target"]
        split = row["split"]
        if (not isinstance(top, str) or not top or
                not all(isinstance(s, str) and s for s in (a, b))
                or a == b or split not in SPLITS
                or type(row["verified_link"]) is not bool):
            raise ValueError("Invalid candidate or verification label")
        # Directed adjacency assumptions are not allowed: candidate pairs
        # are treated as undirected, and duplicates fail closed.
        key = (top, *sorted((a, b)))
        if key in pair_keys:
            raise ValueError("Repeated candidate pair could leak labels")
        pair_keys.add(key)
        if top in groups and groups[top] != split:
            raise ValueError("A topology must belong to a single partition")
        groups[top] = split
        fs = row["features"]
        if not isinstance(fs, dict) or set(fs) != set(FEATURES) or any(type(fs[k]) is not bool for k in FEATURES):
            raise ValueError("Explicit boolean pre-verification features required")
        counts[split] += 1
    if not counts["train"] or not counts["test"]:
        raise ValueError("Separate train and test topology groups required")
    labels = {row["verified_link"] for row in rows if row["split"] == "train"}
    if labels != {True, False}:
        raise ValueError("Training requires both independently verified classes")
    return {"configuration_groups": dict(Counter(groups.values())),
            "candidate_rows": dict(counts)}


def vector(row: dict) -> list[int]:
    return [int(row["features"][k]) for k in FEATURES]


def rule_baseline(row: dict) -> float:
    """Strong transparent discovery baseline: authenticated LLDP or routing seen."""
    f = row["features"]
    return float(f["lldp_seen"] or f["routing_adjacency_seen"])


def confusion(y: list[bool], predictions: list[float], threshold: float = 0.5) -> dict:
    if len(y) != len(predictions):
        raise ValueError("Mismatched evaluation arrays")
    tp = fp = tn = fn = 0
    for label, score in zip(y, predictions):
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Invalid model probability")
        if score >= threshold:
            if label: tp += 1
            else: fp += 1
        elif label: fn += 1
        else: tn += 1
    return {"tp":tp,"fp":fp,"tn":tn,"fn":fn,
            "precision":tp/(tp+fp) if tp+fp else None,
            "recall":tp/(tp+fn) if tp+fn else None,
            "false_positive_rate":fp/(fp+tn) if fp+tn else None}


def train_evaluate(rows: list[dict]) -> tuple[dict,dict]:
    """Fit only on training topology groups; evaluate once on held-out groups."""
    summary = validate_rows(rows)
    from sklearn.linear_model import LogisticRegression
    train = [r for r in rows if r["split"]=="train"]
    test = [r for r in rows if r["split"]=="test"]
    estimator = LogisticRegression(max_iter=1000,random_state=20261114,
                                   solver="liblinear",class_weight="balanced")
    estimator.fit([vector(r) for r in train],[int(r["verified_link"]) for r in train])
    probs = [float(p[1]) for p in estimator.predict_proba([vector(r) for r in test])]
    labels = [r["verified_link"] for r in test]
    baseline = [rule_baseline(r) for r in test]
    fitted = {
        "schema":"predict-shield/telecom-link-logistic/1",
        "features":list(FEATURES),
        "coef":[float(x) for x in estimator.coef_[0]],
        "intercept":float(estimator.intercept_[0]),
        "positive_class":int(estimator.classes_[-1]),
        "model_training_only":True,
        "training_row_sha256":hashlib.sha256(
            json.dumps(train,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
    }
    comparison = {
        "schema":"predict-shield/topology-link-heldout/1",
        "split_integrity":summary,
        "model":"LogisticRegression",
        "model_confusion":confusion(labels,probs),
        "deterministic_baseline_confusion":confusion(labels,baseline),
        "threshold":0.5,
        "test_topologies":sorted({r["topology_id"] for r in test}),
        "test_records":len(test),
        "synthetic_or_external_provenance_must_be_reported":True,
        "model_superiority_claim":False,
        "production_topology_verified":False,
    }
    return fitted, comparison


def infer_pairs(bundle: dict, candidates: list[dict]) -> list[dict]:
    """Rank candidate links without turning probabilities into observed facts."""
    if bundle.get("schema")!="predict-shield/telecom-link-logistic/1" or bundle.get("features")!=list(FEATURES):
        raise ValueError("Unrecognized trained link model")
    weights=bundle["coef"]
    intercept=bundle["intercept"]
    if len(weights)!=len(FEATURES) or not all(math.isfinite(float(x)) for x in weights+[intercept]):
        raise ValueError("Invalid learned parameters")
    proposals=[]
    seen=set()
    for candidate in candidates:
        src,dst=candidate.get("source"),candidate.get("target")
        if not isinstance(src,str) or not isinstance(dst,str) or not src or not dst or src==dst:
            raise ValueError("Invalid candidate endpoints")
        key=tuple(sorted((src,dst)))
        if key in seen:
            raise ValueError("Duplicate candidate")
        seen.add(key)
        val=vector({"features":candidate["features"]})
        score=float(intercept)+sum(float(a)*b for a,b in zip(weights,val))
        probability=1/(1+math.exp(-max(-700,min(700,score))))
        proposals.append({"source":src,"target":dst,"relation":"NEIGHBOR_OF",
                          "status":"INFERRED","model_score":probability,
                          "calibrated_confidence":False,"physically_verified":False,
                          "requires_independent_confirmation":True,
                          "training_fingerprint":bundle["training_row_sha256"]})
    return sorted(proposals,key=lambda r:(-r["model_score"],r["source"],r["target"]))


def main():
    p=argparse.ArgumentParser(description="Research-only grouped topology inference")
    p.add_argument("--training-data",required=True,type=Path)
    p.add_argument("--model-output",required=True,type=Path)
    p.add_argument("--report-output",required=True,type=Path)
    args=p.parse_args()
    if args.model_output.exists() or args.report_output.exists():
        p.error("Refuse to overwrite research artifacts")
    rows=json.loads(args.training_data.read_text())
    bundle,report=train_evaluate(rows)
    for path,value in ((args.model_output,bundle),(args.report_output,report)):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    print("Evaluated learned topology link ranking and deterministic baseline:",report["test_records"],"held-out examples")


if __name__=="__main__":
    main()
