"""Train graph-context AI for missing telemetry against transitive-closure rules.

Labels must describe independently verified *service reachability*, not direct
physical cables. No test topologies may enter fitting or threshold selection.
"""
from __future__ import annotations
import hashlib
import json
from collections import defaultdict

from predict_shield.telemetry_blindspots import (
    FEATURES, preverification_pair, strong_deterministic_baseline
)


def _confusion(ground, predictions):
    tp=sum(a and b for a,b in zip(ground,predictions))
    tn=sum(not a and not b for a,b in zip(ground,predictions))
    fp=sum(not a and b for a,b in zip(ground,predictions))
    fn=sum(a and not b for a,b in zip(ground,predictions))
    count=tp+tn+fp+fn
    return {"tp":tp,"tn":tn,"fp":fp,"fn":fn,
            "accuracy":(tp+tn)/count,
            "recall":tp/(tp+fn) if tp+fn else None,
            "specificity":tn/(tn+fp) if tn+fp else None}


def fit_blindspot_model(records):
    if not isinstance(records,list) or not records:
        raise ValueError("Independent source records required")
    train,test=[],[]
    group_splits={}
    pair_ids=set()
    for item in records:
        if not isinstance(item,dict):
            raise ValueError("Invalid record")
        group=item.get("topology_group")
        split=item.get("split")
        source,target=item.get("source"),item.get("target")
        if not isinstance(group,str) or not group or split not in ("train","test"):
            raise ValueError("Predeclared topology group and split required")
        if not all(isinstance(a,str) and a for a in (source,target)) or source==target:
            raise ValueError("Invalid endpoint identity")
        pair=(group,*sorted((source,target)))
        if pair in pair_ids:
            raise ValueError("Duplicate candidate in same network")
        pair_ids.add(pair)
        if group in group_splits and group_splits[group]!=split:
            raise ValueError("Training and test topology leakage")
        group_splits[group]=split
        if type(item.get("verified_reachable")) is not bool:
            raise ValueError("Independently verified reachability label is required")
        if not isinstance(item.get("truth_evidence_id"),str) or not item["truth_evidence_id"]:
            raise ValueError("Missing independent verification artifact ID")
        f=preverification_pair(item["graph"],source,target)
        row={"group":group,"source":source,"target":target,
             "features":f,"verified_reachable":item["verified_reachable"],
             "truth_evidence_id":item["truth_evidence_id"]}
        (train if split=="train" else test).append(row)
    if not train or not test or {r["verified_reachable"] for r in train}!={True,False}:
        raise ValueError("Both train labels and independent test groups required")
    from sklearn.linear_model import LogisticRegression
    features=lambda row:[row["features"][k] for k in FEATURES]
    model=LogisticRegression(max_iter=2000,class_weight="balanced",
                             solver="liblinear",random_state=20261114)
    model.fit([features(row) for row in train],
              [int(row["verified_reachable"]) for row in train])
    probabilities=[float(p[1]) for p in model.predict_proba([features(r) for r in test])]
    truth=[r["verified_reachable"] for r in test]
    model_preds=[p>=.5 for p in probabilities]
    baseline=[strong_deterministic_baseline(r["features"]) for r in test]
    bundle={"schema":"predict-shield/telemetry-blindspot-logistic/1",
            "features":list(FEATURES),
            "coefficients":[float(a) for a in model.coef_[0]],
            "intercept":float(model.intercept_[0]),
            "calibrated_probability":False,
            "training_sha256":hashlib.sha256(
                json.dumps(train,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            "inference_only_no_action_authorization":True}
    results={"schema":"predict-shield/telemetry-blindspot-heldout/1",
             "train_topology_groups":len({r["group"] for r in train}),
             "heldout_topology_groups":len({r["group"] for r in test}),
             "train_records":len(train),"heldout_records":len(test),
             "ai":_confusion(truth,model_preds),
             "strong_graph_closure_baseline":_confusion(truth,baseline),
             "heldout_pairs":[{
                 "topology_group":r["group"],"source":r["source"],"target":r["target"],
                 "verified_reachable":r["verified_reachable"],
                 "truth_evidence_id":r["truth_evidence_id"],
                 "ai_score":p,"ai_prediction":pred,
                 "strong_rule_prediction":base,
             } for r,p,pred,base in zip(test,probabilities,model_preds,baseline)],
             "ai_superiority_established":False,
             "data_independence_needs_external_verification":True,
             "model_probability_calibrated":False}
    return bundle,results
