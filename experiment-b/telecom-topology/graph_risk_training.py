"""Train graph-aware cyber-risk model on independent labeled topology groups.

The training program never interprets unlabeled graph structure as observed
security incidents. Pre-action features and externally measured labels are distinct.
"""
from __future__ import annotations
import hashlib
import json
from collections import Counter
from predict_shield.graph_risk import FEATURES,features_for_asset


def fit_and_evaluate(records:list[dict]) -> tuple[dict,dict]:
    if not isinstance(records,list) or not records:
        raise ValueError("Explicit labeled records required")
    groups={}
    seen=set()
    train=[]
    test=[]
    for item in records:
        if item.get("split") not in ("train","test") or type(item.get("observed_security_incident")) is not bool:
            raise ValueError("Independent boolean outcome label and split required")
        group=item.get("topology_group")
        asset=item.get("asset_id")
        if not isinstance(group,str) or not group or (group,asset) in seen:
            raise ValueError("Distinct topology + asset labels required")
        seen.add((group,asset))
        if group in groups and groups[group]!=item["split"]:
            raise ValueError("Train/test topology group leakage")
        groups[group]=item["split"]
        feats=features_for_asset(item["graph"],asset,
                                 critical_services=tuple(item["critical_services"]),
                                 confirmed_exposure=item["confirmed_exposure"])
        row={"group":group,"asset_id":asset,"x":[feats[k] for k in FEATURES],
             "y":int(item["observed_security_incident"])}
        (train if item["split"]=="train" else test).append(row)
    if not train or not test or set(x["y"] for x in train)!={0,1}:
        raise ValueError("Need both train classes and disjoint test groups")
    from sklearn.linear_model import LogisticRegression
    model=LogisticRegression(max_iter=1000,solver="liblinear",random_state=20261114)
    model.fit([x["x"] for x in train],[x["y"] for x in train])
    predictions=[float(x[1]) for x in model.predict_proba([x["x"] for x in test])]
    labels=[bool(r["y"]) for r in test]
    def metrics(scores):
        tp=sum(s>=.5 and y for s,y in zip(scores,labels))
        fp=sum(s>=.5 and not y for s,y in zip(scores,labels))
        tn=sum(s<.5 and not y for s,y in zip(scores,labels))
        fn=sum(s<.5 and y for s,y in zip(scores,labels))
        return {"tp":tp,"fp":fp,"tn":tn,"fn":fn,
                "balanced_accuracy":((tp/(tp+fn))+(tn/(tn+fp)))/2 if (tp+fn)*(tn+fp) else None}
    bundle={"schema":"predict-shield/telecom-graph-risk-logistic/1",
            "features":list(FEATURES),
            "coefficients":[float(z) for z in model.coef_[0]],
            "intercept":float(model.intercept_[0]),
            "training_fingerprint":hashlib.sha256(json.dumps(train,sort_keys=True).encode()).hexdigest(),
            "probability_calibrated":False}
    report={"schema":"predict-shield/telecom-graph-risk-evaluation/1",
            "train_groups":len({r["group"] for r in train}),
            "test_groups":len({r["group"] for r in test}),
            "test_records":len(test),
            "learned_model":metrics(predictions),
            "field_effectiveness_confirmed":False,
            "interpretation":"Only independent real labels can support effectiveness claims"}
    return bundle,report
