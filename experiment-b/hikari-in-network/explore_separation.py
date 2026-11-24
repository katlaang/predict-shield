"""EXPLORATORY, written after the registered test result was seen.

Checks whether the in-network models separate attacks from normal flows at
all, independent of the alert thresholds: ROC AUC and average precision of the
supervised and anomaly scores on the test half, per attack category, at the
50% training fraction. This does not change or replace the registered result.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

import run
from run import fv


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    from sklearn.metrics import average_precision_score, roc_auc_score
    proto = json.loads((run.HERE / "protocol.json").read_text())
    frame = run.load(a.archive, proto)
    x = fv.build(frame, fv.resolve_hikari(list(frame.columns)), fv.HIKARI_PORT, hikari=True, feature_set="flow+service")
    cats = frame[fv.HIKARI_CATEGORY].astype(str).to_numpy()
    attack = np.array([fv.hikari_class(c, l)[0] for c, l in zip(cats, frame[fv.HIKARI_LABEL].to_numpy())])
    u = run.uniform("hikari-in-network", frame[fv.HIKARI_ID].to_numpy())
    v = run.uniform("hikari-in-network-fit", frame[fv.HIKARI_ID].to_numpy())
    train, test = u < 0.25, u >= 0.5
    fit_m, thr_m = train & (v < 0.8), train & (v >= 0.8) & ~attack
    sup, iso, t_s, t_a = run.fit(x[fit_m], attack[fit_m], ~attack[fit_m], x[thr_m])
    s_sup = sup.predict_proba(x[test])[:, 1]
    s_iso = -iso.score_samples(x[test])
    s_fit = sup.predict_proba(x[fit_m])[:, 1]
    y, c = attack[test], cats[test]
    out = {"exploratory": True, "written_after_result": True,
           "training_fit_auc": float(roc_auc_score(attack[fit_m], s_fit)),
           "test_auc": {"supervised": float(roc_auc_score(y, s_sup)), "anomaly": float(roc_auc_score(y, s_iso))},
           "test_average_precision": {"supervised": float(average_precision_score(y, s_sup)),
                                      "anomaly": float(average_precision_score(y, s_iso)), "base_rate": float(y.mean())},
           "per_category_auc_vs_all_normal": {}}
    for cat in sorted(set(c[y].tolist())):
        m = (c == cat) | ~y
        out["per_category_auc_vs_all_normal"][cat] = float(roc_auc_score((c[m] == cat), s_sup[m]))
    for q in (0.005, 0.01, 0.05, 0.10):
        t = np.quantile(s_sup[~y], 1 - q)
        out.setdefault("supervised_detection_at_normal_alert_rate", {})[str(q)] = float((s_sup[y] > t).mean())
    a.output.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
