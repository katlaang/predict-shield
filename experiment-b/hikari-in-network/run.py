"""In-network learning curve on HIKARI-2021. See protocol.json.

  python run.py --archive hikari.zip --output report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "cic-flow-v3"))
import features_v3 as fv  # noqa: E402

SEED = 20261124
FRACTIONS = (0.01, 0.05, 0.20, 0.50)
BUDGET_EACH = 0.005
CEILING = 0.01
FLOOR = 0.90
PASS_FRACTION = 0.05


def uniform(salt: str, values) -> np.ndarray:
    return np.array([int.from_bytes(hashlib.sha256(f"{salt}\x00{v}".encode()).digest()[:8], "big") / 2.0 ** 64
                     for v in values])


def load(archive: Path, proto: dict) -> pd.DataFrame:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != proto["source"]["sha256"]:
        raise SystemExit(f"archive does not match its pin: {digest}")
    with zipfile.ZipFile(archive) as z, z.open(proto["source"]["member"]) as raw:
        frame = pd.read_csv(raw, low_memory=False)
    if len(frame) != proto["source"]["rows"] or frame[fv.HIKARI_ID].duplicated().any():
        raise SystemExit("unexpected row count or duplicate uid")
    return frame


def fit(x, y, normal_mask_fit, x_thr_normal):
    from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
    sup = HistGradientBoostingClassifier(max_leaf_nodes=15, max_iter=100, learning_rate=0.1, class_weight="balanced",
                                         early_stopping=False, random_state=SEED).fit(x, y)
    iso = IsolationForest(n_estimators=200, max_samples=1024, random_state=SEED).fit(x[normal_mask_fit][:200_000])
    t_s = fv.normal_threshold(sup.predict_proba(x_thr_normal)[:, 1], BUDGET_EACH)
    t_a = fv.normal_threshold(-iso.score_samples(x_thr_normal), BUDGET_EACH)
    return sup, iso, t_s, t_a


def score(sup, iso, t_s, t_a, x, attack, cats) -> dict:
    alert = (sup.predict_proba(x)[:, 1] > t_s) | (-iso.score_samples(x) > t_a)
    tp, fp = int((alert & attack).sum()), int((alert & ~attack).sum())
    fn, tn = int((~alert & attack).sum()), int((~alert & ~attack).sum())
    by_cat = {}
    for c in sorted(set(cats.tolist())):
        m = cats == c
        by_cat[c] = {"flows": int(m.sum()), "alerts": int(alert[m].sum()), "rate": float(alert[m].mean()),
                     "wilson_95": fv.wilson(int(alert[m].sum()), int(m.sum())), "attack": bool(attack[m][0])}
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "detection": tp / (tp + fn) if tp + fn else None, "detection_wilson_95": fv.wilson(tp, tp + fn),
            "normal_alert_rate": fp / (fp + tn) if fp + tn else None, "normal_alert_wilson_95": fv.wilson(fp, fp + tn),
            "by_category": by_cat}


def train_and_test(x, attack, cats, train_mask, test_mask, v) -> dict:
    fit_m = train_mask & (v < 0.8)
    thr_m = train_mask & (v >= 0.8) & ~attack
    sup, iso, t_s, t_a = fit(x[fit_m], attack[fit_m], ~attack[fit_m], x[thr_m])
    res = score(sup, iso, t_s, t_a, x[test_mask], attack[test_mask], cats[test_mask])
    res["training_rows"] = {c: int((train_mask & (cats == c)).sum()) for c in sorted(set(cats.tolist()))}
    res["threshold_rows"] = int(thr_m.sum())
    res["thresholds"] = {"supervised": t_s, "anomaly": t_a}
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    proto = json.loads((HERE / "protocol.json").read_text())
    frame = load(a.archive, proto)
    cols = fv.resolve_hikari(list(frame.columns))
    x = fv.build(frame, cols, fv.HIKARI_PORT, hikari=True, feature_set="flow+service")
    cats = frame[fv.HIKARI_CATEGORY].astype(str).to_numpy()
    attack = np.array([fv.hikari_class(c, l)[0] for c, l in zip(cats, frame[fv.HIKARI_LABEL].to_numpy())])
    uid = frame[fv.HIKARI_ID].to_numpy()
    u = uniform("hikari-in-network", uid)
    v = uniform("hikari-in-network-fit", uid)
    test = u >= 0.5
    report = {"schema": "predict-shield/hikari-in-network/1", "protocol_sha256": hashlib.sha256((HERE / "protocol.json").read_bytes()).hexdigest(),
              "run_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "test_flows": int(test.sum()), "fractions": {}}
    for f in FRACTIONS:
        res = train_and_test(x, attack, cats, u < f / 2, test, v)
        report["fractions"][str(f)] = res
        print("fraction", f, "detection", round(res["detection"], 4), "normal alerts", round(res["normal_alert_rate"], 4), flush=True)
    p = report["fractions"][str(PASS_FRACTION)]
    normal_rates = {c: e["rate"] for c, e in p["by_category"].items() if not e["attack"]}
    report["passed"] = bool(p["detection"] >= FLOOR and p["normal_alert_rate"] <= CEILING
                            and all(r <= CEILING for r in normal_rates.values()))
    report["pass_condition"] = proto["pass_condition"]
    hosts = uniform("hikari-hosts", frame["originh"].astype(str).to_numpy())
    report["host_disjoint"] = train_and_test(x, attack, cats, hosts < 0.5, hosts >= 0.5, v)
    report["note"] = "Flows are dependent; Wilson intervals understate uncertainty. The primary split is random over flows (no timestamps)."
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"passed": report["passed"], "host_disjoint_detection": report["host_disjoint"]["detection"],
                      "host_disjoint_normal_alerts": report["host_disjoint"]["normal_alert_rate"]}, indent=1))


if __name__ == "__main__":
    main()
