"""Version 2 development: fit the supervised model on all CIC-IDS2017 flows,
report leave-one-day-out results that mirror the 2018 calibration step,
freeze. Never opens the test archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

import features_v2 as fv

HERE = Path(__file__).resolve().parent
SEED = 20261120
BUDGET_EACH = 0.005
CODE_FILES = ("features_v2.py", "train_dev_v2.py", "score_test_v2.py", "protocol_v2.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            h.update(block)
    return h.hexdigest()


def code_hashes(directory: Path = HERE) -> dict:
    return {name: sha256_file(directory / name) for name in CODE_FILES}


def fit_supervised(x, y):
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, max_leaf_nodes=31,
                                          class_weight="balanced", early_stopping=False,
                                          random_state=SEED).fit(x, y)


def calibrate(x_fit, x_thresholds, supervised):
    """The calibration step, shared with the test stage: anomaly model on
    x_fit, both thresholds on x_thresholds. Labels are not an argument."""
    from sklearn.ensemble import IsolationForest
    anomaly = IsolationForest(n_estimators=200, max_samples=1024, random_state=SEED).fit(x_fit[:200_000])
    t_s = fv.benign_threshold(supervised.predict_proba(x_thresholds)[:, 1], BUDGET_EACH)
    t_a = fv.benign_threshold(-anomaly.score_samples(x_thresholds), BUDGET_EACH)
    return anomaly, t_s, t_a


def load(archive: Path, members: list[str]):
    xs, attack, family, bucket, member_of, stats = [], [], [], [], [], {}
    columns = None
    for member in members:
        started = time.monotonic()
        for chunk, ctx, st in fv.read_member(archive, member):
            numeric = fv.numeric_columns(list(chunk.columns))
            if columns is None:
                columns = numeric
            elif numeric != columns:
                raise ValueError(f"{member}: columns differ")
            xs.append(fv.build(chunk, columns, ctx))
            classes = [fv.label_class(v) for v in chunk["Label"].astype(str)]
            attack += [a for a, _ in classes]
            family += [f for _, f in classes]
            bucket += [fv.split_bucket(member, i) for i in chunk["id"].to_numpy()]
            member_of += [member] * len(chunk)
            stats[member] = st
        print(member, stats[member], round(time.monotonic() - started), "s", flush=True)
    return (np.vstack(xs), np.array(attack), np.array(family), np.array(bucket), np.array(member_of),
            columns, stats)


def counts(alert, attack):
    return {"TP": int(np.sum(alert & attack)), "FP": int(np.sum(alert & ~attack)),
            "FN": int(np.sum(~alert & attack)), "TN": int(np.sum(~alert & ~attack))}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--protocol", type=Path, default=HERE / "protocol_v2.json")
    args = ap.parse_args()
    protocol = json.loads(args.protocol.read_bytes())
    source = protocol["sources"]["development"]
    digest = sha256_file(args.archive)
    if digest != source["sha256"]:
        raise SystemExit(f"development archive does not match its pin: {digest}")
    x, attack, family, bucket, member_of, columns, stats = load(args.archive, source["members_in_order"])
    print("rows", len(x), "attack", int(attack.sum()), flush=True)

    folds = {}
    for day in source["members_in_order"]:
        on_day = member_of == day
        if not attack[on_day].any():
            continue
        model = fit_supervised(x[~on_day], attack[~on_day])
        anomaly, t_s, t_a = calibrate(x[on_day & (bucket <= 2)], x[on_day & (bucket >= 3) & (bucket <= 5)], model)
        ev = on_day & (bucket >= 6)
        fire_s = model.predict_proba(x[ev])[:, 1] > t_s
        fire_a = -anomaly.score_samples(x[ev]) > t_a
        alert = fire_s | fire_a
        c = counts(alert, attack[ev])
        fams = {}
        for fam in sorted(set(family[ev].tolist()) - {"benign"}):
            m = family[ev] == fam
            fams[fam] = {"flows": int(m.sum()), "detected": int(alert[m].sum()),
                         "by_supervised": int(fire_s[m].sum()), "by_anomaly_only": int((fire_a & ~fire_s)[m].sum()),
                         "family_in_other_days": bool(np.any((family == fam) & ~on_day))}
        folds[day] = dict(c, thresholds={"supervised": t_s, "anomaly": t_a},
                          detection_rate=c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else None,
                          benign_alert_rate=c["FP"] / (c["FP"] + c["TN"]) if c["FP"] + c["TN"] else None,
                          by_family=fams)
        print("held-out day", day, {k: folds[day][k] for k in ("TP", "FP", "FN", "TN", "detection_rate",
                                                               "benign_alert_rate")}, flush=True)
        for fam, v in fams.items():
            print("   ", fam, v, flush=True)

    supervised = fit_supervised(x, attack)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    bundle = pickle.dumps({"supervised": supervised, "numeric_columns": columns,
                           "feature_names": fv.feature_names(columns)}, protocol=5)
    (args.out_dir / "supervised.pkl").write_bytes(bundle)
    freeze = {"schema": "predict-shield/cic-flow-v2-freeze/1", "supervised_sha256": hashlib.sha256(bundle).hexdigest(),
              "code_sha256": code_hashes(), "development_archive_sha256": digest,
              "test_pin": protocol["sources"]["test"]["sha256"], "calibration_member": protocol["calibration"]["member"],
              "development_families": sorted(set(family.tolist()) - {"benign"}),
              "sklearn": __import__("sklearn").__version__, "numpy": np.__version__, "pandas": pd.__version__}
    freeze["freeze_sha256"] = hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest()
    report = {"schema": "predict-shield/cic-flow-v2-development/1", "rows": int(len(x)),
              "family_rows": dict(Counter(family.tolist())), "member_stats": stats,
              "leave_one_day_out": folds, "freeze_sha256": freeze["freeze_sha256"]}
    (args.out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (args.out_dir / "development-report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("FROZEN supervised", freeze["supervised_sha256"], "freeze", freeze["freeze_sha256"], flush=True)


if __name__ == "__main__":
    main()
