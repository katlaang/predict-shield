"""Development: fit on CIC-IDS2017 improved, set thresholds, report, freeze.

Follows protocol.json. Writes the frozen model bundle and a freeze record.
Never opens the test archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

import flow_features as ff

HERE = Path(__file__).resolve().parent
SEED = 20261119
BUDGET_EACH = 0.005


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            h.update(block)
    return h.hexdigest()


def load_development(archive: Path, members: list[str]):
    xs, attack, family, bucket, member_of = [], [], [], [], []
    names = None
    with zipfile.ZipFile(archive) as z:
        for member in members:
            started = time.monotonic()
            context = ff.ContextWindow()
            with z.open(member) as raw:
                for chunk in pd.read_csv(raw, chunksize=200_000, low_memory=False):
                    numeric = ff.numeric_columns(list(chunk.columns))
                    if names is None:
                        names, columns = ff.feature_names(numeric), numeric
                    elif numeric != columns:
                        raise ValueError(f"{member}: columns differ from the first member")
                    xs.append(ff.build(chunk, columns, context))
                    classes = [ff.label_class(v) for v in chunk["Label"].astype(str)]
                    attack += [a for a, _ in classes]
                    family += [f for _, f in classes]
                    bucket += [ff.split_bucket(member, i) for i in chunk["id"].to_numpy()]
                    member_of += [member] * len(chunk)
            print(member, "loaded in", round(time.monotonic() - started), "s", flush=True)
    return (np.vstack(xs), np.array(attack), np.array(family), np.array(bucket), np.array(member_of),
            names, columns)


def fit_supervised(x, y):
    from sklearn.ensemble import HistGradientBoostingClassifier
    model = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, max_leaf_nodes=31,
                                           class_weight="balanced", early_stopping=False, random_state=SEED)
    return model.fit(x, y)


def counts(alert, attack):
    return {"TP": int(np.sum(alert & attack)), "FP": int(np.sum(alert & ~attack)),
            "FN": int(np.sum(~alert & attack)), "TN": int(np.sum(~alert & ~attack))}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--protocol", type=Path, default=HERE / "protocol.json")
    ap.add_argument("--skip-leave-one-out", action="store_true")
    args = ap.parse_args()
    protocol_bytes = args.protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    source = protocol["sources"]["development"]
    digest = sha256_file(args.archive)
    if digest != source["sha256"]:
        raise SystemExit(f"development archive does not match its pin: {digest}")
    x, attack, family, bucket, member_of, names, columns = load_development(args.archive,
                                                                           source["members_in_order"])
    train, calib, dev = bucket <= 5, (bucket == 6) | (bucket == 7), bucket >= 8
    print("rows", len(x), "train", int(train.sum()), "calibration", int(calib.sum()), "dev", int(dev.sum()),
          flush=True)

    from sklearn.ensemble import IsolationForest
    supervised = fit_supervised(x[train], attack[train])
    benign_train = np.flatnonzero(train & ~attack)[:200_000]
    anomaly = IsolationForest(n_estimators=200, max_samples=1024, random_state=SEED).fit(x[benign_train])

    p = supervised.predict_proba(x)[:, 1]
    a = -anomaly.score_samples(x)
    t_s = ff.benign_threshold(p[calib & ~attack], BUDGET_EACH)
    t_a = ff.benign_threshold(a[calib & ~attack], BUDGET_EACH)
    fire_s, fire_a = p > t_s, a > t_a
    alert = fire_s | fire_a

    def summary(mask):
        c = counts(alert[mask], attack[mask])
        pos, neg = c["TP"] + c["FN"], c["FP"] + c["TN"]
        return dict(c, detection_rate=c["TP"] / pos if pos else None,
                    false_alarm_rate=c["FP"] / neg if neg else None)

    report = {
        "schema": "predict-shield/cic-flow-development/1",
        "protocol_sha256": hashlib.sha256(protocol_bytes).hexdigest(),
        "development_archive_sha256": digest,
        "rows": {"total": int(len(x)), "train": int(train.sum()), "calibration": int(calib.sum()),
                 "development_evaluation": int(dev.sum())},
        "family_rows": dict(Counter(family.tolist())),
        "thresholds": {"supervised": t_s, "anomaly": t_a},
        "calibration_benign_alert_rate": float(alert[calib & ~attack].mean()),
        "development_evaluation": summary(dev),
        "by_family": {},
        "by_member": {m: summary(dev & (member_of == m)) for m in source["members_in_order"]},
    }
    for fam in sorted(set(family.tolist()) - {"benign"}):
        m = dev & (family == fam)
        report["by_family"][fam] = {"flows": int(m.sum()), "detected": int(alert[m].sum()),
                                    "by_supervised": int(fire_s[m].sum()), "by_anomaly": int(fire_a[m].sum()),
                                    "by_anomaly_only": int((fire_a & ~fire_s)[m].sum())}
    print(json.dumps({k: report[k] for k in ("thresholds", "calibration_benign_alert_rate",
                                             "development_evaluation")}, indent=1), flush=True)

    if not args.skip_leave_one_out:
        loo = {}
        for fam in sorted(set(family.tolist()) - {"benign"}):
            keep = train & (family != fam)
            model = fit_supervised(x[keep], attack[keep])
            pp = model.predict_proba(x)[:, 1]
            ts = ff.benign_threshold(pp[calib & ~attack], BUDGET_EACH)
            m = dev & (family == fam)
            loo[fam] = {"flows": int(m.sum()), "detected": int(((pp > ts) | fire_a)[m].sum()),
                        "by_supervised_without_family": int((pp > ts)[m].sum()),
                        "by_anomaly": int(fire_a[m].sum())}
            print("leave out", fam, loo[fam], flush=True)
        report["leave_one_family_out"] = loo

    args.out_dir.mkdir(parents=True, exist_ok=True)
    bundle = pickle.dumps({"supervised": supervised, "anomaly": anomaly, "thresholds": (t_s, t_a),
                           "feature_names": names, "numeric_columns": columns}, protocol=5)
    (args.out_dir / "model.pkl").write_bytes(bundle)
    freeze = {"schema": "predict-shield/cic-flow-freeze/1", "model_sha256": hashlib.sha256(bundle).hexdigest(),
              "thresholds": {"supervised": t_s, "anomaly": t_a}, "feature_names": names,
              "numeric_columns": columns, "protocol_sha256": report["protocol_sha256"],
              "development_archive_sha256": digest, "test_pin": protocol["sources"]["test"]["sha256"],
              "sklearn": __import__("sklearn").__version__, "numpy": np.__version__, "pandas": pd.__version__}
    freeze["freeze_sha256"] = hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest()
    report["freeze"] = {k: freeze[k] for k in ("model_sha256", "freeze_sha256")}
    (args.out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (args.out_dir / "development-report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("FROZEN model", freeze["model_sha256"], "freeze", freeze["freeze_sha256"], flush=True)


if __name__ == "__main__":
    main()
