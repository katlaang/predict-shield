"""Version 3 test on HIKARI-2021: verify the freeze, calibrate on the test
network's verified-normal flows, score every other flow once.

Split by SHA-256 of the flow uid into ten buckets:
  * buckets 0 and 1 are the calibration share. Their traffic_category is read
    only to keep flows marked Benign (verified normal): bucket 0 fits the
    anomaly model, bucket 1 sets both thresholds. Background flows and
    attacks in these buckets are not used and not scored.
  * buckets 2 to 9 are scored once. Benign and Background count as normal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

import features_v3 as fv
from train_dev_v3 import calibrate, code_hashes, sha256_file

HERE = Path(__file__).resolve().parent
DETECTION_FLOOR = 0.5
NORMAL_CEILING = 0.01


def verify(frozen_dir: Path, expected: str, archive: Path, code_dir: Path) -> tuple[dict, dict]:
    freeze = json.loads((frozen_dir / "freeze.json").read_text())
    recorded = freeze.pop("freeze_sha256")
    if recorded != expected or hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest() != recorded:
        raise SystemExit("freeze record does not match")
    if code_hashes(code_dir) != freeze["code_sha256"]:
        raise SystemExit("feature, scoring or protocol code changed after freeze")
    bundle_bytes = (frozen_dir / "supervised.pkl").read_bytes()
    if hashlib.sha256(bundle_bytes).hexdigest() != freeze["supervised_sha256"]:
        raise SystemExit("supervised model does not match the freeze record")
    proto = json.loads((code_dir / "protocol_v3.json").read_text())
    if sha256_file(archive) != freeze["test_pin"] or freeze["test_pin"] != proto["sources"]["test"]["sha256"]:
        raise SystemExit("test archive does not match its pin")
    freeze["freeze_sha256"] = recorded
    return freeze, pickle.loads(bundle_bytes)


def load(archive: Path, member: str) -> pd.DataFrame:
    with zipfile.ZipFile(archive) as z, z.open(member) as raw:
        return pd.read_csv(raw, low_memory=False)


def buckets_for(uids) -> np.ndarray:
    return np.array([fv.split_bucket("hikari2021", u) for u in uids], dtype=np.int8)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--frozen-dir", type=Path, required=True)
    ap.add_argument("--expected-freeze-sha256", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--code-dir", type=Path, default=HERE)
    args = ap.parse_args()
    freeze, bundle = verify(args.frozen_dir, args.expected_freeze_sha256, args.archive, args.code_dir)
    proto = json.loads((args.code_dir / "protocol_v3.json").read_text())
    member = proto["sources"]["test"]["member"]
    supervised, cfg = bundle["supervised"], bundle["config"]

    frame = load(args.archive, member)
    columns = fv.resolve_hikari(list(frame.columns))
    if frame[fv.HIKARI_ID].duplicated().any():
        raise SystemExit("flow uid is not unique")
    x = fv.build(frame, columns, fv.HIKARI_PORT, hikari=True, feature_set=cfg["feature_set"])
    bucket = buckets_for(frame[fv.HIKARI_ID].to_numpy())
    category = frame[fv.HIKARI_CATEGORY].astype(str).to_numpy()

    # calibration share: verified-normal flows only
    benign = category == "Benign"
    if np.any(frame[fv.HIKARI_LABEL].to_numpy()[benign] != 0):
        raise SystemExit("a flow marked Benign carries Label 1; the verified-normal set is not clean")
    anomaly, t_s, t_a = calibrate(x[benign & (bucket == 0)], x[benign & (bucket == 1)], supervised)
    calibration = {"anomaly_fit_rows": int(min(np.sum(benign & (bucket == 0)), 200_000)),
                   "threshold_rows": int(np.sum(benign & (bucket == 1))),
                   "unused_calibration_share_rows": int(np.sum(~benign & (bucket <= 1))),
                   "thresholds": {"supervised": t_s, "anomaly": t_a}}
    print("calibrated", calibration, flush=True)

    ev = bucket >= 2
    fire_s = supervised.predict_proba(x[ev])[:, 1] > t_s
    fire_a = -anomaly.score_samples(x[ev]) > t_a
    alert = fire_s | fire_a
    classes = [fv.hikari_class(c, l) for c, l in zip(category[ev], frame[fv.HIKARI_LABEL].to_numpy()[ev])]
    attack = np.array([a for a, _ in classes])
    family = np.array([f for _, f in classes], dtype=object)
    cats = category[ev]

    tp, fp = int(np.sum(alert & attack)), int(np.sum(alert & ~attack))
    fn, tn = int(np.sum(~alert & attack)), int(np.sum(~alert & ~attack))
    by_category = {}
    for c in sorted(set(cats.tolist())):
        m = cats == c
        is_attack = bool(attack[m][0])
        entry = {"flows": int(m.sum()), "alerts": int(alert[m].sum()), "by_supervised": int(fire_s[m].sum()),
                 "by_anomaly_only": int((fire_a & ~fire_s)[m].sum()), "attack": is_attack,
                 "rate": float(alert[m].mean()), "wilson_95": fv.wilson(int(alert[m].sum()), int(m.sum()))}
        if is_attack:
            entry["family"] = str(family[m][0])
            entry["family_in_development"] = entry["family"] in freeze["development_families"]
        by_category[c] = entry
    normal_rates = {c: e["rate"] for c, e in by_category.items() if not e["attack"]}
    pooled_normal = fp / (fp + tn) if fp + tn else None
    detection = tp / (tp + fn) if tp + fn else None
    passed = bool(pooled_normal is not None and detection is not None and pooled_normal <= NORMAL_CEILING
                  and all(r <= NORMAL_CEILING for r in normal_rates.values()) and detection >= DETECTION_FLOOR)
    report = {
        "schema": "predict-shield/cic-flow-v3-test/1", "freeze_sha256": freeze["freeze_sha256"],
        "supervised_sha256": freeze["supervised_sha256"], "config": cfg, "code_sha256": freeze["code_sha256"],
        "test_archive_sha256": freeze["test_pin"], "member": member, "rows_in_file": int(len(frame)),
        "calibration": calibration, "flows": int(ev.sum()), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "detection_rate": detection, "detection_wilson_95": fv.wilson(tp, tp + fn),
        "normal_alert_rate": pooled_normal, "normal_alert_wilson_95": fv.wilson(fp, fp + tn),
        "normal_alert_rate_by_category": normal_rates,
        "precision": tp / (tp + fp) if tp + fp else None,
        "pass_condition": "normal alert rate at most 1% pooled and for Benign and Background separately, "
                          "and attack detection at least 50% pooled",
        "passed": passed, "by_category": by_category,
        "note": "Flows within one capture are dependent; Wilson intervals understate uncertainty.",
    }
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("flows", "TP", "FP", "FN", "TN", "detection_rate",
                                             "normal_alert_rate", "precision", "passed")}, indent=1))
    for c, e in by_category.items():
        print(c, e)


if __name__ == "__main__":
    main()
