"""Version 2 test: verify the freeze (model, code, protocol, archive), run the
calibration step on the calibration day without reading its labels, then
score every flow of the other days once."""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import time
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np

import features_v2 as fv
from train_dev_v2 import calibrate, code_hashes, sha256_file

HERE = Path(__file__).resolve().parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--frozen-dir", type=Path, required=True)
    ap.add_argument("--expected-freeze-sha256", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--code-dir", type=Path, default=HERE)
    args = ap.parse_args()
    freeze = json.loads((args.frozen_dir / "freeze.json").read_text())
    recorded = freeze.pop("freeze_sha256")
    if recorded != args.expected_freeze_sha256 or \
            hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest() != recorded:
        raise SystemExit("freeze record does not match")
    if code_hashes(args.code_dir) != freeze["code_sha256"]:
        raise SystemExit("feature, scoring or protocol code changed after freeze")
    bundle_bytes = (args.frozen_dir / "supervised.pkl").read_bytes()
    if hashlib.sha256(bundle_bytes).hexdigest() != freeze["supervised_sha256"]:
        raise SystemExit("supervised model does not match the freeze record")
    protocol = json.loads((args.code_dir / "protocol_v2.json").read_text())
    if sha256_file(args.archive) != freeze["test_pin"] or freeze["test_pin"] != protocol["sources"]["test"]["sha256"]:
        raise SystemExit("test archive does not match its pin")
    bundle = pickle.loads(bundle_bytes)
    supervised, columns = bundle["supervised"], bundle["numeric_columns"]
    calibration_member = freeze["calibration_member"]

    # calibration: features only; the Label column is never read here
    started = time.monotonic()
    fit_rows, threshold_rows, cal_stats = [], [], None
    for chunk, ctx, st in fv.read_member(args.archive, calibration_member):
        x = fv.build(chunk, columns, ctx)
        b = np.array([fv.split_bucket(calibration_member, i) for i in chunk["id"].to_numpy()])
        fit_rows.append(x[b <= 4])
        threshold_rows.append(x[b >= 5])
        cal_stats = st
    x_fit, x_thr = np.vstack(fit_rows), np.vstack(threshold_rows)
    anomaly, t_s, t_a = calibrate(x_fit, x_thr, supervised)
    cal_bytes = pickle.dumps({"anomaly": anomaly, "thresholds": (t_s, t_a)}, protocol=5)
    calibration = {"member": calibration_member, "rows": cal_stats["rows"],
                   "out_of_order_rows": cal_stats["out_of_order_rows"],
                   "anomaly_fit_rows": int(min(len(x_fit), 200_000)), "threshold_rows": int(len(x_thr)),
                   "thresholds": {"supervised": t_s, "anomaly": t_a},
                   "calibration_bundle_sha256": hashlib.sha256(cal_bytes).hexdigest(),
                   "seconds": round(time.monotonic() - started)}
    print("calibrated", calibration, flush=True)
    del fit_rows, threshold_rows, x_fit, x_thr

    total = defaultdict(int)
    by_family = defaultdict(lambda: defaultdict(int))
    by_label = defaultdict(lambda: defaultdict(int))
    by_member = defaultdict(lambda: defaultdict(int))
    unmapped = set()
    with zipfile.ZipFile(args.archive) as z:
        members = sorted(i.filename for i in z.infolist()
                         if i.filename.lower().endswith(".csv") and i.filename != calibration_member)
    for member in members:
        started = time.monotonic()
        for chunk, ctx, st in fv.read_member(args.archive, member):
            x = fv.build(chunk, columns, ctx)
            fire_s = supervised.predict_proba(x)[:, 1] > t_s
            fire_a = -anomaly.score_samples(x) > t_a
            alert = fire_s | fire_a
            for label, a, s, an in zip(chunk["Label"].astype(str), alert, fire_s, fire_a):
                is_attack, fam = fv.label_class(label)
                key = ("TP" if a else "FN") if is_attack else ("FP" if a else "TN")
                total[key] += 1
                by_member[member][key] += 1
                if fam == "unmapped":
                    unmapped.add(label)
                if is_attack:
                    for bucket in (by_family[fam], by_label[label]):
                        bucket["flows"] += 1
                        bucket["detected"] += int(a)
                        bucket["by_supervised"] += int(s)
                        bucket["by_anomaly"] += int(an)
                        bucket["by_anomaly_only"] += int(an and not s)
                else:
                    b = by_family["benign"]
                    b["flows"] += 1
                    b["false_alarms"] += int(a)
                    b["by_supervised"] += int(s)
                    b["by_anomaly"] += int(an)
        by_member[member]["out_of_order_rows"] = st["out_of_order_rows"]
        print(member, dict(by_member[member]), round(time.monotonic() - started), "s", flush=True)

    tp, fp, fn, tn = (total[k] for k in ("TP", "FP", "FN", "TN"))
    families = {}
    for fam, c in sorted(by_family.items()):
        c = dict(c)
        if fam != "benign":
            c["detection_rate"] = c["detected"] / c["flows"]
            c["wilson_95"] = fv.wilson(c["detected"], c["flows"])
            c["family_in_development"] = fam in freeze["development_families"]
        families[fam] = c
    day_rates = {m: v["FP"] / (v["FP"] + v["TN"]) for m, v in by_member.items() if v["FP"] + v["TN"]}
    benign_rate = fp / (fp + tn) if fp + tn else None
    report = {
        "schema": "predict-shield/cic-flow-v2-test/1", "freeze_sha256": recorded,
        "supervised_sha256": freeze["supervised_sha256"], "code_sha256": freeze["code_sha256"],
        "test_archive_sha256": freeze["test_pin"], "calibration": calibration, "members": members,
        "flows": tp + fp + fn + tn, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "detection_rate": tp / (tp + fn) if tp + fn else None, "detection_wilson_95": fv.wilson(tp, tp + fn),
        "benign_alert_rate": benign_rate, "benign_alert_wilson_95": fv.wilson(fp, fp + tn),
        "precision": tp / (tp + fp) if tp + fp else None,
        "benign_alert_rate_by_day": day_rates,
        "pass_condition": "benign alert rate at most 1% pooled and on every day",
        "passed": bool(benign_rate is not None and benign_rate <= 0.01 and all(r <= 0.01 for r in day_rates.values())),
        "by_family": families, "by_label": {k: dict(v) for k, v in sorted(by_label.items())},
        "by_member": {k: dict(v) for k, v in by_member.items()}, "unmapped_labels": sorted(unmapped),
        "note": "Second measurement on the 2018 data (version 1 read its labels). Flows within a day are dependent; intervals understate uncertainty.",
    }
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("flows", "TP", "FP", "FN", "TN", "detection_rate",
                                             "benign_alert_rate", "precision", "passed")}, indent=1))
    for fam, c in families.items():
        print(fam, c)


if __name__ == "__main__":
    main()
