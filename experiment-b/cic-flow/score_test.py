"""The single test run: score every CSE-CIC-IDS2018 improved flow with the
frozen bundle. Refuses to run if the bundle, the freeze record, the protocol
or the test archive differ from what was recorded at freeze time.
"""
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
import pandas as pd

import flow_features as ff
from train_dev import sha256_file

HERE = Path(__file__).resolve().parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--frozen-dir", type=Path, required=True)
    ap.add_argument("--expected-freeze-sha256", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--protocol", type=Path, default=HERE / "protocol.json")
    args = ap.parse_args()
    protocol_bytes = args.protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    freeze = json.loads((args.frozen_dir / "freeze.json").read_text())
    recorded = freeze.pop("freeze_sha256")
    if recorded != args.expected_freeze_sha256 or \
            hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest() != recorded:
        raise SystemExit("freeze record does not match")
    bundle_bytes = (args.frozen_dir / "model.pkl").read_bytes()
    if hashlib.sha256(bundle_bytes).hexdigest() != freeze["model_sha256"]:
        raise SystemExit("model bundle does not match the freeze record")
    if hashlib.sha256(protocol_bytes).hexdigest() != freeze["protocol_sha256"]:
        raise SystemExit("protocol changed after freeze")
    pin = protocol["sources"]["test"]["sha256"]
    if pin != freeze["test_pin"] or sha256_file(args.archive) != pin:
        raise SystemExit("test archive does not match its pin")
    bundle = pickle.loads(bundle_bytes)
    supervised, anomaly = bundle["supervised"], bundle["anomaly"]
    t_s, t_a = bundle["thresholds"]
    columns = bundle["numeric_columns"]

    total = defaultdict(int)
    by_family = defaultdict(lambda: defaultdict(int))
    by_label = defaultdict(lambda: defaultdict(int))
    by_member = defaultdict(lambda: defaultdict(int))
    unmapped_labels = set()
    with zipfile.ZipFile(args.archive) as z:
        members = sorted(i.filename for i in z.infolist() if i.filename.lower().endswith(".csv"))
        for member in members:
            started = time.monotonic()
            context = ff.ContextWindow()
            with z.open(member) as raw:
                for chunk in pd.read_csv(raw, chunksize=200_000, low_memory=False):
                    missing = [c for c in columns if c not in chunk.columns]
                    if missing:
                        raise SystemExit(f"{member}: missing columns {missing}")
                    x = ff.build(chunk, columns, context)
                    fire_s = supervised.predict_proba(x)[:, 1] > t_s
                    fire_a = -anomaly.score_samples(x) > t_a
                    alert = fire_s | fire_a
                    for label, a, s, an in zip(chunk["Label"].astype(str), alert, fire_s, fire_a):
                        is_attack, fam = ff.label_class(label)
                        key = ("TP" if a else "FN") if is_attack else ("FP" if a else "TN")
                        total[key] += 1
                        by_member[member][key] += 1
                        if fam == "unmapped":
                            unmapped_labels.add(label)
                        if is_attack:
                            for bucket in (by_family[fam], by_label[label]):
                                bucket["flows"] += 1
                                bucket["detected"] += int(a)
                                bucket["by_supervised"] += int(s)
                                bucket["by_anomaly"] += int(an)
                                bucket["by_anomaly_only"] += int(an and not s)
                        else:
                            by_family["benign"]["flows"] += 1
                            by_family["benign"]["false_alarms"] += int(a)
                            by_family["benign"]["by_supervised"] += int(s)
                            by_family["benign"]["by_anomaly"] += int(an)
            print(member, dict(by_member[member]), round(time.monotonic() - started), "s", flush=True)

    tp, fp, fn, tn = (total[k] for k in ("TP", "FP", "FN", "TN"))
    development_families = set(json.loads((args.frozen_dir / "development-report.json").read_text())
                               ["by_family"])
    families = {}
    for fam, c in sorted(by_family.items()):
        c = dict(c)
        if fam != "benign":
            c["detection_rate"] = c["detected"] / c["flows"]
            c["wilson_95"] = ff.wilson(c["detected"], c["flows"])
            c["family_in_development"] = fam in development_families
        families[fam] = c
    report = {
        "schema": "predict-shield/cic-flow-test/1",
        "freeze_sha256": recorded, "model_sha256": freeze["model_sha256"],
        "protocol_sha256": freeze["protocol_sha256"], "test_archive_sha256": pin,
        "members": members, "flows": tp + fp + fn + tn,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "detection_rate": tp / (tp + fn) if tp + fn else None, "detection_wilson_95": ff.wilson(tp, tp + fn),
        "false_alarm_rate": fp / (fp + tn) if fp + tn else None, "false_alarm_wilson_95": ff.wilson(fp, fp + tn),
        "precision": tp / (tp + fp) if tp + fp else None,
        "by_family": families,
        "by_label": {k: dict(v) for k, v in sorted(by_label.items())},
        "by_member": {k: dict(v) for k, v in by_member.items()},
        "unmapped_labels": sorted(unmapped_labels),
        "note": "Flows within a day are dependent; Wilson intervals understate the real uncertainty. Per-day results are in by_member.",
    }
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("flows", "TP", "FP", "FN", "TN", "detection_rate",
                                             "false_alarm_rate", "precision")}, indent=1))
    for fam, c in families.items():
        print(fam, c)


if __name__ == "__main__":
    main()
