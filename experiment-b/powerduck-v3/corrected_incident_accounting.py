"""Retrospective correction of PowerDuck v3 incident truth accounting.

Original model, frozen code, alert decisions and threshold stay unchanged.
A true incident must contain a malicious message that actually alerted.
This is post-result reanalysis on already examined captures.
"""
import argparse
import json
from pathlib import Path
import zipfile

import numpy as np

import detector_v3 as d
import gated_history as gh


def incident_counts(times, alerts, malicious):
    alerts = np.asarray(alerts, dtype=bool)
    malicious = np.asarray(malicious, dtype=bool)
    if len(alerts) != len(malicious) or len(alerts) != len(times):
        raise ValueError("mismatched message arrays")
    groups = gh.incidents(np.asarray(times), alerts, d.GAP_S)
    true = sum(bool(np.any(alerts[s:e + 1] & malicious[s:e + 1])) for s, e in groups)
    return {"incidents": len(groups), "true_incidents": true,
            "false_incidents": len(groups) - true}


def audit(archive: Path, frozen: Path, output: Path):
    registered = json.loads((frozen / "test-report.json").read_text())
    freeze_record = json.loads((frozen / "freeze.json").read_text())
    freeze, payload = d.verify(frozen, freeze_record["freeze_sha256"], archive)
    forest = gh.FastForest(payload["model"])
    threshold, known = payload["threshold"], payload["known_streams"]
    corrected = {}
    with zipfile.ZipFile(archive) as z:
        members = sorted(n for n in z.namelist()
                         if n.startswith("dataset/ipal/Attack/") and n.endswith(".ipal.gz"))
    for member in members:
        rec, base, streams, times = d.load(archive, member)
        _, alert = gh.gated_scores(forest, threshold, base, streams, known)
        malicious = np.asarray([gh.is_malicious(r) for r in rec], dtype=bool)
        name = member.split("/")[-1].removesuffix(".ipal.gz")
        corrected[name] = incident_counts(times, alert, malicious)
        original = registered["scenarios"][name]
        if corrected[name]["incidents"] != original["incidents"]:
            raise ValueError("Incident grouping differs from original frozen output")
        if corrected[name]["false_incidents"] < original["false_incidents"]:
            raise ValueError("Corrected false incidents cannot decrease")
        if int((alert & malicious).sum()) != original["TP"]:
            raise ValueError("Original attack detection decisions changed")
        if int((alert & ~malicious).sum()) != original["FP"]:
            raise ValueError("Original false-positive decisions changed")
    if set(corrected) != set(registered["scenarios"]):
        raise ValueError("Scenario population mismatch")
    false = sum(v["false_incidents"] for v in corrected.values())
    true = sum(v["true_incidents"] for v in corrected.values())
    hours = sum(v["hours"] for v in registered["scenarios"].values())
    result = {
        "schema": "predict-shield/powerduck-v3-incident-correction/1",
        "post_hoc": True, "new_holdout": False, "model_changed": False,
        "threshold_changed": False, "freeze_sha256": freeze["freeze_sha256"],
        "original_report_false_incidents": registered["false_incidents"],
        "corrected_false_incidents": false,
        "corrected_true_incidents": true,
        "hours": hours,
        "corrected_false_incidents_per_hour": false / hours if hours else None,
        "scenarios": corrected,
        "registered_pass_condition_failed": True,
        "qualification": "Retrospective accounting correction on previously scored scenarios; no fresh detector evaluation."
    }
    if false < registered["false_incidents"] or false + true != sum(v["incidents"] for v in corrected.values()):
        raise ValueError("Retrospective incident arithmetic mismatch")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--frozen-dir", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    print(json.dumps(audit(args.archive, args.frozen_dir, args.output), sort_keys=True))
