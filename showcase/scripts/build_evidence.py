"""Collect the headline numbers for the showcase from committed reports only.

Every figure on the site's evidence page is read here from a report file in
the repository, and each entry carries the path it came from.

  python showcase/scripts/build_evidence.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "showcase" / "public" / "data" / "evidence.json"
REPO = "https://github.com/katlaang/predict-shield/blob/master/"


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text())


def main() -> None:
    camp = "docs/evidence/mechanism-scored-campaign/run-44879497946/"
    outcomes = load(camp + "scored-outcomes.json")["by_fault_and_class"]
    verifier = load(camp + "scored-verifier-scoring.json")
    audit = load(camp + "scored-audit.json")
    controls = load(camp + "controls.json")
    exploit = load("experiment-b/exploit-likelihood/frozen/test-report.json")["test"]
    pd = load("experiment-b/powerduck/frozen/test-report.json")
    v2 = load("experiment-b/cic-flow-v2/frozen/test-report.json")
    v3 = load("experiment-b/cic-flow-v3/frozen/test-report.json")

    arms = {cls: {a: {k: s[k] for k in ("remediated", "trials", "configurations",
                                         "configurations_remediated_in_majority_of_repeats",
                                         "exposure_seconds_lower_mean", "exposure_seconds_upper_mean",
                                         "failed_requests_mean", "mean_cost_by_missed_weight", "error_counts")}
                       for a, s in outcomes[f"ALL/{cls}"]["arms"].items()}
            for cls in ("persistent", "self_healing")}
    lowest = {cls: {"lowest": outcomes[f"ALL/{cls}"]["lowest_cost_actions"],
                    "robust": outcomes[f"ALL/{cls}"]["robust_across_ratios"]}
              for cls in ("persistent", "self_healing")}
    ver = verifier["by_fault_and_action"]["ALL/ALL"]
    v2_det = v2.get("detection_rate") or v2.get("pooled", {}).get("detection_rate")
    data = {
        "campaign": {
            "source": REPO + "docs/evidence/MEASURED_MECHANISM_LAB_SCORED_CAMPAIGN_2026_11_21.md",
            "run": "https://github.com/katlaang/predict-shield/actions/runs/44879497946",
            "trials": audit["complete"], "planned": audit["planned_trials"], "missing": audit["missing"],
            "lock": "9422667f129b2da8d1d121387f2f8dc0a2b0f40777d6f4b7c635bf39243f973b",
            "controls_confirmed": controls["plan_classes_confirmed"],
            "arms": arms, "costs": lowest,
            "verifier": {k: {x: ver[k][x] for x in ("TP", "TN", "FN", "false_VERIFIED", "abstain_truly_denied",
                                                     "abstain_truly_exposed", "cases")}
                         for k in ("single_evidence", "dual_evidence")},
        },
        "exploit": {
            "source": REPO + "docs/evidence/MEASURED_EXPLOIT_LIKELIHOOD_2026_11_20.md",
            "cves": exploit["rows"], "exploited": exploit["positives"], "roc_auc": exploit["roc_auc"],
            "top": {k: exploit[k] for k in ("top_1pct", "top_5pct", "top_10pct")},
        },
        "misses": [
            {"name": "Substation GOOSE detector", "source": REPO + "docs/evidence/MEASURED_POWERDUCK_GOOSE_DETECTOR_2026_11_21.md",
             "target": "False alarms at most 1% and at least 12 of 16 scenarios caught",
             "detection": pd["scenarios_detected"], "scenarios": pd["scenarios_total"],
             "false_alarm_rate": pd["non_malicious_alert_rate"]},
            {"name": "Network-flow detector v2", "source": REPO + "docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_V2_2026_11_20.md",
             "target": "False alarms at most 1% (met). No detection floor was set, and detection was under 1%", "detection_rate": v2_det,
             "false_alarm_rate": v2.get("benign_alert_rate") or v2.get("pooled", {}).get("benign_alert_rate")},
            {"name": "Network-flow detector v3", "source": REPO + "docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_V3_2026_11_23.md",
             "target": "False alarms at most 1% and at least 50% detection",
             "detection_rate": v3["detection_rate"], "false_alarm_rate": v3["normal_alert_rate"]},
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print("wrote", OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
