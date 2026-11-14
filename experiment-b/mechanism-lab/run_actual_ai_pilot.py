"""Run registered exploratory AI-vs-rule experiment on ACTUAL four-stream records.

The 24 configurations and their partitions are deterministic and registered
before observing outcomes. Replay each arm physically in disposable Docker.
No oracle stream or pre-action private injected fault metadata reaches model.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ai_comparison_plan import build, digest, save
from actual_ai_comparison import evaluate, read_measured
from audit import audit_campaign
from campaign import run_batch


def run(root: Path, report_path: Path) -> dict:
    if report_path.exists():
        raise FileExistsError("Refusing to overwrite a measured report")
    if root.exists():
        raise FileExistsError("Use a new evidence root for each independent study")
    control = os.getenv("LAB_CONTROL_TOKEN", "")
    oracle = os.getenv("LAB_ORACLE_TOKEN", "")
    internal = os.getenv("LAB_INTERNAL_TOKEN", "")
    if any(len(x) < 24 for x in (control, oracle, internal)) or len({control, oracle, internal}) != 3:
        raise RuntimeError("Three unique disposable lab credentials are mandatory")
    configs, trials = build()
    plan_dir = root / "plan"
    save(plan_dir)
    records = root / "records"
    if digest(configs, trials) != json.loads((plan_dir / "registration.json").read_text())["plan_sha256"]:
        raise RuntimeError("Prospective plan fingerprint mismatch")
    for start in range(0, len(trials), 8):
        status = run_batch(configs, trials, records, control, oracle,
                           start=start, max_trials=min(8, len(trials) - start))
        if status["partial"] or status["invalid"]:
            raise RuntimeError("Physical four-stream audit failed")
    audit = audit_campaign(configs, trials, records)
    if (audit["complete"] != 96 or audit["partial"] or audit["invalid"]
            or audit["missing"] or audit["unexpected_files"]
            or not audit["single_source_revision"]):
        raise RuntimeError("Refusing to score incomplete/invalid executed physical actions")
    rows, provenance = read_measured(records)
    result = evaluate(rows, provenance)
    result["physical_four_stream_integrity_audit"] = {
        "complete": audit["complete"],
        "missing": audit["missing"],
        "partial": audit["partial"],
        "invalid": audit["invalid"],
        "unexpected_files": audit["unexpected_files"],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--execute-lab", action="store_true")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    if not args.execute_lab:
        p.error("Real Docker mutation requires explicit --execute-lab")
    r = run(args.root, args.report)
    print(json.dumps({"physical_replays": r["executed_physical_action_replays"],
                      "heldout_groups": r["heldout_groups"],
                      "ai_regret": r["test_ai_mean_hindsight_regret"],
                      "baseline_regret": r["test_locked_rule_mean_hindsight_regret"],
                      "exploratory_only": True}))
