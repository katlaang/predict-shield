"""Per-action outcome report for the scored mechanism-lab campaign (questions Q1 and Q2).

Written and tested on synthetic records and the CI pilot before any scored
result existed, and added to the preregistration lock through DEVIATIONS.md.

For every arm (fault mode x control class x action) it reports:
- Q1: how often every revoked access is denied after the action, judged by
  the oracle (injected ground truth), per trial and per configuration;
- Q2: exposure-seconds during the measured window (lower and upper bound) and
  failed legitimate requests;
- error counts: missed fix, late fix, disruption, unnecessary action and
  abstention, as defined in PREREGISTRATION.json;
- mean cost under the preregistered cost matrix, with the missed-fix weight
  at 1, 5 and 20 (unnecessary action fixed at 1), and which action has the
  lowest mean cost under each ratio. A lowest-cost action is called robust
  only if it is the same at all three ratios.

Actions are compared with each other only. No learned model is evaluated here.

Usage, inside experiment-b/mechanism-lab:
  python outcome_report.py --plan plans/v31 --records results/scored --output reports/outcomes.json
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, median

from collect import load_plan
from verifier_scoring import dual_verdict, telemetry_reading, wilson

HERE = Path(__file__).resolve().parent
COSTS = json.loads((HERE / "PREREGISTRATION.json").read_text())["cost_matrix"]
MISSED_WEIGHTS = (1, 5, 20)
LATE_FRACTION = 0.5


def trial_row(config: dict, records: dict[str, dict]) -> dict:
    """One trial's outcome fields from its four record streams."""
    v, o, op = records["verification"], records["oracle"], records["operations"]
    timeline = v["timed_gateway_exposure"]
    remediated = bool(o["actual_revoked_access_denied"])
    window = timeline["window_seconds"]
    upper = timeline["exposure_seconds_upper_bound"]
    dual, _ = dual_verdict(v["outcome"], telemetry_reading(v.get("operator_observations_after")))
    action = v["action_id"]
    return {
        "run_id": v["run_id"],
        "configuration_id": config["configuration_id"],
        "partition": config["partition"],
        "fault_mode": config["fault_mode"],
        "control_class": config.get("control_class"),
        "restart_permitted": config.get("restart_permitted", True),
        "action": action,
        "remediated": remediated,
        "exposure_lower": timeline["exposure_seconds_lower_bound"],
        "exposure_upper": upper,
        "window_seconds": window,
        "failed_requests": op["failed_requests"],
        "observed_requests": op["observed_requests"],
        "errors": {
            "missed_fix": not remediated,
            "late_fix": remediated and upper > LATE_FRACTION * window,
            "disruption": op["failed_requests"] > config.get("absolute_error_budget_requests", 25),
            "unnecessary_action": config.get("control_class") == "self_healing" and action != "monitor_only",
            "abstention": v["outcome"] == "INDETERMINATE" or dual == "ABSTAIN",
        },
    }


def trial_cost(row: dict, missed_weight: float) -> float:
    weights = {**{k: COSTS[k] for k in ("late_fix", "disruption", "unnecessary_action", "abstention")},
               "missed_fix": missed_weight}
    return sum(weights[k] for k, hit in row["errors"].items() if hit)


def arm_summary(rows: list[dict]) -> dict:
    n = len(rows)
    k = sum(r["remediated"] for r in rows)
    by_config = defaultdict(list)
    for r in rows:
        by_config[r["configuration_id"]].append(r["remediated"])
    config_majority = sum(sum(v) * 2 > len(v) for v in by_config.values())
    return {
        "trials": n,
        "remediated": k,
        "remediated_rate": k / n if n else None,
        "remediated_wilson_95": wilson(k, n),
        "configurations": len(by_config),
        "configurations_remediated_in_majority_of_repeats": config_majority,
        "configuration_level_wilson_95": wilson(config_majority, len(by_config)),
        "exposure_seconds_lower_mean": mean(r["exposure_lower"] for r in rows) if rows else None,
        "exposure_seconds_upper_mean": mean(r["exposure_upper"] for r in rows) if rows else None,
        "exposure_seconds_upper_median": median(r["exposure_upper"] for r in rows) if rows else None,
        "failed_requests_mean": mean(r["failed_requests"] for r in rows) if rows else None,
        "error_counts": {e: sum(r["errors"][e] for r in rows) for e in rows[0]["errors"]} if rows else {},
        "mean_cost_by_missed_weight": {str(w): mean(trial_cost(r, w) for r in rows) if rows else None
                                       for w in MISSED_WEIGHTS},
        "restart_not_permitted_trials": sum(not r["restart_permitted"] and r["action"] == "restart_enforcer"
                                            for r in rows),
    }


def lowest_cost(arms: dict[str, dict]) -> dict:
    """Lowest mean-cost action per ratio, and whether it is the same at all ratios."""
    best = {}
    for w in MISSED_WEIGHTS:
        costs = {a: s["mean_cost_by_missed_weight"][str(w)] for a, s in arms.items()}
        low = min(costs.values())
        best[f"1:{w}"] = sorted(a for a, c in costs.items() if c == low)
    choices = {tuple(v) for v in best.values()}
    return {"lowest_cost_actions": best, "robust_across_ratios": len(choices) == 1}


def build_report(rows: list[dict]) -> dict:
    groups: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        groups[(r["fault_mode"], r["control_class"])][r["action"]].append(r)
        groups[("ALL", r["control_class"])][r["action"]].append(r)
    report = {}
    for (fault, cls), by_action in sorted(groups.items(), key=lambda x: (str(x[0][0]), str(x[0][1]))):
        arms = {a: arm_summary(v) for a, v in sorted(by_action.items())}
        report[f"{fault}/{cls}"] = {"arms": arms, **lowest_cost(arms)}
    return report


def load_rows(plan_dir: Path, records: Path) -> list[dict]:
    configs, trials = load_plan(plan_dir)
    by_id = {c["configuration_id"]: c for c in configs}
    rows = []
    for t in trials:
        files = {s: records / s / (t["run_id"] + ".json") for s in ("verification", "oracle", "operations")}
        if not all(f.is_file() for f in files.values()):
            continue
        rows.append(trial_row(by_id[t["configuration_id"]],
                              {s: json.loads(f.read_text()) for s, f in files.items()}))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", type=Path, required=True)
    ap.add_argument("--records", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    rows = load_rows(args.plan, args.records)
    if not rows:
        raise SystemExit("no complete trials")
    out = {
        "schema": "predict-shield/mechanism-outcomes/1",
        "label": "oracle actual_revoked_access_denied (injected ground truth)",
        "trials": len(rows),
        "cost_matrix": COSTS,
        "late_fix_rule": f"remediated with exposure upper bound above {LATE_FRACTION:.0%} of the window",
        "by_fault_and_class": build_report(rows),
        "note": "Repeats of one configuration share a seed; configuration-level counts are the primary unit.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for key, entry in out["by_fault_and_class"].items():
        print(key, {a: (s["remediated"], s["trials"]) for a, s in entry["arms"].items()},
              entry["lowest_cost_actions"], "robust" if entry["robust_across_ratios"] else "not robust")


if __name__ == "__main__":
    main()
