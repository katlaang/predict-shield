"""Repeat actual disposable authority-outage pilot batches and retain sanitized evidence.

Every invocation runs a bounded number of physical four-action replay batches.
These are repeated observations of ONE declared fault configuration, not
independent test configurations, a new preregistered experiment, AI training
data, or evidence of an infrastructure field deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from authority_outage_actions import ACTIONS, execute
from outage_interval_diagnostic import evaluate as interval_evaluate

SCHEMA = "predict-shield/repeated-physical-outage-pilot/1"


def source_revision(root: Path) -> str:
    sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True, timeout=8).stdout.strip()
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise ValueError("Missing exact Git source commit")
    return sha


def summarize(batch: dict, diagnostic: dict) -> dict:
    if (batch.get("schema") != "predict-shield/v31-outage-action-observations/1"
            or batch.get("physical_action_replays") != 4
            or batch.get("decision_value_computed") is not False
            or batch.get("v31_feasibility_evaluated") is not False):
        raise ValueError("Not a complete physical four-action observation batch")
    if (diagnostic.get("status") != "EXPLORATORY_INTERVALS_ONLY"
            or not diagnostic.get("not_v31_feasibility_or_campaign_authorization")):
        raise ValueError("Invalid fail-closed interval evaluator")
    items = batch.get("results")
    if not isinstance(items, list) or len(items) != 4 or set(x.get("action") for x in items) != set(ACTIONS):
        raise ValueError("Missing physical action arm")
    score_by_action = {x["action"]: x for x in diagnostic["action_intervals"]}
    if set(score_by_action) != set(ACTIONS):
        raise ValueError("Incomplete exploratory action intervals")
    rows = []
    for x in items:
        t = x["timed_observations"]
        ex = t["revoked_gateway_exposure"]
        if (x["policy_truth"] != "UNKNOWN" or x["verification_status"] != "INDETERMINATE"
                or ex["valid_probe_count"] < 2 or
                t["authorized_protected"]["requests"] < 1 or
                t["legitimate_endpoint"]["requests"] < 1):
            raise ValueError("Invalid independent physical observation")
        rows.append({
            "action": x["action"],
            "physical_action_status": x["action_observation"]["action_status"],
            "policy_truth": "UNKNOWN",
            "verification_status": "INDETERMINATE",
            "direct_allow_count": x["observed_allow_count"],
            "direct_deny_count": x["observed_deny_count"],
            "direct_unknown_count": x["unknown_target_count"],
            "exposure_seconds_lower": ex["exposure_seconds_lower_bound"],
            "exposure_seconds_upper": ex["exposure_seconds_upper_bound"],
            "exposure_fraction_lower": ex["exposure_fraction_lower_bound"],
            "exposure_fraction_upper": ex["exposure_fraction_upper_bound"],
            "valid_revoked_gateway_probe_count": ex["valid_probe_count"],
            "authorized_requests": t["authorized_protected"]["requests"],
            "authorized_failures": t["authorized_protected"]["non_200_requests"],
            "legitimate_requests": t["legitimate_endpoint"]["requests"],
            "legitimate_failures": t["legitimate_endpoint"]["non_200_requests"],
            "exploratory_cost_lower": score_by_action[x["action"]]["cost_lower_bound"],
            "exploratory_cost_upper": score_by_action[x["action"]]["cost_upper_bound"],
            "policy_witness_sha256": x["witness_sha256"],
        })
    return {"actions": rows,
            "known_offline_eligible_actions":
                diagnostic["feasible_actions_for_offline_comparison"],
            "unique_definite_exploratory_best_action":
                diagnostic["unique_definite_best_action"],
            "no_model_used_to_choose_action": True}


def aggregate(batches: list[dict], source_sha: str) -> dict:
    if len(batches) < 1 or len(batches) > 5:
        raise ValueError("One to five complete physical batches supported")
    if not isinstance(source_sha, str) or len(source_sha) != 40:
        raise ValueError("Exact source SHA required")
    all_witnesses = []
    for b in batches:
        if not isinstance(b.get("actions"), list) or set(x["action"] for x in b["actions"]) != set(ACTIONS):
            raise ValueError("Partial batch")
        all_witnesses.extend(x["policy_witness_sha256"] for x in b["actions"])
    if len(set(all_witnesses)) != len(all_witnesses):
        raise ValueError("Reused witnessed trial across physical action arms")
    by_action = {}
    for action in ACTIONS:
        v = [next(a for a in batch["actions"] if a["action"] == action) for batch in batches]
        by_action[action] = {
            "physical_repetitions": len(v),
            "observed_gateway_exposure_seconds_lower_total": sum(x["exposure_seconds_lower"] for x in v),
            "observed_gateway_exposure_seconds_upper_total": sum(x["exposure_seconds_upper"] for x in v),
            "authorized_failures": sum(x["authorized_failures"] for x in v),
            "authorized_attempts": sum(x["authorized_requests"] for x in v),
            "legitimate_failures": sum(x["legitimate_failures"] for x in v),
            "legitimate_attempts": sum(x["legitimate_requests"] for x in v),
        }
    return {
        "schema": SCHEMA, "source_commit_sha": source_sha,
        "experiment_name": "physical_authority_outage_repeated_exploratory_mechanism",
        "record_type": "MEASURED_DISPOSABLE_DOCKER_PHYSICAL_REPLAYS",
        "fault_family": "authority_outage",
        "independent_fault_configuration_count": 1,
        "physical_four_action_batches": len(batches),
        "physical_action_replays": 4 * len(batches),
        "batch_records": batches,
        "by_action": by_action,
        "v31_feasibility_evaluated": False,
        "ai_action_model_trained_or_tested": False,
        "critical_infrastructure_operator_pilot": False,
        "research_conclusion": "EXPLORATORY_MECHANISM_REPEATS_ONLY",
        "limitations": [
            "Repeated batches reuse the same fault configuration; they are not independent configurations",
            "UNKNOWN live authority truth is not a verified policy outcome",
            "Exposure integrates sampled HTTP probe intervals with conservative bounds",
            "Research weights are exploratory, not a prospectively frozen v3.1 primary utility",
            "No model action-selection performance or real operator benefit is evaluated",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--execute-lab", action="store_true")
    p.add_argument("--batches", type=int, default=2)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if not a.execute_lab:
        p.error("Physical Docker mutations require --execute-lab")
    if not 1 <= a.batches <= 5:
        p.error("Use 1-5 actual batches per invocation")
    if a.output.exists():
        raise FileExistsError("Refusing to overwrite recorded measured evidence")
    control, oracle = os.getenv("LAB_CONTROL_TOKEN", ""), os.getenv("LAB_ORACLE_TOKEN", "")
    if min(len(control), len(oracle)) < 24 or control == oracle:
        raise RuntimeError("Separate disposable control and oracle credentials required")
    root = Path(__file__).resolve().parent
    recorded = []
    for index in range(a.batches):
        batch = execute(control, oracle, root)
        evaluation = interval_evaluate(batch, error_budget_requests=25, restart_permitted=True)
        row = summarize(batch, evaluation)
        row["batch_number"] = index + 1
        row["observed_utc"] = datetime.now(timezone.utc).isoformat()
        # Commit each FULL action batch separately before attempting the
        # next one; failed later batches cannot erase earlier observations.
        a.output.parent.mkdir(parents=True, exist_ok=True)
        partial = a.output.parent / ("physical-batch-%02d.json" % (index + 1))
        with partial.open("x", encoding="utf-8") as stream:
            json.dump({"schema": "predict-shield/single-physical-batch/1",
                       "source_commit_sha": source_revision(root),
                       "four_physical_actions_observed": True,
                       "batch": row, "not_independent_configuration": True},
                      stream, sort_keys=True, indent=2)
            stream.write("\n")
        recorded.append(row)
    report = aggregate(recorded, source_revision(root))
    with a.output.open("x", encoding="utf-8") as f:
        json.dump(report, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps({"schema": SCHEMA, "physical_action_replays": report["physical_action_replays"],
                      "research_conclusion": report["research_conclusion"],
                      "ai_tested": False}))


if __name__ == "__main__":
    main()
