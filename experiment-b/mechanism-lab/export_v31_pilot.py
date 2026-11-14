"""Export v3.1 feasibility inputs ONLY from independently audited physical records.

A registered pilot is separate from the 150-group final campaign. Four
streams, matching source commits and actual measured action effects are
required. No oracle-derived truth enters the pre-action predictor.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

from audit import STREAMS, inspect_trial
from decision_eval import ACTIONS, observed_utility

SCHEMA = "predict-shield/v31-audited-action-costs/1"
PILOT_SCHEMA = "predict-shield/v31-physical-pilot-plan/1"


def export(configs: list[dict], trials: list[dict], root: Path) -> list[dict]:
    """Compute one record per group/repeat, never from generated labels."""
    if len(configs) < 3:
        raise ValueError("At least three predeclared pilot configuration groups")
    by_id = {c["configuration_id"]: c for c in configs}
    if len(by_id) != len(configs):
        raise ValueError("Duplicate pilot configurations")
    for c in configs:
        if (c.get("schema") != PILOT_SCHEMA or c.get("partition") != "pilot"
                or not c["configuration_id"].startswith("v31-pilot-")):
            raise ValueError("No main-campaign or unsupported pilot configuration")
    assignments = defaultdict(dict)
    source_revisions = set()
    seen_runs = set()
    for t in trials:
        ident = t.get("configuration_id")
        config = by_id.get(ident)
        if config is None or t.get("partition") != "pilot":
            raise ValueError("Unregistered or nonpilot replay")
        if t.get("execution_status") != "PLANNED_NOT_EXECUTED":
            raise ValueError("Pilot registration must not contain invented outcomes")
        action = t.get("action_id")
        repeat = t.get("repeat")
        if action not in ACTIONS or type(repeat) is not int or repeat not in (0, 1):
            raise ValueError("Invalid paired action/repeat")
        key = (ident, repeat)
        if action in assignments[key] or t.get("run_id") in seen_runs:
            raise ValueError("Duplicate pilot action or run ID")
        seen_runs.add(t["run_id"])
        status, reason = inspect_trial(t, root)
        if status != "complete":
            raise ValueError("Unverified physical replay: " + reason)
        files = {stream: json.loads((root / stream / (t["run_id"] + ".json")).read_text())
                 for stream in STREAMS}
        pre, verification, operations, oracle = (
            files[name] for name in STREAMS)
        source_revisions.add(pre["source_commit"])
        if any(files[name]["source_commit"] != pre["source_commit"] for name in STREAMS):
            raise ValueError("Cross-stream source mismatch")
        conditions = pre.get("experimental_conditions") or {}
        if (conditions.get("fault_mode") != config["fault_mode"]
                or conditions.get("fault_target") != config["fault_target"]):
            raise ValueError("Physical conditions differ from registered pilot")
        if pre.get("complexity_stratum") != config["complexity_stratum"]:
            raise ValueError("Wrong measured complexity stratum")
        policy = pre.get("decision_policy_metadata", {})
        if (policy.get("restart_permitted") is not config["restart_permitted"]
                or policy.get("absolute_error_budget_requests") != config["absolute_error_budget_requests"]):
            raise ValueError("Policy metadata differs across registered plan")
        if (verification.get("verification_did_not_read_oracle") is not True
                or pre.get("oracle_features_excluded") is not True):
            raise ValueError("Independent verification or no-leakage contract violated")
        if config["fault_mode"] == "consumer_paused":
            physical = oracle.get("physical_fault_evidence")
            if not isinstance(physical, dict) or (
                    physical.get("listener_pause_physically_observed") is not True
                    or physical.get("target_http_status") != 200):
                raise ValueError("No physical consumer-pause witness in privileged stream")
            if oracle["before"].get("all_revoked_access_denied") is not False:
                raise ValueError("Consumer pause did not cause actual stale access")
        timeline = verification.get("timed_gateway_exposure", {})
        exposure = timeline.get("exposure_fraction_upper_bound")
        if (timeline.get("valid_probe_count", 0) < 2 or
                type(exposure) not in (float, int) or
                not math.isfinite(exposure) or not 0 <= exposure <= 1):
            raise ValueError("No valid observed upper exposure bound")
        truth = oracle.get("actual_revoked_access_denied")
        if type(truth) is not bool:
            raise ValueError("No independent full-scope outcome")
        failed, observed = operations.get("failed_requests"), operations.get("observed_requests")
        if (type(failed) is not int or type(observed) is not int
                or not 0 <= failed <= observed or observed == 0):
            raise ValueError("Invalid physical legitimate-request count")
        cost = observed_utility({
            "label_path_exposure": exposure,
            "label_security_exposure": float(not truth),
            "label_absolute_failed_requests": failed,
            "absolute_error_budget_requests": config["absolute_error_budget_requests"],
        })
        assignments[key][action] = cost
    if len(source_revisions) != 1 or len(assignments) != len(configs) * 2:
        raise ValueError("Not a single-source, two-repeat pilot")
    source = next(iter(source_revisions))
    if not (isinstance(source, str) and len(source) == 40 and
            all(v in "0123456789abcdef" for v in source)):
        raise ValueError("Unverifiable source revision")
    expected = set(ACTIONS)
    result = []
    for c in configs:
        for repeat in (0, 1):
            by_action = assignments.get((c["configuration_id"], repeat))
            if by_action is None or set(by_action) != expected:
                raise ValueError("Missing measured candidate action")
            result.append({
                "schema": SCHEMA,
                "measurement_verified": True,
                "four_streams_complete": True,
                "partition": "pilot",
                "source_commit": source,
                "configuration_id": c["configuration_id"],
                "stratum": c["complexity_stratum"],
                "repeat": repeat,
                "eligible_actions": [
                    a for a in ACTIONS
                    if c["restart_permitted"] or a != "restart_enforcer"],
                "action_costs": by_action,
            })
    # Refuse extraneous observations instead of silently ignoring them.
    for stream in STREAMS:
        unexpected = [p.name for p in (root / stream).glob("*.json")
                      if p.stem not in seen_runs]
        if unexpected:
            raise ValueError("Unregistered trial records in " + stream)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    configs = [json.loads(line) for line in
               (args.plan_dir / "configurations.jsonl").read_text().splitlines()
               if line.strip()]
    trials = [json.loads(line) for line in
              (args.plan_dir / "trials.jsonl").read_text().splitlines()
              if line.strip()]
    result = export(configs, trials, args.records)
    with args.output.open("x") as f:
        for row in result:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    print(json.dumps({"audited_configuration_groups":len(configs),
                      "paired_decisions":len(result),
                      "caution":"Audited laboratory evidence is not external validation"}))


if __name__ == "__main__":
    main()
