"""Execute and audit one of five disjoint physical v3 experiment shards.

One shard = 20 registered independent operating configurations, 3 repeats and
4 distinct physical actions = 240 real Kafka/JVM/Docker action replays.
Exports ONLY audited, numeric, pre-action + measured-label learning records.
Privileged four-stream raw oracle observations never leave the CI runner.
This is exploratory execution of the existing v3 protocol, not v3.1 validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path

from plan import create_plan, ACTIONS
from campaign import run_batch
from audit import inspect_trial, audit_campaign, plan_fingerprint
from train import summarize_operator_telemetry

SCHEMA = "predict-shield/full-v3-exploratory-physical-shard/1"
SHARDS = 5
GROUPS_PER_SHARD = 20
TRIALS_PER_SHARD = 240


def manifest(shard: int) -> tuple[list[dict], list[dict]]:
    if type(shard) is not int or not 0 <= shard < SHARDS:
        raise ValueError("Shard ID must be 0-4")
    configs, trials = create_plan()
    selected = {c["configuration_id"] for c in configs
                if int(c["configuration_id"].split("-")[-1]) % SHARDS == shard}
    subset_configs = [c for c in configs if c["configuration_id"] in selected]
    subset_trials = [t for t in trials if t["configuration_id"] in selected]
    if len(subset_configs) != GROUPS_PER_SHARD or len(subset_trials) != TRIALS_PER_SHARD:
        raise ValueError("Shard violates original frozen v3 design")
    if len({x["run_id"] for x in subset_trials}) != len(subset_trials):
        raise ValueError("Duplicate physical trial")
    return subset_configs, subset_trials


def _physical_rows(configs: list[dict], trials: list[dict], records: Path) -> list[dict]:
    by_config = {c["configuration_id"]: c for c in configs}
    out = []
    source_commits = set()
    for trial in trials:
        state, message = inspect_trial(trial, records)
        if state != "complete":
            raise ValueError("Missing independently audited physical trial: " + message)
        streams = {kind: json.loads((records / kind / (trial["run_id"] + ".json")).read_text())
                   for kind in ("pre_action", "verification", "operations", "oracle")}
        pre, verification, ops, oracle = [streams[k] for k in
                                         ("pre_action", "verification", "operations", "oracle")]
        if (len({s["source_commit"] for s in streams.values()}) != 1 or
                pre.get("model_prediction_recorded") is not False or
                pre.get("oracle_features_excluded") is not True or
                verification.get("verification_did_not_read_oracle") is not True):
            raise ValueError("Missing independent source/feature isolation")
        source_commits.add(pre["source_commit"])
        cfg = by_config[trial["configuration_id"]]
        conditions = pre["experimental_conditions"]
        if (conditions["fault_mode"] != cfg["fault_mode"] or
                conditions["fault_target"] != cfg["fault_target"]):
            raise ValueError("Unregistered physical fault was executed")
        if pre["decision_policy_metadata"]["restart_permitted"] != cfg["restart_permitted"]:
            raise ValueError("Policy eligibility changed during physical experiment")
        timeline = verification["timed_gateway_exposure"]
        if timeline["method"] != "monotonic_http_step_integral" or timeline["valid_probe_count"] < 2:
            raise ValueError("No genuine bounded physical exposure samples")
        truth = oracle["after"].get("all_revoked_access_denied")
        if type(truth) is not bool or oracle["after"].get("inventory_complete") is not True:
            raise ValueError("Missing full-scope independent oracle evidence")
        attempts, failures = ops["observed_requests"], ops["failed_requests"]
        if (type(attempts) is not int or type(failures) is not int or
                attempts < 1 or not 0 <= failures <= attempts):
            raise ValueError("Invalid measured operational failure denominators")
        observations = pre["external_deny_observations"]
        if not observations or any(x.get("http_status") not in (200, 403) for x in observations):
            raise ValueError("No complete measured pre-action gateway observations")
        features = {
            **summarize_operator_telemetry(pre["operator_observations"]),
            "routing_profile": pre.get("routing_profile", "balanced"),
            "cache_ttl_ms": pre["features"]["cache_ttl_ms"],
            "requested_rps": pre["features"]["requested_rps"],
            "gateway_visible_enforcer_count": pre["features"]["visible_enforcement_processes"],
            "initial_gateway_allowed_fraction":
                sum(x["http_status"] == 200 for x in observations) / len(observations),
        }
        if set(features) & {"fault_mode", "fault_target", "oracle", "post_action", "event_delay_ms"}:
            raise ValueError("Privileged fault or post-action data leaked into model inputs")
        out.append({
            "group": pre["configuration_id"], "partition": pre["partition"],
            "repeat": trial["repeat"], "action": trial["action_id"],
            # Fault and target metadata are retained ONLY for post-hoc
            # stratification, and are not used in train.to_features().
            "fault": conditions["fault_mode"], "target": conditions["fault_target"],
            "complexity_stratum": pre["complexity_stratum"],
            "restart_permitted": cfg["restart_permitted"],
            "absolute_error_budget_requests": cfg["absolute_error_budget_requests"],
            "pre_action": features,
            "label_security_exposure": float(not truth),
            "label_path_exposure": float(timeline["exposure_fraction_upper_bound"]),
            "label_exposure_seconds": float(timeline["exposure_seconds_upper_bound"]),
            "label_absolute_failed_requests": float(failures),
            "label_service_failure_fraction": failures / attempts,
        })
    if len(out) != TRIALS_PER_SHARD or len(source_commits) != 1:
        raise ValueError("Incomplete or mixed-version shard results")
    return out


def run(shard: int, root: Path, output: Path) -> dict:
    if root.exists() or output.exists():
        raise FileExistsError("A new shard execution requires an untouched output root")
    credentials = [os.getenv(x, "") for x in
                   ("LAB_CONTROL_TOKEN", "LAB_ORACLE_TOKEN", "LAB_INTERNAL_TOKEN")]
    if any(len(t) < 24 for t in credentials) or len(set(credentials)) != 3:
        raise ValueError("Distinct disposable credentials required")
    configs, trials = manifest(shard)
    records = root / "raw-private-four-streams"
    for start in range(0, len(trials), 12):
        result = run_batch(configs, trials, records, credentials[0], credentials[1],
                           start=start, max_trials=12)
        if result["newly_executed_trials"] != 12 or result["partial"] or result["invalid"]:
            raise RuntimeError("Incomplete physical batch")
        print(json.dumps({"shard": shard,
                          "measured_action_replays": result["total_completed"],
                          "remaining": result["total_remaining"]}), flush=True)
    status = audit_campaign(configs, trials, records)
    if (status["complete"] != TRIALS_PER_SHARD or status["missing"] or status["partial"]
            or status["invalid"] or status["unexpected_files"] or
            status["single_source_revision"] is not True):
        raise ValueError("Failed independent full four-stream shard integrity")
    samples = _physical_rows(configs, trials, records)
    payload = json.dumps(samples, sort_keys=True, separators=(",", ":")).encode()
    from collect import source_commit
    report = {
        "schema": SCHEMA, "shard_id": shard,
        "source_commit_sha": source_commit(),
        "registration_sha256": plan_fingerprint(configs, trials),
        "physical_replays_completed": status["complete"],
        "configuration_groups": GROUPS_PER_SHARD,
        "distinct_partitions": dict(Counter(c["partition"] for c in configs)),
        "sanitized_measured_training_rows": samples,
        "sanitized_rows_sha256": hashlib.sha256(payload).hexdigest(),
        "raw_oracle_records_published": False,
        "all_four_physical_record_streams_audited": True,
        "model_training_performed_in_shard": False,
        "research_status": "EXPLORATORY_REAL_PHYSICAL_OBSERVATIONS_NOT_AI_RESULT",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf8") as file:
        json.dump(report, file, sort_keys=True, separators=(",", ":"))
        file.write("\n")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--execute-lab", action="store_true")
    p.add_argument("--shard", required=True, type=int)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if not args.execute_lab:
        p.error("Physical Docker mutation requires --execute-lab")
    result = run(args.shard, args.root, args.output)
    print(json.dumps({"shard": args.shard,
                      "physical_replays": result["physical_replays_completed"],
                      "claim": "LAB_OBSERVATIONS_NOT_AI_EFFECTIVENESS"}))
