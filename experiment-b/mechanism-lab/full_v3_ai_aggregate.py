"""Combine five independently executed real lab shards, fit AI, audit decisions.

Never accepts planned manifest, synthetic outcomes, partial shards, leaked
train/calibration/test group memberships, or mixed source revisions.
Strong deterministic baselines are calibrated before held-out test scoring.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from audit import plan_fingerprint
from full_v3_physical_shard import SCHEMA, SHARDS, GROUPS_PER_SHARD, TRIALS_PER_SHARD, manifest
from plan import ACTIONS, PARTITIONS, create_plan
from train import train_evaluate, to_features

OUTPUT_SCHEMA = "predict-shield/full-v3-real-physical-ai-comparison/1"


def combine(folder: Path) -> dict:
    expected_configs, expected_trials = create_plan()
    expected = {(x["configuration_id"], x["repeat"], x["action_id"])
                for x in expected_trials}
    configurations = {x["configuration_id"]: x for x in expected_configs}
    all_rows = []
    source_sha = set()
    evidence = []
    for shard in range(SHARDS):
        path = folder / f"shard-{shard}.json"
        if not path.is_file():
            raise ValueError("Missing required measured physical shard: " + str(shard))
        data = json.loads(path.read_text(encoding="utf8"))
        c, t = manifest(shard)
        if (data.get("schema") != SCHEMA or data.get("shard_id") != shard
                or data.get("registration_sha256") != plan_fingerprint(c, t)
                or data.get("physical_replays_completed") != TRIALS_PER_SHARD
                or data.get("configuration_groups") != GROUPS_PER_SHARD
                or data.get("all_four_physical_record_streams_audited") is not True
                or data.get("raw_oracle_records_published") is not False
                or data.get("model_training_performed_in_shard") is not False):
            raise ValueError("Shard is not a fully audited physical-only study")
        samples = data.get("sanitized_measured_training_rows")
        if not isinstance(samples, list) or len(samples) != TRIALS_PER_SHARD:
            raise ValueError("Incomplete sanitized measured shard rows")
        payload = json.dumps(samples, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(payload).hexdigest() != data.get("sanitized_rows_sha256"):
            raise ValueError("Measured shard integrity hash mismatch")
        revision = data.get("source_commit_sha")
        if not isinstance(revision, str) or len(revision) != 40 or any(
                x not in "0123456789abcdef" for x in revision):
            raise ValueError("Invalid Git revision on measured physical shard")
        source_sha.add(revision)
        all_rows.extend(samples)
        evidence.append({"shard_id": shard, "manifest_sha256": data["registration_sha256"],
                         "rows_sha256": data["sanitized_rows_sha256"],
                         "physical_replays": TRIALS_PER_SHARD})
    if len(source_sha) != 1 or len(all_rows) != 1200:
        raise ValueError("Mixed source versions or missing measured rows")
    identifiers = [(r["group"], r["repeat"], r["action"]) for r in all_rows]
    if len(set(identifiers)) != 1200 or set(identifiers) != expected:
        raise ValueError("Unregistered, duplicated or missing full v3 paired action")
    seen = Counter()
    for row in all_rows:
        config = configurations[row["group"]]
        if (row["partition"] != config["partition"] or
                row["restart_permitted"] is not config["restart_permitted"] or
                row["absolute_error_budget_requests"] !=
                config["absolute_error_budget_requests"] or
                row["fault"] != config["fault_mode"] or
                row["target"] != config["fault_target"] or
                row["complexity_stratum"] != config["complexity_stratum"]):
            raise ValueError("Physical action disagrees with prospectively registered config")
        if set(row["pre_action"]) & {"fault_mode", "fault_target", "oracle",
                                     "post_action", "event_delay_ms"}:
            raise ValueError("Hidden experimental truth entered pre-action predictor")
        for key in ("label_path_exposure", "label_security_exposure",
                    "label_absolute_failed_requests", "label_service_failure_fraction"):
            val = row.get(key)
            if type(val) not in (int, float) or not math.isfinite(val) or val < 0:
                raise ValueError("Invalid numeric observed physical label")
            if key != "label_absolute_failed_requests" and val > 1:
                raise ValueError("Invalid normalized measured physical label")
        if (len(to_features(row)) < 8 or
                type(row["repeat"]) is not int or not 0 <= row["repeat"] <= 2):
            raise ValueError("Invalid pre-action model feature vector")
        seen[row["partition"]] += 1
    if seen != Counter({p: n*12 for p, n in PARTITIONS.items()}):
        raise ValueError("Train/calibration/test measured rows are not independent")
    # Train sklearn, calibrate only on separately registered groups, then
    # evaluate model-vs-seven-rule decision regret on untouched heldout groups.
    result = train_evaluate(all_rows)
    audit = result["heldout_decision_superiority_audit"]
    return {
        "schema": OUTPUT_SCHEMA,
        "frozen_v3_plan_sha256": plan_fingerprint(expected_configs, expected_trials),
        "source_commit_sha": next(iter(source_sha)),
        "real_physical_action_replays": 1200,
        "independent_configuration_groups": 100,
        "three_repetitions_per_configuration": True,
        "four_actions_per_repetition": True,
        "record_stream_integrity_performed_within_each_shard": True,
        "sanitized_shard_evidence": evidence,
        "all_observations_from_disposable_Kafka_JVM_Docker_lab": True,
        "ai_trained_on_actual_physical_outcomes": True,
        "ai_heldout_group_count": audit["heldout_group_count"],
        "ai_model_mean_regret": audit["heldout_model_mean_regret"],
        "locked_deterministic_rule": audit["locked_non_ai_comparator"],
        "locked_rule_heldout_mean_regret": audit["heldout_locked_baseline_mean_regret"],
        "heldout_paired_regret_improvement": audit["heldout_paired_mean_regret_improvement"],
        "relative_improvement_95": audit["paired_group_bootstrap_relative_95"],
        "seven_rule_familywise_improvement_lower": audit[
            "familywise_adjusted_relative_improvement_lower_by_rule"],
        "all_declared_comparators_beaten": audit["all_prespecified_non_ai_comparators_beaten"],
        "lab_superiority_supported_under_declared_test": audit[
            "improvement_target_supported_in_lab"],
        "reported_lab_conclusion": audit["research_status"],
        "full_model_evaluation": result,
        "external_critical_infrastructure_validated": False,
        "new_six_family_v31_campaign_completed": False,
        "no_production_defensive_actions_by_model": True,
        "limitations": [
            "The predeclared v3 testbed covers four physical fault families, not all six proposed v3.1 families",
            "The operational environment is a disposable Java/Kafka laboratory, not a U.S. infrastructure operator",
            "Shared Docker services and action/repeat carryover may affect independence assumptions",
            "A negative or inconclusive result must remain visible without reselecting heldout examples or hyperparameters",
            "Strong deterministic comparator is selected on calibration groups, not test; all seven rule contrasts reported",
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--shards", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    if args.report.exists():
        raise FileExistsError("Refusing to overwrite actual evidence")
    report = combine(args.shards)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({
        "actual_physical_action_replays": report["real_physical_action_replays"],
        "heldout_groups": report["ai_heldout_group_count"],
        "ai_mean_regret": report["ai_model_mean_regret"],
        "rule_mean_regret": report["locked_rule_heldout_mean_regret"],
        "relative_95_ci": report["relative_improvement_95"],
        "superiority_supported_in_this_lab": report["lab_superiority_supported_under_declared_test"],
        "infrastructure_field_validation": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
