"""New-configuration disposable Kafka pilot: independent four-stream pair scoring.

This DOES NOT establish statistical AI superiority. Strictly accepts one
pre-registered, previously unexecuted plan-v3.1 test configuration, with
three complete replays and four physical actions each.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from collect import load_plan
from train import _read_stream, summarize_operator_telemetry, ROUTING_PROFILES
from paired_defense_eval import ACTIONS, evaluate_paired, make_trusted_lab_model_policy


def _hash_json(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
                    separators=(",", ":")).encode("utf-8")).hexdigest()


def _selected(configs: list[dict]) -> dict:
    test = [c for c in configs if c["partition"] == "test"]
    if not test:
        raise ValueError("No test configuration in registered plan")
    return min(test, key=lambda c: c["configuration_id"])


def load_new_paired(registered_plan: Path, records: Path, *,
                    expected_seed: int = 20261130) -> tuple[list[dict], dict]:
    # Independently regenerate, rather than trusting an attacker-writable
    # manifest for a "fresh" label or selected test configuration.
    from plan import create_plan
    regenerated, regenerated_trials = create_plan(seed=expected_seed, version="v3.1")
    configs, trials = load_plan(registered_plan)
    if _hash_json(configs) != _hash_json(regenerated) or _hash_json(trials) != _hash_json(regenerated_trials):
        raise ValueError("Measured plan differs from newly registered deterministic configuration")
    chosen = _selected(configs)
    wanted = {t["run_id"]: t for t in trials if t["configuration_id"] == chosen["configuration_id"]}
    if len(wanted) != 12 or set(t["action_id"] for t in wanted.values()) != set(ACTIONS):
        raise ValueError("Registered new test configuration must contain 12 trial arms")

    sources = {kind: _read_stream(records / kind) for kind in
               ("pre_action", "verification", "operations", "oracle")}
    if any(set(rows) != set(wanted) for rows in sources.values()):
        raise ValueError("Incomplete or unexpected physical action records")
    source_revisions = set()
    examples = []
    for trial_id, t in sorted(wanted.items()):
        pre, verifier, operations, oracle = (sources[name][trial_id] for name in
                                             ("pre_action", "verification", "operations", "oracle"))
        for src in (pre, verifier, operations, oracle):
            if any(src.get(k) != expected for k, expected in (
                ("run_id", trial_id),
                ("configuration_id", t["configuration_id"]),
                ("action_id", t["action_id"]),
                ("repeat", t["repeat"]),
                ("partition", "test"),
                ("initial_state_seed", t["initial_state_seed"]),
                ("experiment_type", "real_kafka_multijvm_lab"),
            )):
                raise ValueError("Cross-stream identity, partition or protocol mismatch")
        revisions = {src.get("source_commit") for src in (pre, verifier, operations, oracle)}
        if len(revisions) != 1:
            raise ValueError("Mixed source commits in four independent streams")
        revision = revisions.pop()
        if (not isinstance(revision, str) or len(revision) != 40 or
                any(ch not in "0123456789abcdef" for ch in revision)):
            raise ValueError("Invalid new physical collection source revision")
        source_revisions.add(revision)
        if pre.get("model_prediction_recorded") is not False or pre.get("oracle_features_excluded") is not True:
            raise ValueError("Oracle/post-action features have polluted the pre-action record")
        if any(name in pre["features"] for name in ("fault_mode", "fault_target", "oracle_truth")):
            raise ValueError("Hidden fault information leaked into model features")
        # Never interpret a v2 schema mismatch, absent collector results, or
        # out-of-range zero-imputed telemetry as a valid AI decision trial.
        # Missing operator measurements are an inconclusive measurement
        # failure, not evidence that an AI intentionally chose to abstain.
        observations = pre.get("operator_observations")
        if (not isinstance(observations, list) or len(observations) != 4
                or {row.get("node") for row in observations if isinstance(row, dict)}
                   != {"enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden"}
                or any(not isinstance(row, dict)
                       or row.get("observed") is not True
                       or row.get("operator_schema") != "operator_pre_action_v2"
                       for row in observations)):
            raise ValueError("Incomplete v2 operator telemetry: experiment INCONCLUSIVE")
        meta = pre.get("decision_policy_metadata", {})
        if type(meta.get("restart_permitted")) is not bool or type(meta.get("absolute_error_budget_requests")) is not int:
            raise ValueError("No verified action authorization metadata")
        before = pre.get("external_deny_observations")
        if not isinstance(before, list) or not before or any(x.get("http_status") not in (200,403)
                                                           for x in before):
            raise ValueError("Incomplete pre-action gateway observation")
        post = oracle.get("after")
        if (not isinstance(post, dict) or post.get("inventory_complete") is not True
                or type(post.get("all_revoked_access_denied")) is not bool
                or oracle.get("oracle_role") != "separate_process_admin_plus_direct_probe"):
            raise ValueError("Missing independent post-action physical oracle")
        timeline = verifier.get("timed_gateway_exposure")
        if (not isinstance(timeline, dict) or timeline.get("method") != "monotonic_http_step_integral"
                or timeline.get("valid_probe_count", 0) < 2
                or not 0 <= timeline.get("exposure_fraction_lower_bound", -1)
                         <= timeline.get("exposure_fraction_upper_bound", -1) <= 1):
            raise ValueError("No independent valid exposure interval")
        failed, attempted = operations.get("failed_requests"), operations.get("observed_requests")
        if type(failed) is not int or type(attempted) is not int or not 0 <= failed <= attempted or attempted < 1:
            raise ValueError("No measured service-health denominator")
        features = pre["features"]
        if pre.get("routing_profile") not in ROUTING_PROFILES:
            raise ValueError("Invalid operational routing profile")
        examples.append({
            "group": t["configuration_id"],
            "partition": "test", "repeat": t["repeat"],
            "action": t["action_id"],
            "restart_permitted": meta["restart_permitted"],
            "absolute_error_budget_requests": meta["absolute_error_budget_requests"],
            "pre_action": {
                **summarize_operator_telemetry(pre.get("operator_observations", [])),
                "routing_profile": pre["routing_profile"],
                "cache_ttl_ms": features["cache_ttl_ms"],
                "requested_rps": features["requested_rps"],
                "gateway_visible_enforcer_count": features["visible_enforcement_processes"],
                "initial_gateway_allowed_fraction": sum(
                    x["http_status"] == 200 for x in before) / len(before),
            },
            "label_security_exposure": float(not post["all_revoked_access_denied"]),
            "label_path_exposure": float(timeline["exposure_fraction_upper_bound"]),
            "label_absolute_failed_requests": float(failed),
        })
    if len(source_revisions) != 1:
        raise ValueError("Mixed collector source revisions across new physical trials")
    if len({(x["group"], x["repeat"]) for x in examples}) != 3:
        raise ValueError("Expected three complete independent action pairs within one configuration")
    return examples, {"selected_configuration": chosen["configuration_id"],
                      "source_commit": next(iter(source_revisions)),
                      "selected_fault_family_is_not_a_model_input": True,
                      "pre_registered_seed": expected_seed,
                      "trial_count": len(examples),
                      "physical_dataset_sha256": _hash_json(sources),
                      "plan_sha256": _hash_json([configs,trials])}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--records", type=Path, required=True)
    p.add_argument("--historical-model", type=Path, required=True)
    p.add_argument("--historical-model-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Refusing to overwrite results")
    rows, provenance = load_new_paired(args.plan, args.records)
    from model_adapter import load_local_bundle
    model = load_local_bundle(args.historical_model,
                              trusted_sha256=args.historical_model_sha256)
    report = evaluate_paired(
        rows, make_trusted_lab_model_policy(model),
        model_fingerprint=args.historical_model_sha256,
        dataset_fingerprint=provenance["physical_dataset_sha256"])
    report["status"] = "SMALL_NEW_CONFIGURATION_PILOT_NOT_SUPERIORITY_PROOF"
    report["historical_evaluator_schema_reused"] = True
    report["new_measurement_provenance"] = provenance
    report["prospective_superiority_established"] = False
    report["production_effectiveness_established"] = False
    report["limitations"].extend([
        "Only one new independent configuration; three within-configuration replays are correlated",
        "This protocol cannot be used to claim statistical superiority or a validated trained AI defense model",
        "New random seeds do not guarantee unseen fault families; all faults use the existing simulated mechanism classes",
        "Experimental utility and selected model are only a laboratory policy evaluation",
    ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Saved new physical small pilot, no superiority established:", args.output)


if __name__ == "__main__":
    main()
