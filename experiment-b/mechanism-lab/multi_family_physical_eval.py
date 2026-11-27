"""Multi-family measured Kafka defense development evaluation.

Reads real four-stream, separately physically executed action arms from one
previously frozen v3.1 seed. No generated outcomes, online model tuning,
production action dispatch, or claims of prospective superiority.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from collect import load_plan
from plan import create_plan
from train import _read_stream, summarize_operator_telemetry, ROUTING_PROFILES
from paired_defense_eval import ACTIONS, evaluate_paired, make_trusted_lab_model_policy

SEED = 20261201
FAMILIES = (
    ("persistent_loss", "loss", "persistent"),
    ("persistent_paused_consumer", "consumer_paused", "persistent"),
    ("self_healing_delay", "delay", "self_healing"),
    ("self_healing_short_ttl", "loss", "self_healing"),
)
N_REPEATS = 3


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                          separators=(",", ":")).encode()).hexdigest()


def select_families(configurations):
    """Selection is based on registered fault class, never observed outcomes.

    The returned fault class is *administrative registration metadata*. It is
    never given to either the learned policy or transparent comparator.
    """
    chosen = []
    for title, fault, control in FAMILIES:
        candidates = [c for c in configurations if c["partition"] == "test"
                      and c["fault_mode"] == fault
                      and c.get("control_class") == control]
        if not candidates:
            raise ValueError("Missing registered test family: " + title)
        config = min(candidates, key=lambda c: c["configuration_id"])
        chosen.append((title, config))
    if len({c["configuration_id"] for _, c in chosen}) != len(FAMILIES):
        raise ValueError("Independent configuration IDs are not unique")
    return chosen


def admitted_rows(plan_dir: Path, record_dir: Path, *, seed: int = SEED):
    original_config, original_trials = create_plan(seed=seed, version="v3.1")
    configs, trials = load_plan(plan_dir)
    if digest([configs, trials]) != digest([original_config, original_trials]):
        raise ValueError("Source plan does not match frozen deterministic seed")
    chosen = select_families(configs)
    ids = {c["configuration_id"] for _, c in chosen}
    wanted = {t["run_id"]: t for t in trials if t["configuration_id"] in ids}
    if len(wanted) != len(FAMILIES) * N_REPEATS * len(ACTIONS):
        raise ValueError("Incomplete planned action arms")
    sources = {kind: _read_stream(record_dir / kind) for kind in
               ("pre_action", "verification", "operations", "oracle")}
    if any(set(stream) != set(wanted) for stream in sources.values()):
        raise ValueError("Missing/extra physical action stream or invalid run join")
    revisions, rows = set(), []
    by_episode = {}
    for run_id, t in sorted(wanted.items()):
        pre, verify, ops, oracle = (sources[kind][run_id] for kind in
                                  ("pre_action", "verification", "operations", "oracle"))
        for source in (pre, verify, ops, oracle):
            if any(source.get(key) != value for key, value in (
                ("run_id", run_id), ("configuration_id", t["configuration_id"]),
                ("repeat", t["repeat"]), ("action_id", t["action_id"]),
                ("partition", "test"), ("initial_state_seed", t["initial_state_seed"]),
                ("experiment_type", "real_kafka_multijvm_lab"),
            )):
                raise ValueError("Cross-stream action identity mismatch")
        source_commits = {source.get("source_commit") for source in
                          (pre, verify, ops, oracle)}
        if len(source_commits) != 1:
            raise ValueError("Conflicting source commit between physical evidence streams")
        revision = source_commits.pop()
        if (not isinstance(revision, str) or len(revision) != 40 or
                any(ch not in "0123456789abcdef" for ch in revision)):
            raise ValueError("Invalid measured source revision")
        revisions.add(revision)
        if pre.get("model_prediction_recorded") is not False or pre.get("oracle_features_excluded") is not True:
            raise ValueError("Unsealed model/ground-truth provenance")
        features = pre.get("features", {})
        if any(k in features for k in ("fault_mode", "fault_target",
                                       "event_delay_ms", "oracle_truth")):
            raise ValueError("Injected fault labels leaked into pre-action model features")
        observations = pre.get("operator_observations")
        nodes = {"enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden"}
        if (not isinstance(observations, list) or len(observations) != len(nodes)
                or {o.get("node") for o in observations if isinstance(o, dict)} != nodes
                or any(not isinstance(o, dict) or o.get("observed") is not True
                       or o.get("operator_schema") != "operator_pre_action_v2"
                       for o in observations)):
            raise ValueError("INCONCLUSIVE: missing real v2 pre-action operator measurements")
        policy = pre.get("decision_policy_metadata", {})
        if (type(policy.get("restart_permitted")) is not bool or
                type(policy.get("absolute_error_budget_requests")) is not int or
                policy["absolute_error_budget_requests"] <= 0):
            raise ValueError("Missing established authorization or budget")
        probes = pre.get("external_deny_observations")
        if not isinstance(probes, list) or not probes or any(
                p.get("http_status") not in (200, 403) for p in probes):
            raise ValueError("Invalid pre-action independent gateway probes")
        post = oracle.get("after", {})
        if (oracle.get("oracle_role") != "separate_process_admin_plus_direct_probe"
                or post.get("inventory_complete") is not True
                or post.get("direct_target_observations_complete") is not True
                or type(post.get("all_revoked_access_denied")) is not bool):
            raise ValueError("INCONCLUSIVE: incomplete independent security oracle")
        timeline = verify.get("timed_gateway_exposure", {})
        if (timeline.get("method") != "monotonic_http_step_integral" or
                timeline.get("valid_probe_count", 0) < 2 or
                not 0 <= timeline.get("exposure_fraction_lower_bound", -1)
                    <= timeline.get("exposure_fraction_upper_bound", -1) <= 1):
            raise ValueError("Invalid physical gateway exposure interval")
        attempts, failures = ops.get("observed_requests"), ops.get("failed_requests")
        if (type(attempts) is not int or attempts < 1 or
                type(failures) is not int or not 0 <= failures <= attempts):
            raise ValueError("Invalid measured legitimate request burden")
        if pre.get("routing_profile") not in ROUTING_PROFILES:
            raise ValueError("Invalid operator routing feature")
        measured = {
            "group": t["configuration_id"], "repeat": t["repeat"],
            "partition": "test", "action": t["action_id"],
            "restart_permitted": policy["restart_permitted"],
            "absolute_error_budget_requests": policy["absolute_error_budget_requests"],
            "pre_action": {
                **summarize_operator_telemetry(observations),
                "routing_profile": pre["routing_profile"],
                "cache_ttl_ms": features["cache_ttl_ms"],
                "requested_rps": features["requested_rps"],
                "gateway_visible_enforcer_count": features["visible_enforcement_processes"],
                "initial_gateway_allowed_fraction":
                    sum(p["http_status"] == 200 for p in probes) / len(probes),
            },
            "label_security_exposure": float(not post["all_revoked_access_denied"]),
            "label_path_exposure": float(timeline["exposure_fraction_upper_bound"]),
            "label_absolute_failed_requests": float(failures),
        }
        rows.append(measured)
        by_episode.setdefault((t["configuration_id"], t["repeat"]), set()).add(t["action_id"])
    if (len(revisions) != 1 or len(by_episode) != len(FAMILIES) * N_REPEATS or
            any(actions != set(ACTIONS) for actions in by_episode.values())):
        raise ValueError("Incomplete measured independent configuration pairing")
    return rows, {
        "plan_seed": seed,
        "registered_family_configurations": [
            {"family": title, "configuration_id": config["configuration_id"],
             "fault_class_for_posthoc_stratification_only":
                 [config["fault_mode"], config["control_class"]]}
            for title, config in chosen
        ],
        "source_commit": next(iter(revisions)),
        "plan_sha256": digest([configs, trials]),
        "four_stream_measured_records_sha256": digest(sources),
        "physical_action_arms": len(rows),
        "independent_configuration_groups": len(chosen),
        "test_outcomes_not_used_to_train_or_select_policy": True,
    }


def transparent_expert(context, eligible):
    """Predeclared illustrative engineering heuristic, NOT an oracle.

    Uses exactly the same summarized pre-action feature projection as the AI.
    These thresholds are fixed before new results and are not calibrated
    estimates or production authority to execute actions.
    """
    pre = context["pre_action"]
    if pre["operator_missing_count"] != 0:
        return None
    if pre["initial_gateway_allowed_fraction"] == 0:
        return "monitor_only"
    if (pre["cache_ttl_ms"] <= 4000 and
            pre["operator_pending_callback_count"] > 0):
        return "monitor_only"
    if ("restart_enforcer" in eligible and
            pre["requested_rps"] <= 30 and
            pre["operator_max_service_latency_ms"] <= 55):
        return "restart_enforcer"
    if "gateway_restrict" in eligible and pre["requested_rps"] <= 20:
        return "gateway_restrict"
    return "resync_policy"


def compile_report(rows, provenance, bundle, model_sha, training_report):
    measured_sha = provenance["four_stream_measured_records_sha256"]
    ai = evaluate_paired(rows, make_trusted_lab_model_policy(bundle),
                         model_fingerprint=model_sha, dataset_fingerprint=measured_sha)
    expert = evaluate_paired(rows, transparent_expert,
                             model_fingerprint=model_sha, dataset_fingerprint=measured_sha)
    gateway = evaluate_paired(rows, lambda _ctx, _eligible: "gateway_restrict",
                              model_fingerprint=model_sha, dataset_fingerprint=measured_sha)
    ai["policies"]["transparent_expert_heuristic"] = expert["policies"]["learned_policy"]
    ai["policies"]["fixed_gateway_restrict"] = gateway["policies"]["learned_policy"]
    for dest, cmp_expert, cmp_gateway in zip(ai["choices"], expert["choices"], gateway["choices"]):
        if (dest["configuration_id"], dest["repeat"]) != (cmp_expert["configuration_id"], cmp_expert["repeat"]):
            raise ValueError("Mismatch between offline policy cohorts")
        dest["selected_actions"]["transparent_expert_heuristic"] = cmp_expert["selected_actions"]["learned_policy"]
        dest["selected_actions"]["fixed_gateway_restrict"] = cmp_gateway["selected_actions"]["learned_policy"]
    ai["status"] = "EXPLORATORY_NEW_MULTIFAMILY_PHYSICAL_LAB_NOT_CONFIRMATORY"
    ai["new_measurement_provenance"] = provenance
    ai["execution_performed"] = False  # Analysis scorer did not execute actions
    ai["physical_actions_separately_executed"] = True
    ai["independent_configuration_groups"] = len(provenance["registered_family_configurations"])
    ai["configurations_selected_before_physical_outcomes"] = True
    ai["critical_infrastructure_effectiveness_established"] = False
    ai["prospective_superiority_established"] = False
    ai["historical_model_calibration"] = {
        label: {
            "heldout_configuration_group_coverage":
                training_report["metrics"][label]["heldout_configuration_group_coverage"],
            "nominal_coverage": training_report["metrics"][label]["nominal_coverage"],
        } for label in ("label_security_exposure", "label_path_exposure",
                        "label_absolute_failed_requests")
    }
    ai["calibration_security_shortfall"] = (
        ai["historical_model_calibration"]["label_security_exposure"]["heldout_configuration_group_coverage"]
        < ai["historical_model_calibration"]["label_security_exposure"]["nominal_coverage"])
    ai["limitations"] = [
        "Four independent new configurations but only one per fault family: no generalizable superiority inference",
        "AI proposals are evaluated offline against physically measured separate-action resets; no AI action dispatched",
        "Historical model calibration security coverage is inadequate for safety authorization if flagged",
        "Transparent comparator is a predeclared illustrative engineering heuristic, not certified expert judgment",
        "Restart-if-authorized baseline may exceed physical disruption limits; count actual breaches and direct resolutions separately",
        "A green Actions workflow proves execution completeness, not defensible AI superiority",
    ]
    return ai


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--historical-model", type=Path, required=True)
    parser.add_argument("--historical-model-sha256", required=True)
    parser.add_argument("--training-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite measured evidence report")
    rows, provenance = admitted_rows(args.plan, args.records)
    from model_adapter import load_local_bundle
    bundle = load_local_bundle(args.historical_model,
                               trusted_sha256=args.historical_model_sha256)
    training_report = json.loads(args.training_report.read_text())
    report = compile_report(rows, provenance, bundle, args.historical_model_sha256, training_report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("Measured physical action arms", provenance["physical_action_arms"])
    print("Registered independent configurations", provenance["registered_family_configurations"])
    print("Historical security-model coverage", report["historical_model_calibration"]["label_security_exposure"])
    print("AI abstention reasons:", report["abstention_reasons"])
    for policy, outcome in report["policies"].items():
        print(policy, "verified resolution", outcome["successful_replays"],
              "of", outcome["paired_replays"], "cost", round(outcome["mean_configuration_cost"], 6),
              "failed legitimate requests", outcome["failed_legitimate_requests"],
              "budget breaches", outcome["observed_disruption_budget_breaches"])
    print("Status:", report["status"])


if __name__ == "__main__":
    main()
