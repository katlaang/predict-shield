"""Post-hoc, read-only explanation of a frozen adaptive-defense failure.

The trained selector is not modified, and no action is executed. Every
counterfactual prediction is computed strictly from operator-observable
pre-action telemetry. Physical post-action labels are appended afterward,
ONLY for audit. This is retrospective analysis of an already opened test.

No proposed safety relaxation may be inferred from a favorable outcome.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from paired_defense_eval import ACTIONS, _eligible, _preaction, _finite, (
    make_trusted_lab_model_policy
)
from train import to_features


def inspect_frozen_proposal(bundle: dict, pre_action: dict, *,
                            restart_permitted: bool, disruption_budget: int) -> dict:
    """Reproduce model predictions and distinct policy/safety eligibility gates.

    Historical model uses real-valued regression of 0/1 residual exposure;
    predictions are not calibrated success probabilities. This is a
    diagnostic, not a production decision contract.
    """
    if type(restart_permitted) is not bool:
        raise ValueError("Unsigned restart permission")
    if type(disruption_budget) is not int or disruption_budget < 1:
        raise ValueError("Missing disruption budget")
    _preaction(pre_action)
    chooser = make_trusted_lab_model_policy(bundle)
    radii = bundle["radii"]
    models = bundle["models"]
    bounds = bundle["numeric_feature_bounds"]
    ood = any(name not in pre_action or not _finite(pre_action[name])
              or not _finite(lo) or not _finite(hi)
              or not lo <= pre_action[name] <= hi
              for name, (lo, hi) in bounds.items() if name != "routing_profile")
    eligible = _eligible(restart_permitted)
    proposals = {}
    for action in ACTIONS:
        vector = [to_features({"pre_action": pre_action, "action": action})]
        path = float(models["label_path_exposure"].predict(vector)[0])
        unresolved = float(models["label_security_exposure"].predict(vector)[0])
        failures = float(models["label_absolute_failed_requests"].predict(vector)[0])
        if not all(map(_finite, (path, unresolved, failures))):
            raise ValueError("Model returned nonfinite predictions")
        path = max(0.0, min(1.0, path))
        unresolved = max(0.0, min(1.0, unresolved))
        failures = max(0.0, failures)
        radius = float(radii["label_absolute_failed_requests"])
        allowed_by_policy = action in eligible
        allowed_by_uncertainty = (action == "monitor_only" or failures + radius <= disruption_budget)
        proposals[action] = {
            "predicted_path_exposure": path,
            "predicted_residual_security_exposure": unresolved,
            "predicted_failed_legitimate_requests": failures,
            "calibrated_absolute_error_radius_failed_requests": radius,
            "predicted_failure_upper_bound": failures + radius,
            "predicted_weighted_cost": 0.5 * path + 0.25 * unresolved + 0.25 * failures / disruption_budget,
            "permission_eligible": allowed_by_policy,
            "uncertainty_gate_eligible": allowed_by_uncertainty,
            "eligible_for_selector": allowed_by_policy and allowed_by_uncertainty and not ood,
            "gate_reason": (
                "OUT_OF_DISTRIBUTION" if ood else
                "PROHIBITED_BY_POLICY" if not allowed_by_policy else
                "DISRUPTION_UPPER_BOUND_EXCEEDS_BUDGET" if not allowed_by_uncertainty else
                "ELIGIBLE"
            ),
        }
    context = {
        "pre_action": dict(pre_action), "restart_permitted": restart_permitted,
        "absolute_error_budget_requests": disruption_budget,
    }
    selected = chooser(context, eligible)
    if selected is not None and not proposals[selected]["eligible_for_selector"]:
        raise ValueError("Selection contradicts model/policy gate")
    ranked_eligible = [a for a in ACTIONS if proposals[a]["eligible_for_selector"]]
    if selected is not None and selected != min(
            ranked_eligible, key=lambda a: (proposals[a]["predicted_weighted_cost"],
                                            ACTIONS.index(a))):
        raise ValueError("Selection does not match frozen model scoring")
    # The model is research-only. A predicted unresolved action is not
    # automatically interpreted as a successful remediation.
    unresolved = selected is not None and proposals[selected]["predicted_residual_security_exposure"] >= 0.5
    blocked_effective = [
        a for a, record in proposals.items()
        if record["permission_eligible"] and not record["uncertainty_gate_eligible"]
        and record["predicted_residual_security_exposure"] < 0.5
    ]
    return {
        "selected": selected, "options": proposals,
        "model_out_of_domain": ood,
        "selected_action_predicted_unresolved": unresolved,
        "potentially_effective_action_blocked_by_disruption_gate": blocked_effective,
        "requires_operator_escalation": bool(unresolved or blocked_effective or ood or selected is None),
        "automated_execution_permitted": False,
        "status": "RESEARCH_DIAGNOSTIC_POSTHOC_NOT_AUTHORIZATION",
    }


def heldout_calibration_audit(training_report: dict) -> dict:
    """Read frozen held-out coverage, no tuning on those results."""
    metrics = training_report.get("metrics", {})
    observed = {}
    failures = []
    for name in ("label_security_exposure", "label_path_exposure",
                 "label_absolute_failed_requests"):
        info = metrics.get(name)
        if not isinstance(info, dict):
            raise ValueError("Missing model reliability metric " + name)
        target = info.get("nominal_coverage")
        actual = info.get("heldout_configuration_group_coverage")
        if not _finite(target) or not _finite(actual) or not 0 < target <= 1 or not 0 <= actual <= 1:
            raise ValueError("Invalid measured coverage")
        valid = actual >= target
        if not valid:
            failures.append(name)
        observed[name] = {"nominal": target, "observed_group_coverage": actual,
                          "met_nominal_on_prior_heldout": valid,
                          "calibration_radius": info.get("conformal_absolute_error_radius")}
    return {
        "status": "PRIOR_HELDOUT_RELIABILITY_FAILURE" if failures else "PRIOR_HELDOUT_NO_COVERAGE_SHORTFALL_OBSERVED",
        "shortfall_labels": failures,
        "by_label": observed,
        "production_model_qualification": False,
        "notes": "Heldout performance is retrospective. It is NOT a valid development/calibration split for selecting revised models.",
    }


def audit_failed_physical_cohort(measured_rows: list[dict], bundle: dict,
                                 original_report: dict, training_report: dict,
                                 *, source_run: int = 45922944490) -> dict:
    from collections import defaultdict
    by_repeat = defaultdict(dict)
    for row in measured_rows:
        if row["partition"] != "test" or row["action"] not in ACTIONS:
            raise ValueError("Unexpected measured partition/action")
        key = (row["group"], row["repeat"])
        if row["action"] in by_repeat[key]:
            raise ValueError("Duplicate matched physical action")
        by_repeat[key][row["action"]] = row
    if not by_repeat or any(set(group) != set(ACTIONS) for group in by_repeat.values()):
        raise ValueError("Incomplete matched outcomes")
    choices = {(x["configuration_id"], x["repeat"]): x
               for x in original_report.get("choices", [])}
    if set(choices) != set(by_repeat):
        raise ValueError("Original frozen evaluation report pairing changed")
    audit = []
    for key in sorted(by_repeat):
        group = by_repeat[key]
        anchor = group["monitor_only"]
        # Predictions are complete BEFORE reading any recorded outcomes.
        diagnostic = inspect_frozen_proposal(
            bundle, dict(anchor["pre_action"]),
            restart_permitted=anchor["restart_permitted"],
            disruption_budget=anchor["absolute_error_budget_requests"],
        )
        selected = diagnostic["selected"] or "monitor_only"
        if choices[key]["selected_actions"]["learned_policy"] != selected:
            raise ValueError("Reproduced model selection differs from measured frozen report")
        # Outcome labels enter only this section. Never call chooser again.
        outcomes = {
            action: {
                "observed_residual_security_exposure": row["label_security_exposure"],
                "observed_path_exposure": row["label_path_exposure"],
                "observed_failed_legitimate_requests": row["label_absolute_failed_requests"],
                "observed_budget_breach": row["label_absolute_failed_requests"]
                                          > row["absolute_error_budget_requests"],
            } for action, row in group.items()
        }
        audit.append({
            "configuration": key[0], "repeat": key[1],
            "decision_explanation": diagnostic,
            "observed_counterfactual_matched_lab_outcomes": outcomes,
            "selected_security_resolved": outcomes[selected]["observed_residual_security_exposure"] == 0,
            "fixed_restart_security_resolved": outcomes["restart_enforcer"]["observed_residual_security_exposure"] == 0,
        })
    return {
        "schema": "predict-shield/posthoc-adaptive-defense-audit/1",
        "source_physical_run": source_run,
        "source_status": "FROZEN_PAST_TEST_ALREADY_EXAMINED",
        "model_training_report": heldout_calibration_audit(training_report),
        "paired_episodes": len(audit),
        "per_episode": audit,
        "repeat_selection_mismatch": 0,
        "new_test_performed": False,
        "future_model_qualified_for_autonomous_actions": False,
        "proves_AI_superiority": False,
    }


def main():
    from model_adapter import load_local_bundle
    from new_configuration_pilot import load_new_paired
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--training-report", type=Path, required=True)
    parser.add_argument("--frozen-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Refuse overwrite of any existing diagnosis")
    bundle = load_local_bundle(args.model, trusted_sha256=args.model_sha256)
    rows, _ = load_new_paired(args.plan, args.records)
    frozen = json.loads(args.frozen_result.read_text())
    prior = json.loads(args.training_report.read_text())
    out = audit_failed_physical_cohort(rows, bundle, frozen, prior)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print("Posthoc failed-defense diagnosis; no autonomous actions:", args.output)
    for entry in out["per_episode"]:
        d = entry["decision_explanation"]
        print("repeat", entry["repeat"], "selected", d["selected"],
              "blocked_effective", d["potentially_effective_action_blocked_by_disruption_gate"],
              "requires_operator_escalation", d["requires_operator_escalation"])
        for name, pred in d["options"].items():
            print(name, "predicted_cost", round(pred["predicted_weighted_cost"],5),
                  "pred_security_residual", round(pred["predicted_residual_security_exposure"],5),
                  "pred_failure_upper", round(pred["predicted_failure_upper_bound"],5),
                  "reason", pred["gate_reason"],
                  "observed_success", entry["observed_counterfactual_matched_lab_outcomes"][name]["observed_residual_security_exposure"]==0)
    print("Model heldout status",out["model_training_report"]["status"])


if __name__ == "__main__":
    main()
