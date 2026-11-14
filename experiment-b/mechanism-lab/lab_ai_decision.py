"""Integrate a trained local model with bounded lab scope and policy selection.

This runner never executes actions and never reads post-action oracle labels.
Actual model bundles must be verified against an independently trusted digest.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from predict_shield.ai_contracts import ActionTier, CandidateAction
from predict_shield.lab_scope_evidence import collect_live_scope
from predict_shield.selector import select_action
from model_adapter import load_local_bundle, predictions_from_bundle

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")


def select_lab_defense(bundle, pre_action, snapshot, *, remaining_budget: float,
                       restart_permitted: bool, disruption_weight: float = 0.5):
    """Make real trained-model predictions before applying independent lab policy."""
    if type(restart_permitted) is not bool or not 0 < remaining_budget < 100000:
        raise ValueError("Lab budget and restart authorization must be explicit")
    candidates = tuple(CandidateAction(
        action_id=name,
        tier=ActionTier.AUTOMATIC if (name != "restart_enforcer" or restart_permitted)
             else ActionTier.PROHIBITED,
        affected_services=("authorization",),
        postcondition="Revoked operation denied at all in-scope lab enforcers",
        reversible=name != "monitor_only",
    ) for name in ACTIONS)
    # Retain experimental injection metadata only in offline research records;\n    # the model request receives a pre-action, operator-observable projection.\n    # Oracle or post-action fields must fail in the predictor, never be stripped.\n    inference_input = {k: v for k, v in pre_action.items() if k != "experimental_conditions"}\n    predictions = predictions_from_bundle(bundle, inference_input, snapshot, candidates)
    result = select_action(snapshot, candidates, predictions,
                           {"authorization": remaining_budget},
                           disruption_weight=disruption_weight)
    return {
        "schema": "predict-shield/lab-ai-defense-recommendation/1",
        "case_id": snapshot.case_id,
        "snapshot_id": snapshot.snapshot_id,
        "model_fingerprint": bundle.get("training_fingerprint"),
        "model_name": predictions[0].model_name,
        "selected_action": result.selected.action_id if result.selected else None,
        "abstained": result.abstained,
        "reason": result.reason,
        "candidate_actions": [a.action_id for a in candidates],
        "screened": {a: {"decision": g.decision.value, "reason": g.reason}
                     for a, g in result.screened.items()},
        "scores": [{"action": p.action_id, "score": p.score,
                    "residual_risk": p.estimated_residual_risk,
                    "normalized_disruption": p.normalized_service_disruption}
                   for p in result.eligible],
        "budget_source": "explicitly-supplied-lab-experimental-limit-not-verified-production-budget",
        "action_executed": False,
        "independently_verified_post_action": False,
        "research_lab_only": True,
    }


def main():
    p = argparse.ArgumentParser(description="Read-only live-scope calibrated-model lab decision")
    p.add_argument("--project", required=True)
    p.add_argument("--pre-action", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--trusted-model-sha256", required=True)
    p.add_argument("--remaining-lab-budget", required=True, type=float)
    p.add_argument("--restart-permitted", action="store_true")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error("Refusing to overwrite an earlier decision")
    pre_action = json.loads(args.pre_action.read_text())
    if not pre_action.get("run_id"):
        raise ValueError("Missing run identifier")
    snapshot, scope, discovery = collect_live_scope(
        project=args.project,
        token=os.environ.get("LAB_CONTROL_TOKEN", ""),
        case_id=pre_action["run_id"])
    bundle = load_local_bundle(args.model, trusted_sha256=args.trusted_model_sha256)
    result = select_lab_defense(bundle, pre_action, snapshot,
        remaining_budget=args.remaining_lab_budget,
        restart_permitted=args.restart_permitted)
    result["scope_assessment"] = scope
    result["discovery_digest"] = discovery["sha256"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Learned model recommendation:", result["selected_action"] or "ABSTAIN",
          "action dispatched: false")


if __name__ == "__main__":
    main()
