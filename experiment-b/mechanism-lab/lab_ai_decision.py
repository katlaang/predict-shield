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
from defense_review_v2 import review_recommendation

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")


def select_lab_defense(bundle, pre_action, snapshot, *, remaining_budget: float,
                       restart_permitted: bool, disruption_weight: float = 0.5,
                       model_evaluation: dict | None = None):
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
    # Retain experimental injection metadata only in offline lab records;
    # the model request receives a pre-action, operator-observable projection.
    # Oracle or post-action fields must fail in the predictor, never be stripped.
    inference_input = {k: v for k, v in pre_action.items() if k != "experimental_conditions"}
    predictions = predictions_from_bundle(bundle, inference_input, snapshot, candidates)
    result = select_action(snapshot, candidates, predictions,
                           {"authorization": remaining_budget},
                           disruption_weight=disruption_weight)
    proposed = result.selected.action_id if result.selected else None
    # A model ranking is not permission to claim or execute a remediation.
    # Only evidence from authenticated, fresh pre-action health reports and a
    # separately fingerprint-verified evaluation can pass this second gate.
    evidence_review = review_recommendation(
        pre_action=pre_action, selected_action=proposed, predictions=predictions,
        eligible_actions=tuple(a.action_id for a in candidates
                               if a.tier != ActionTier.PROHIBITED),
        bundle=bundle, model_evaluation=model_evaluation,
        remaining_budget=remaining_budget)
    needs_review = evidence_review["requires_human_review"]
    return {
        "schema": "predict-shield/lab-ai-defense-recommendation/1",
        "case_id": snapshot.case_id,
        "snapshot_id": snapshot.snapshot_id,
        "model_fingerprint": bundle.get("training_fingerprint"),
        "model_name": predictions[0].model_name,
        "selected_action": None if needs_review else proposed,
        "model_proposed_action": proposed,
        "abstained": bool(result.abstained or needs_review),
        "reason": "HUMAN_REVIEW_REQUIRED_EVIDENCE_OR_EFFECTIVENESS" if needs_review else result.reason,
        "decision_review": evidence_review,
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
        "lab_only": True,
    }


def main():
    p = argparse.ArgumentParser(description="Read-only live-scope calibrated-model lab decision")
    p.add_argument("--project", required=True)
    p.add_argument("--pre-action", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--trusted-model-sha256", required=True)
    p.add_argument("--model-evaluation-report", type=Path,
                   help="Optional independently trusted source-pinned model reliability report")
    p.add_argument("--trusted-evaluation-sha256",
                   help="Expected SHA-256 from trusted independent evidence manifest")
    p.add_argument("--remaining-lab-budget", required=True, type=float)
    p.add_argument("--restart-permitted", action="store_true")
    p.add_argument("--execute-lab", action="store_true", help="Opt in to allowlisted disposable lab actions only")
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
    evaluation = None
    if args.model_evaluation_report is not None:
        import hashlib
        if not args.trusted_evaluation_sha256 or args.model_evaluation_report.is_symlink():
            raise ValueError("Explicit independent evaluation hash and regular file required")
        data = args.model_evaluation_report.read_bytes()
        if hashlib.sha256(data).hexdigest() != args.trusted_evaluation_sha256:
            raise ValueError("Independent reliability report checksum mismatch")
        evaluation = json.loads(data)
    result = select_lab_defense(bundle, pre_action, snapshot,
        remaining_budget=args.remaining_lab_budget,
        restart_permitted=args.restart_permitted, model_evaluation=evaluation)
    result["scope_assessment"] = scope
    result["discovery_digest"] = discovery["sha256"]
    if args.execute_lab:
        from lab_autonomous_execution import execute_lab_recommendation
        result["execution"] = execute_lab_recommendation(
            result, scope_assessment=scope,
            control_token=os.environ.get("LAB_CONTROL_TOKEN", ""),
            oracle_token=os.environ.get("LAB_ORACLE_TOKEN", ""))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Learned model recommendation:", result["selected_action"] or "ABSTAIN",
          "action dispatched:", bool(result.get("execution", {}).get("action_executed", False)))


if __name__ == "__main__":
    main()
