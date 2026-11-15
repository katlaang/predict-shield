"""Bind an eligible AI vulnerability case to the EXISTING JVM/Kafka lab executor.

This is a narrow research bridge, not a second actuator. It independently
refreshes bounded lab scope and learned-action policy immediately before
dispatch. The independent oracle verifies authorization policy only, NEVER
a matched CVE's remediation. A lab result cannot establish production safety.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from predict_shield.ai_contracts import EvidenceSnapshot
from predict_shield.assessment import Evidence, Outcome, assess
from predict_shield.pipeline import record_independent_outcome

_ALLOWED_PROJECTS = {"psunified", "psailab"}
_ALLOWED_MUTATIONS = {"resync_policy", "gateway_restrict"}


def execute_bound_lab_case(plan: dict, *, project: str, model_bundle: dict,
                           pre_action: dict, control_token: str,
                           oracle_token: str, remaining_lab_budget: float,
                           applicability_observations: tuple[Evidence, ...],
                           now: datetime | None = None,
                           scope_collector: Callable | None = None,
                           lab_selector: Callable | None = None,
                           lab_executor: Callable | None = None,
                           post_oracle_reader: Callable | None = None,
                           post_gateway_reader: Callable | None = None) -> dict:
    """Recheck all authority and trust bindings on a fixed disposable lab.

    Dependency injection exists exclusively for contract tests. The default
    production path calls real current-state lab collectors and existing
    selector/executor. Never trust a saved plan as an authorization token.
    """
    if project not in _ALLOWED_PROJECTS:
        raise ValueError("Only explicitly disposable project identifiers permitted")
    if (not isinstance(control_token, str) or len(control_token) < 24
            or not isinstance(oracle_token, str) or len(oracle_token) < 24
            or control_token == oracle_token):
        raise ValueError("Distinct disposable lab control and oracle tokens required")
    if (not isinstance(plan, dict) or plan.get("schema") != "predict-shield/unified-ai-case-plan/1"
            or plan.get("selection_status") != "ELIGIBLE_RESEARCH_LAB_PLAN"
            or plan.get("dispatch_authorized") is not False
            or plan.get("independent_verification") != "NOT_EVALUATED"):
        raise ValueError("No unexecuted independently screened case plan")
    action = plan.get("selected_action")
    if action not in _ALLOWED_MUTATIONS:
        raise ValueError("Selected action not eligible for limited lab bridge")
    proposals = plan.get("ai_proposals")
    if (not isinstance(proposals, list) or len(proposals) != 1
            or proposals[0].get("action_id") != action
            or proposals[0].get("status") != "MODEL_PROPOSAL_UNVERIFIED"
            or proposals[0].get("execution_authorized") is not False):
        raise ValueError("AI output must remain an untrusted single proposal")
    if plan.get("applicability") != "VERIFIED" or not plan.get("applicability_evidence_sources"):
        raise ValueError("No independent vulnerability applicability finding")
    if (not isinstance(pre_action, dict) or pre_action.get("run_id") != plan.get("case_id")
            or pre_action.get("oracle_features_excluded") is not True
            or pre_action.get("experiment_type") != "real_kafka_multijvm_lab"):
        raise ValueError("Model input and case scope mismatch")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    try:
        planned_at = datetime.fromisoformat(plan["created_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Missing case creation time") from exc
    if planned_at.tzinfo is None or not 0 <= (now - planned_at).total_seconds() <= 300:
        raise ValueError("Stale or future lab case")
    if (not isinstance(remaining_lab_budget, (float, int))
            or isinstance(remaining_lab_budget, bool)
            or not 0 < remaining_lab_budget <= 100):
        raise ValueError("Explicit bounded experimental service budget required")

    # Reassess applicability: never accept the report's VERIFIED text alone.
    proposal = proposals[0]
    assertion = "cve-applicable:" + proposal["cve"] + ":" + proposal["purl"]
    applicability = assess(proposal["asset_id"], assertion,
                           list(applicability_observations), now=now,
                           max_age_seconds=300)
    if applicability.outcome is not Outcome.VERIFIED:
        raise ValueError("Fresh independent CVE applicability observation missing")
    if not set(applicability.evidence_sources).intersection(
            plan["applicability_evidence_sources"]):
        raise ValueError("Applicability evidence source changed after planning")

    if scope_collector is None:
        from predict_shield.lab_scope_evidence import collect_live_scope
        scope_collector = collect_live_scope
    if lab_selector is None:
        from lab_ai_decision import select_lab_defense
        lab_selector = select_lab_defense
    if lab_executor is None:
        from lab_autonomous_execution import execute_lab_recommendation
        lab_executor = execute_lab_recommendation
    if post_oracle_reader is None:
        from pilot import oracle_snapshot
        post_oracle_reader = oracle_snapshot
    if post_gateway_reader is None:
        from pilot import gateway_probes
        post_gateway_reader = lambda: gateway_probes(24)

    snapshot, scope, inventory = scope_collector(
        project=project, token=control_token, case_id=plan["case_id"])
    if (not isinstance(snapshot, EvidenceSnapshot) or
            not snapshot.trusted or not snapshot.scope_complete or
            snapshot.case_id != plan["case_id"] or
            snapshot.snapshot_id != plan.get("scope_snapshot_id") or
            not 0 <= (now - snapshot.captured_at).total_seconds() <= 300 or
            scope.get("status") != "LAB_SCOPE_SUPPORTED" or
            scope.get("production_scope_attested") is not False):
        raise ValueError("Current independently observed lab scope does not match the case")
    if (not isinstance(inventory, dict) or
            inventory.get("sha256") != snapshot.snapshot_id.removeprefix("lab-scope:")):
        raise ValueError("Live inventory is not bound to scoped lab evidence")
    if not plan.get("discovery_sha256"):
        raise ValueError("No initial asset discovery provenance recorded")
    recommendation = lab_selector(model_bundle, pre_action, snapshot,
                                  remaining_budget=remaining_lab_budget,
                                  restart_permitted=False)
    screened = recommendation.get("screened", {}).get(action, {})
    if (recommendation.get("research_lab_only") is not True or
            recommendation.get("action_executed") is not False or
            recommendation.get("abstained") is not False or
            recommendation.get("selected_action") != action or
            recommendation.get("case_id") != plan["case_id"] or
            recommendation.get("snapshot_id") != snapshot.snapshot_id or
            screened.get("decision") != "ELIGIBLE_AUTOMATIC" or
            recommendation.get("model_fingerprint") !=
            plan.get("selected_action_model_fingerprint")):
        raise ValueError("Fresh trained prediction or policy selection does not match plan")
    if (not isinstance(model_bundle, dict) or model_bundle.get("training_fingerprint")
            != recommendation.get("model_fingerprint")):
        raise ValueError("Trusted model fingerprint mismatch")
    # The only mutation path is the existing allowlisted JVM/Kafka lab executor.
    receipt = lab_executor(recommendation, scope_assessment=scope,
                           control_token=control_token, oracle_token=oracle_token)
    if (not isinstance(receipt, dict) or
            receipt.get("schema") != "predict-shield/lab-execution-record/1" or
            receipt.get("lab_only") is not True or
            receipt.get("selected_action") != action):
        raise ValueError("Unexpected lab execution receipt")
    # Re-observe independently after action. No HTTP acknowledgment or saved
    # executor claim is used as proof of authorization control correctness.
    oracle = post_oracle_reader(oracle_token)
    gateway = post_gateway_reader()
    if not isinstance(oracle, dict) or not isinstance(gateway, list):
        raise ValueError("Missing independent post-action observations")
    complete = (oracle.get("inventory_complete") is True and
                oracle.get("direct_target_observations_complete") is True and
                len(gateway) >= 3 and
                all(isinstance(p, dict) and p.get("http_status") in (200, 403)
                    for p in gateway))
    deny = oracle.get("all_revoked_access_denied")
    if not complete or type(deny) is not bool:
        verdict = "INDETERMINATE"
    elif deny and all(p["http_status"] == 403 for p in gateway):
        verdict = "VERIFIED_LAB_ONLY"
    else:
        verdict = "NOT_VERIFIED_LAB_ONLY"
    # The control is an authorization consistency test, NOT a CVE patch.
    # The generic vulnerability outcome deliberately remains INDETERMINATE.
    general = record_independent_outcome(plan, receipt, (), now=now)
    return {
        "schema": "predict-shield/unified-lab-case-bridge/1",
        "case_id": plan["case_id"],
        "selected_action": action,
        "live_lab_scope_id": snapshot.snapshot_id,
        "fresh_learned_model_fingerprint": recommendation["model_fingerprint"],
        "authorization_control_outcome": verdict,
        "gateway_post_action_probe_count": len(gateway),
        "vulnerability_remediation_outcome": general["verification_status"],
        "vulnerability_remediation_verified": False,
        "action_executed": receipt.get("action_executed") is True,
        "independent_oracle_requeried": True,
        "unmeasured_service_continuity": "UNKNOWN",
        "external_critical_infrastructure_validated": False,
        "research_lab_only": True,
    }
