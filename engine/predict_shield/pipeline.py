"""One evidence-driven case pipeline using the existing PREDICT-SHIELD components.

Local model -> constrained proposal -> independent applicability and scope
evidence -> existing learned-action predictions and policy selector ->
separate execution receipt -> existing independent verifier.

No new execution engine; unknown evidence always abstains. Model text and
executor acknowledgments cannot certify a vulnerability or successful fix.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .assessment import Evidence, Outcome, assess
from .ai_contracts import ActionPrediction, CandidateAction, EvidenceSnapshot
from .asset_risk_context import contextualize
from .dependency_graph import build_dependency_graph, reachable_service_dependents
from .local_ai import prepare_request, validate_proposals
from .risk_evidence import assess_risk_evidence, verify_digest
from .sast_findings import RegisteredScanner, ScanFinding, confirm_before_fix
from .script_integrity import (
    RegisteredScript,
    RegisteredSite,
    ScriptObservation,
    confirm_hash_matches_trusted,
    confirm_no_unregistered_domain,
)
from .script_risk_proposer import ScriptRiskProposer
from .selector import select_action


def _serialize_screened(screened):
    return {action:{"decision":result.decision.value,"reason":result.reason}
            for action,result in screened.items()}


def plan_case(*, case_id: str, discovery: dict, advisories: list[dict],
              local_model, actions: tuple[CandidateAction,...],
              verification_check_ids: tuple[str,...],
              predictions: tuple[ActionPrediction,...]=(),
              scope_snapshot: EvidenceSnapshot | None=None,
              finding_evidence: tuple[Evidence,...]=(),
              remaining_error_budgets: dict[str,float] | None=None,
              service_dependencies: list[dict] | None=None,
              now: datetime | None=None) -> dict:
    if not case_id or not actions or len({a.action_id for a in actions})!=len(actions):
        raise ValueError("Case and distinct approved action catalog required")
    if now is None:
        now=datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Current timestamp must be timezone-aware")
    if not verify_digest(discovery):
        raise ValueError("Untrusted or altered discovery report")
    graph=build_dependency_graph(discovery,service_dependencies=service_dependencies)
    context=contextualize(discovery,advisories)
    risk=assess_risk_evidence(context,case_id=case_id,timestamp=now)
    model_request=prepare_request(context,advisories,
                   action_ids=tuple(a.action_id for a in actions),
                   verification_check_ids=verification_check_ids)
    raw=local_model(model_request)
    proposed=validate_proposals(raw,model_request)
    model_name=getattr(local_model,"model_id",None)
    model_fp=getattr(local_model,"model_fingerprint",None)
    report={
        "schema":"predict-shield/unified-ai-case-plan/1",
        "case_id":case_id,
        "created_at":now.isoformat(),
        "discovery_sha256":discovery["sha256"],
        "context_sha256":context["sha256"],
        "dependency_graph_sha256":graph["sha256"],
        "dependency_graph":graph,
        "risk_evidence_reasons":list(risk.reason_codes),
        "advisory_candidate_count":risk.candidate_cve_count,
        "ai_proposals":list(proposed),
        "local_ai_model":model_name,
        "local_ai_fingerprint":model_fp,
        "scope_snapshot_id":None,
        "selected_action_model_fingerprint":None,
        "applicability":"UNVERIFIED",
        "selection_status":"ESCALATE_FOR_EVIDENCE",
        "selected_action":None,
        "policy_screened":{},
        "dispatch_authorized":False,
        "independent_verification":"NOT_EVALUATED",
        "reason":"No model proposal or verified finding and independently bound scope",
        "lab_execution_adapter":"existing mechanism-lab implementation; not invoked",
    }
    if not proposed:
        return report
    # Require a unique, unambiguous proposal before authorizing consideration.
    if len(proposed)!=1:
        report["reason"]="Multiple model findings require independent case triage"
        return report
    item=proposed[0]
    if not isinstance(scope_snapshot,EvidenceSnapshot) or scope_snapshot.case_id!=case_id:
        report["reason"]="No case-bound independent scope snapshot"
        return report
    if not scope_snapshot.trusted or not scope_snapshot.scope_complete:
        report["reason"]="Independent scope evidence is incomplete or untrusted"
        return report
    if scope_snapshot.captured_at>now:
        report["reason"]="Scope observation is from the future"
        return report
    if "discovery:"+discovery["sha256"] not in scope_snapshot.source_ids:
        report["reason"]="Scope snapshot is not bound to this exact discovery report"
        return report
    if not finding_evidence:
        report["reason"]="No independent vulnerability applicability observation"
        return report
    assertion="cve-applicable:"+item["cve"]+":"+item["purl"]
    applicability=assess(item["asset_id"],assertion,list(finding_evidence),
                         required_independent_checks=1,max_age_seconds=3600,now=now)
    report["applicability"]=applicability.outcome.value
    report["applicability_evidence_sources"]=list(applicability.evidence_sources)
    if applicability.outcome is not Outcome.VERIFIED:
        report["reason"]="Independent CVE applicability not verified: "+applicability.reason
        return report
    selected_action=next(a for a in actions if a.action_id==item["action_id"])
    # The proposal merely narrows the action catalog. The calibrated learned
    # effect estimator and independent selector remain mandatory.
    screened=select_action(scope_snapshot,(selected_action,),predictions,
                           dict(remaining_error_budgets or {}))
    report["policy_screened"]=_serialize_screened(screened.screened)
    if screened.abstained or screened.selected is None:
        report["reason"]="Existing independent action gate abstained: "+screened.reason
        return report
    report["selection_status"]="ELIGIBLE_LAB_PLAN"
    report["scope_snapshot_id"]=scope_snapshot.snapshot_id
    report["selected_action_model_fingerprint"]=next(p.training_fingerprint for p in predictions if p.action_id==screened.selected.action_id)
    report["selected_action"]=screened.selected.action_id
    report["selection_score"]=screened.selected.score
    report["proposed_verification_check_ids"]=item["verification_check_ids"]
    report["reason"]="AI proposal matched independent applicability, scope and policy gate"
    # No execution token and no authority is included in a planning record.
    return report


def plan_sast_case(*, case_id: str, finding: ScanFinding,
                   scanner_registry: dict[str, RegisteredScanner],
                   rule_to_action: dict[str, str],
                   actions: tuple[CandidateAction, ...],
                   predictions: tuple[ActionPrediction, ...] = (),
                   scope_snapshot: EvidenceSnapshot | None = None,
                   remaining_error_budgets: dict[str, float] | None = None,
                   now: datetime | None = None) -> dict:
    """Propose and policy-gate a remediation for a source-code finding, the
    SAST-finding counterpart to `plan_case`'s CVE/advisory flow -- source-
    code findings were previously only ever verified post-fix
    (`sast_findings.evaluate_fix`, exercised only by
    `experiment-b/real-sast-pilot`), never proposed or gated through this
    pipeline's propose-then-gate stage the way a CVE already is.

    Deliberately no AI reading of advisory-style text here: a SAST
    finding's `rule_id` already deterministically names what kind of defect
    it is, so the remediation action it maps to is something the operator
    registers ahead of time (`rule_to_action`), the same "registered, never
    guessed by a model" discipline the action catalog itself already
    follows for `plan_case` too -- not something asked of a language model,
    which would just reintroduce the untrusted-text-parsing risk this
    pipeline screens advisory text for elsewhere.

    Whether the finding is genuinely present is re-derived here via
    `sast_findings.confirm_before_fix()` against the scanner registry this
    function is given, independently of whatever the caller's `finding.present`
    claims -- the same "don't trust the caller's claim, re-check it" rule
    `plan_case` applies to CVE applicability.

    Like `plan_case`, this stops at propose -> gate: it returns an eligible
    plan and never applies anything, and it does not call
    `sast_findings.evaluate_fix()` -- that stays a separate, independent,
    post-action verification step, exactly as `remediation_verification.py`'s
    composite is never called from `plan_case` either.
    """
    if not case_id or not actions or len({a.action_id for a in actions}) != len(actions):
        raise ValueError("Case and distinct approved action catalog required")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Current timestamp must be timezone-aware")
    report: dict = {
        "schema": "predict-shield/sast-case-plan/1",
        "case_id": case_id,
        "created_at": now.isoformat(),
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "finding_key": finding.key,
        "scope_snapshot_id": None,
        "selected_action_model_fingerprint": None,
        "confirmed_present": "NOT_EVALUATED",
        "selection_status": "ESCALATE_FOR_EVIDENCE",
        "selected_action": None,
        "policy_screened": {},
        "dispatch_authorized": False,
        "reason": "No confirmed finding or independently bound scope",
        "lab_execution_adapter": "existing mechanism-lab implementation; not invoked",
    }
    try:
        confirmation = confirm_before_fix(finding, scanner_registry, now=now)
    except ValueError as exc:
        report["reason"] = "Finding could not be confirmed: " + str(exc)
        return report
    confirmed = assess(confirmation.asset, confirmation.assertion, [confirmation], now=now)
    report["confirmed_present"] = confirmed.outcome.value
    if confirmed.outcome is not Outcome.VERIFIED:
        report["reason"] = "Independent finding confirmation not verified: " + confirmed.reason
        return report

    action_id = rule_to_action.get(finding.rule_id)
    if action_id is None:
        report["reason"] = f"No registered remediation action for rule {finding.rule_id!r}"
        return report
    selected_action = next((a for a in actions if a.action_id == action_id), None)
    if selected_action is None:
        report["reason"] = f"Registered action {action_id!r} is not in the approved catalog"
        return report

    if not isinstance(scope_snapshot, EvidenceSnapshot) or scope_snapshot.case_id != case_id:
        report["reason"] = "No case-bound independent scope snapshot"
        return report
    if not scope_snapshot.trusted or not scope_snapshot.scope_complete:
        report["reason"] = "Independent scope evidence is incomplete or untrusted"
        return report
    if scope_snapshot.captured_at > now:
        report["reason"] = "Scope observation is from the future"
        return report
    if "sast-finding:" + finding.finding_id not in scope_snapshot.source_ids:
        report["reason"] = "Scope snapshot is not bound to this exact finding"
        return report

    screened = select_action(scope_snapshot, (selected_action,), predictions,
                             dict(remaining_error_budgets or {}))
    report["policy_screened"] = _serialize_screened(screened.screened)
    if screened.abstained or screened.selected is None:
        report["reason"] = "Existing independent action gate abstained: " + screened.reason
        return report
    report["selection_status"] = "ELIGIBLE_LAB_PLAN"
    report["scope_snapshot_id"] = scope_snapshot.snapshot_id
    report["selected_action_model_fingerprint"] = next(
        (p.training_fingerprint for p in predictions if p.action_id == screened.selected.action_id), None)
    report["selected_action"] = screened.selected.action_id
    report["selection_score"] = screened.selected.score
    report["reason"] = "Confirmed finding matched a registered remediation action and policy gate"
    # No execution token and no authority is included in a planning record.
    return report


def plan_script_integrity_case(
    *, case_id: str, script: RegisteredScript, site: RegisteredSite,
    observation: ScriptObservation, observed_domains: tuple[str, ...], observed_at: datetime,
    proposer: ScriptRiskProposer, permitted_actions_by_reason: dict[str, tuple[str, ...]],
    actions: tuple[CandidateAction, ...], predictions: tuple[ActionPrediction, ...] = (),
    scope_snapshot: EvidenceSnapshot | None = None,
    remaining_error_budgets: dict[str, float] | None = None,
    asset_criticality: str | None = None,
    detection_notes: tuple[str, ...] = (),
    now: datetime | None = None,
) -> dict:
    """Propose and policy-gate a containment action for a third-party
    script integrity finding -- the script-integrity counterpart to
    `plan_sast_case`'s source-code-finding flow.

    Unlike `plan_sast_case`, the mapping from a confirmed finding to a
    containment action is not a single deterministic lookup: more than
    one registered containment action (block via CSP, revoke an SRI
    pin, disable the embed) can be appropriate depending on the kind of
    violation and the asset's context, which is exactly the judgment
    call Chapter 2's AI proposal step exists for elsewhere in this
    pipeline. `proposer` (an instance of `ScriptRiskProposer`) chooses
    among `permitted_actions_by_reason[reason]` -- an operator-registered
    set, never an open-ended catalog the model could expand -- and its
    reply is re-validated against that exact set before the deterministic
    gate runs, the same order of control `action_proposer.py` already
    uses for the CVE path.

    Whether the finding is genuinely present is re-derived here via
    `script_integrity.confirm_hash_matches_trusted` and
    `confirm_no_unregistered_domain`, independently of any upstream
    claim, the same "don't trust the caller's claim, re-check it" rule
    `plan_case` and `plan_sast_case` both already apply.

    The model also returns its own severity assessment, correlating the
    evidence with `asset_criticality` and any registered
    `detection_notes` (free text from a registered detection source,
    screened for injection patterns before it reaches the model). That
    severity is recorded in the plan as advisory only: the approval tier
    comes from the registered action in the catalog, so a model that
    rates a finding "low" cannot move an approval-tier action into
    automatic eligibility.

    Like both of those, this stops at propose -> gate: it returns an
    eligible plan and never applies a containment action, and it does
    not call `script_integrity.evaluate()` -- that stays a separate,
    independent, post-action verification step that also requires the
    real behavioral browser check (`confirm_no_prohibited_network_behavior`),
    which this planning stage has no evidence for yet (there is nothing
    to verify post-action before an action has been taken).
    """
    if not case_id or not actions or len({a.action_id for a in actions}) != len(actions):
        raise ValueError("Case and distinct approved action catalog required")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Current timestamp must be timezone-aware")
    report: dict = {
        "schema": "predict-shield/script-integrity-case-plan/1",
        "case_id": case_id,
        "created_at": now.isoformat(),
        "script_id": script.script_id,
        "site_id": site.site_id,
        "scope_snapshot_id": None,
        "selected_action_model_fingerprint": None,
        "finding_confirmed": "NOT_EVALUATED",
        "finding_reason": None,
        "selection_status": "ESCALATE_FOR_EVIDENCE",
        "selected_action": None,
        "ai_proposal_status": None,
        "ai_proposal_rationale": None,
        "ai_severity_advisory": None,
        "ai_injection_suspected": False,
        "policy_screened": {},
        "dispatch_authorized": False,
        "reason": "No confirmed finding or independently bound scope",
        "lab_execution_adapter": "existing mechanism-lab implementation; not invoked",
    }

    # Independently re-derive whether a finding exists; never trust a
    # caller's claim about it.
    hash_evidence = confirm_hash_matches_trusted(script, observation, now=now)
    domain_evidence = confirm_no_unregistered_domain(site, observed_domains, observed_at, now=now)
    hash_ok = assess(hash_evidence.asset, hash_evidence.assertion, [hash_evidence], now=now)
    domain_ok = assess(domain_evidence.asset, domain_evidence.assertion, [domain_evidence], now=now)

    reason = None
    if hash_ok.outcome is not Outcome.VERIFIED:
        reason = "hash_mismatch"
    elif domain_ok.outcome is not Outcome.VERIFIED:
        reason = "unregistered_domain"
    report["finding_confirmed"] = "VERIFIED" if reason else "NOT_VERIFIED"
    report["finding_reason"] = reason
    if reason is None:
        report["reason"] = "No independently confirmed script-integrity finding"
        return report

    offered = list(permitted_actions_by_reason.get(reason, ()))
    if not offered:
        report["reason"] = f"No registered containment action set for finding reason {reason!r}"
        return report

    context = {
        "case_id": case_id,
        "finding_reason": reason,
        "script_id": script.script_id,
        "observed_sha384": observation.sha384,
        "trusted_sha384_count": len(script.trusted_sha384),
        "observed_domains": sorted(observed_domains),
        "allowed_domains": sorted(site.allowed_script_domains),
        "asset_criticality": asset_criticality,
        "detection_notes": list(detection_notes),
    }
    proposal = proposer.propose(context, offered)
    report["ai_proposal_status"] = proposal.status
    report["ai_proposal_rationale"] = proposal.rationale
    report["ai_severity_advisory"] = proposal.severity
    report["ai_injection_suspected"] = proposal.injection_suspected
    if proposal.status != "ACCEPTED" or proposal.action_id not in offered:
        report["reason"] = "AI containment proposal did not yield a permitted action: " + \
                           "; ".join(proposal.reasons)
        return report

    selected_action = next((a for a in actions if a.action_id == proposal.action_id), None)
    if selected_action is None:
        report["reason"] = f"Proposed action {proposal.action_id!r} is not in the approved catalog"
        return report

    if not isinstance(scope_snapshot, EvidenceSnapshot) or scope_snapshot.case_id != case_id:
        report["reason"] = "No case-bound independent scope snapshot"
        return report
    if not scope_snapshot.trusted or not scope_snapshot.scope_complete:
        report["reason"] = "Independent scope evidence is incomplete or untrusted"
        return report
    if scope_snapshot.captured_at > now:
        report["reason"] = "Scope observation is from the future"
        return report
    if "script-integrity:" + script.script_id not in scope_snapshot.source_ids:
        report["reason"] = "Scope snapshot is not bound to this exact script"
        return report

    screened = select_action(scope_snapshot, (selected_action,), predictions,
                             dict(remaining_error_budgets or {}))
    report["policy_screened"] = _serialize_screened(screened.screened)
    if screened.abstained or screened.selected is None:
        report["reason"] = "Existing independent action gate abstained: " + screened.reason
        return report
    report["selection_status"] = "ELIGIBLE_LAB_PLAN"
    report["scope_snapshot_id"] = scope_snapshot.snapshot_id
    report["selected_action_model_fingerprint"] = next(
        (p.training_fingerprint for p in predictions if p.action_id == screened.selected.action_id), None)
    report["selected_action"] = screened.selected.action_id
    report["selection_score"] = screened.selected.score
    report["reason"] = "Confirmed finding matched an AI-proposed, policy-gated containment action"
    # No execution token and no authority is included in a planning record.
    return report


def record_independent_outcome(plan: dict, execution_receipt: dict,
                               observations: tuple[Evidence,...], *,
                               now: datetime | None=None) -> dict:
    """Adjudicate a separate executor receipt against independent observation.

    This records verification after an externally executed lab action. It
    intentionally exposes no endpoint, credential or mutating tool.
    """
    if plan.get("schema")!="predict-shield/unified-ai-case-plan/1":
        raise ValueError("Unsupported case plan")
    if now is None:
        now=datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Observation timestamp must be timezone-aware")
    action=plan.get("selected_action")
    if (not action or plan.get("selection_status")!="ELIGIBLE_LAB_PLAN"
            or not isinstance(execution_receipt,dict)
            or execution_receipt.get("selected_action")!=action
            or execution_receipt.get("lab_only") is not True):
        raise ValueError("Missing matching lab execution receipt")
    output={
        "schema":"predict-shield/unified-ai-case-outcome/1",
        "case_id":plan["case_id"],"selected_action":action,
        "action_executed":execution_receipt.get("action_executed") is True,
        "execution_receipt_is_not_verification":True,
        "verification_status":"INDETERMINATE",
        "verification_reason":"No verified post-action independent evidence",
        "independent_evidence_sources":[],
        "service_continuity_status":"UNKNOWN",
    }
    if not output["action_executed"]:
        return output
    finding=plan["ai_proposals"][0]
    assert_id="mitigated:"+finding["cve"]+":"+finding["purl"]
    result=assess(finding["asset_id"],assert_id,list(observations),
                  required_independent_checks=1,max_age_seconds=3600,now=now)
    output["verification_status"]=result.outcome.value
    output["verification_reason"]=result.reason
    output["independent_evidence_sources"]=list(result.evidence_sources)
    output["conflicting_evidence"]=result.conflicting_evidence
    return output
