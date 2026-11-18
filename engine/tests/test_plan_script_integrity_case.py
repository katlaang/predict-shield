"""Synthetic contracts for plan_script_integrity_case: the script-integrity
counterpart to plan_sast_case's propose-then-gate flow, with an AI
containment proposal in place of a deterministic rule_to_action lookup."""
import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.ai_contracts import ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval
from predict_shield.pipeline import plan_script_integrity_case
from predict_shield.script_integrity import RegisteredScript, RegisteredSite, ScriptObservation
from predict_shield.script_risk_proposer import ModelScriptRiskProposer
from scripted_model import ScriptedModel

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
GOOD_SHA384 = "a" * 96
BAD_SHA384 = "b" * 96

SCRIPT = RegisteredScript(script_id="vendor-widget", url="https://cdn.vendor.example/widget.js",
                          trusted_sha384=(GOOD_SHA384,))
SITE = RegisteredSite(site_id="example-sme.com", allowed_script_domains=("cdn.vendor.example",),
                      prohibited_sinks=("attacker.example",))
ACTION = CandidateAction("block_via_csp", ActionTier.AUTOMATIC, ("example-sme.com",),
                         "CSP tightened", reversible=True)
PERMITTED = {"hash_mismatch": ("block_via_csp",), "unregistered_domain": ("block_via_csp",)}


def snap(script_id="vendor-widget"):
    return EvidenceSnapshot(snapshot_id="lab-scope:script-test", case_id="script-test-case",
        captured_at=NOW, source_ids=("script-integrity:" + script_id,), trusted=True, scope_complete=True)


def predicted(snapshot):
    return ActionPrediction(action_id=ACTION.action_id, snapshot_id=snapshot.snapshot_id,
        model_name="synthetic-outcome-model", model_version="fixture",
        predicted_at=NOW + timedelta(seconds=1), residual_risk=Interval(.1, .2, .3),
        additional_errors={"example-sme.com": Interval(1, 2, 3)},
        calibration_supported=True, training_fingerprint="synthetic")


def proposer_choosing(action_id):
    model = ScriptedModel([("vendor-widget", {"severity": "high", "action": action_id, "rationale": "contain"})])
    return ModelScriptRiskProposer(model)


def run(**kwargs):
    defaults = dict(
        case_id="script-test-case", script=SCRIPT, site=SITE,
        observation=ScriptObservation(script_id="vendor-widget", sha384=BAD_SHA384,
                                      status_code=200, fetched_at=NOW),
        observed_domains=("cdn.vendor.example",), observed_at=NOW,
        proposer=proposer_choosing("block_via_csp"),
        permitted_actions_by_reason=PERMITTED, actions=(ACTION,), now=NOW,
    )
    defaults.update(kwargs)
    return plan_script_integrity_case(**defaults)


class PlanScriptIntegrityCaseTests(unittest.TestCase):
    def test_without_independent_scope_stays_escalated(self):
        result = run()
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIsNone(result["selected_action"])

    def test_a_tampered_hash_with_full_scope_is_eligible(self):
        s = snap()
        result = run(scope_snapshot=s, predictions=(predicted(s),),
                    remaining_error_budgets={"example-sme.com": 5.0})
        self.assertEqual(result["selection_status"], "ELIGIBLE_LAB_PLAN")
        self.assertEqual(result["selected_action"], "block_via_csp")
        self.assertEqual(result["finding_confirmed"], "VERIFIED")
        self.assertEqual(result["finding_reason"], "hash_mismatch")

    def test_a_clean_hash_and_registered_domains_find_nothing_to_contain(self):
        s = snap()
        result = run(
            observation=ScriptObservation(script_id="vendor-widget", sha384=GOOD_SHA384,
                                          status_code=200, fetched_at=NOW),
            scope_snapshot=s, predictions=(predicted(s),),
            remaining_error_budgets={"example-sme.com": 5.0},
        )
        self.assertEqual(result["finding_confirmed"], "NOT_VERIFIED")
        self.assertIsNone(result["finding_reason"])
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")

    def test_an_unregistered_domain_with_a_clean_hash_is_still_a_finding(self):
        s = snap()
        result = run(
            observation=ScriptObservation(script_id="vendor-widget", sha384=GOOD_SHA384,
                                          status_code=200, fetched_at=NOW),
            observed_domains=("cdn.vendor.example", "evil.example"),
            scope_snapshot=s, predictions=(predicted(s),),
            remaining_error_budgets={"example-sme.com": 5.0},
        )
        self.assertEqual(result["finding_reason"], "unregistered_domain")
        self.assertEqual(result["selection_status"], "ELIGIBLE_LAB_PLAN")

    def test_a_proposal_for_an_unoffered_action_does_not_reach_eligible(self):
        s = snap()
        result = run(proposer=proposer_choosing("something_not_offered"),
                    scope_snapshot=s, predictions=(predicted(s),),
                    remaining_error_budgets={"example-sme.com": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("did not yield a permitted action", result["reason"])

    def test_no_registered_action_set_for_the_finding_reason_is_refused(self):
        s = snap()
        result = run(permitted_actions_by_reason={}, scope_snapshot=s,
                    predictions=(predicted(s),), remaining_error_budgets={"example-sme.com": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("No registered containment action set", result["reason"])

    def test_a_scope_snapshot_bound_to_a_different_script_is_rejected(self):
        s = snap(script_id="some-other-script")
        result = run(scope_snapshot=s, predictions=(predicted(s),),
                    remaining_error_budgets={"example-sme.com": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("not bound to this exact script", result["reason"])

    def test_dispatch_is_never_authorized_from_a_planning_call(self):
        s = snap()
        result = run(scope_snapshot=s, predictions=(predicted(s),),
                    remaining_error_budgets={"example-sme.com": 5.0})
        self.assertFalse(result["dispatch_authorized"])


if __name__ == "__main__":
    unittest.main()
