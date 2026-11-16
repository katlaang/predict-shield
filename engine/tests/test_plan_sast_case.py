"""Synthetic contracts for plan_sast_case: the SAST-finding counterpart to
plan_case's propose-then-gate flow, using a deterministic rule_to_action
registration instead of an AI reading advisory text."""
import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.ai_contracts import ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval
from predict_shield.pipeline import plan_sast_case
from predict_shield.sast_findings import RegisteredScanner, ScanFinding

NOW = datetime(2026, 11, 15, 22, 0, tzinfo=timezone.utc)
ASSET = "repo:web-app/app/db.py"
RULE_ID = "python-sql-string-concat"
ACTION = CandidateAction("apply_parameterized_query_patch", ActionTier.AUTOMATIC,
                         ("web-app",), "Query parameterized", reversible=True)

SCANNER_REGISTRY = {
    "semgrep-oss-local-rule": RegisteredScanner(
        scanner_id="semgrep-oss-local-rule", name="Semgrep OSS", version="1.185.0", trusted=True),
}
RULE_TO_ACTION = {RULE_ID: "apply_parameterized_query_patch"}


def finding(*, present=True, finding_id="finding-0001"):
    return ScanFinding(finding_id=finding_id, asset=ASSET, scanner_id="semgrep-oss-local-rule",
                       rule_id=RULE_ID, fingerprint="abc123", file_path="app/db.py",
                       severity="high", present=present, observed_at=NOW)


def snap(finding_id="finding-0001"):
    return EvidenceSnapshot(snapshot_id="lab-scope:sast-test", case_id="sast-test-case",
        captured_at=NOW, source_ids=("docker", "gateway", "sast-finding:" + finding_id),
        trusted=True, scope_complete=True)


def predicted(snapshot):
    return ActionPrediction(action_id=ACTION.action_id, snapshot_id=snapshot.snapshot_id,
        model_name="synthetic-outcome-model", model_version="fixture",
        predicted_at=NOW + timedelta(seconds=1), residual_risk=Interval(.1, .2, .3),
        additional_errors={"web-app": Interval(1, 2, 3)},
        calibration_supported=True, training_fingerprint="synthetic")


def run(**kwargs):
    defaults = dict(case_id="sast-test-case", finding=finding(),
                    scanner_registry=SCANNER_REGISTRY, rule_to_action=RULE_TO_ACTION,
                    actions=(ACTION,), now=NOW)
    defaults.update(kwargs)
    return plan_sast_case(**defaults)


class PlanSastCaseTests(unittest.TestCase):
    def test_without_independent_scope_stays_escalated(self):
        result = run()
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIsNone(result["selected_action"])

    def test_a_present_finding_with_registered_action_and_full_scope_is_eligible(self):
        s = snap()
        result = run(scope_snapshot=s, predictions=(predicted(s),),
                     remaining_error_budgets={"web-app": 5.0})
        self.assertEqual(result["selection_status"], "ELIGIBLE_RESEARCH_LAB_PLAN")
        self.assertEqual(result["selected_action"], "apply_parameterized_query_patch")
        self.assertEqual(result["confirmed_present"], "VERIFIED")

    def test_a_finding_the_scanner_did_not_actually_observe_is_not_eligible(self):
        # present=False means confirm_before_fix's observed_pass is False:
        # there is nothing here for a fix to resolve, so this must not
        # reach ELIGIBLE regardless of scope/policy state.
        s = snap()
        result = run(finding=finding(present=False), scope_snapshot=s,
                     predictions=(predicted(s),), remaining_error_budgets={"web-app": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertEqual(result["confirmed_present"], "NOT VERIFIED")

    def test_an_unregistered_rule_id_is_refused_not_guessed_at(self):
        s = snap()
        result = run(rule_to_action={}, scope_snapshot=s,
                     predictions=(predicted(s),), remaining_error_budgets={"web-app": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("No registered remediation action", result["reason"])

    def test_a_registered_action_outside_the_approved_catalog_is_refused(self):
        s = snap()
        result = run(rule_to_action={RULE_ID: "something_not_in_catalog"},
                     scope_snapshot=s, predictions=(predicted(s),),
                     remaining_error_budgets={"web-app": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("not in the approved catalog", result["reason"])

    def test_a_scope_snapshot_bound_to_a_different_finding_is_rejected(self):
        s = snap(finding_id="some-other-finding")
        result = run(scope_snapshot=s, predictions=(predicted(s),),
                     remaining_error_budgets={"web-app": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("not bound to this exact finding", result["reason"])

    def test_an_untrusted_scanner_registry_entry_blocks_confirmation(self):
        s = snap()
        untrusted_registry = {
            "semgrep-oss-local-rule": RegisteredScanner(
                scanner_id="semgrep-oss-local-rule", name="Semgrep OSS",
                version="1.185.0", trusted=False),
        }
        result = run(scanner_registry=untrusted_registry, scope_snapshot=s,
                     predictions=(predicted(s),), remaining_error_budgets={"web-app": 5.0})
        self.assertEqual(result["selection_status"], "ESCALATE_FOR_EVIDENCE")
        self.assertIn("could not be confirmed", result["reason"])


if __name__ == "__main__":
    unittest.main()
