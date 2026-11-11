"""Unit tests for v2.2 contract and fail-closed action screening.

These tests exercise pure Python only. They do not establish trained-model
performance, authenticated evidence, or deployed execution safety.
"""
import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.ai_contracts import (
    ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval,
    TrainingExampleLink,
)
from predict_shield.action_gate import GateDecision, screen_action


NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)


def fixture(tier=ActionTier.AUTOMATIC, upper=3.0, width=1.0, ood=False,
            calibrated=True):
    snapshot = EvidenceSnapshot(
        snapshot_id="evidence-001", case_id="case-b-001", captured_at=NOW,
        source_ids=("inventory-a", "inventory-b"), trusted=True, scope_complete=True,
    )
    action = CandidateAction(
        action_id="resync-policy", tier=tier, affected_services=("auth-service",),
        postcondition="revoked principal denied at all applicable enforcement points",
        reversible=True,
    )
    prediction = ActionPrediction(
        action_id=action.action_id, snapshot_id=snapshot.snapshot_id,
        model_name="lab-regression", model_version="test",
        predicted_at=NOW + timedelta(seconds=1),
        residual_risk=Interval(.05, .10, .20),
        additional_errors={"auth-service": Interval(max(0.0, upper-width), upper-width/2, upper)},
        out_of_distribution=ood, calibration_supported=calibrated,
    )
    return snapshot, action, prediction


class AIContractTests(unittest.TestCase):
    def test_reject_malformed_interval(self):
        with self.assertRaises(ValueError):
            Interval(0.2, 0.1, 0.3)

    def test_reject_future_oracle_as_training_feature_not_encodable(self):
        # The estimator interface takes only EvidenceSnapshot and CandidateAction.
        # OracleRecord is a separate type; stronger checks require data lineage tests.
        with self.assertRaises(ValueError):
            TrainingExampleLink(
                run_id="r", case_id="c", prediction_record_id="p",
                verification_record_id=None, oracle_record_id=None,
                operational_outcome_record_id=None,
                split_group="g", split="unknown", label_observed=False,
            )

    def test_supported_low_impact_action_eligible(self):
        s, a, p = fixture()
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.ELIGIBLE_AUTOMATIC)

    def test_prohibited_action_rejected_even_with_safe_prediction(self):
        s, a, p = fixture(tier=ActionTier.PROHIBITED)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.REJECT)

    def test_unknown_budget_escalates(self):
        s, a, p = fixture()
        self.assertEqual(screen_action(s, a, p, {}).decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)

    def test_automatic_high_disruption_rejected(self):
        s, a, p = fixture(upper=12.0)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.REJECT)

    def test_known_high_disruption_approval_tier_proposes(self):
        s, a, p = fixture(tier=ActionTier.APPROVAL, upper=12.0)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.PROPOSE_FOR_APPROVAL)

    def test_missing_evidence_not_repaired_by_human_approval(self):
        s, a, p = fixture(tier=ActionTier.APPROVAL)
        s = EvidenceSnapshot(s.snapshot_id, s.case_id, s.captured_at,
                             s.source_ids, trusted=False, scope_complete=False)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)

    def test_ood_escalates_even_with_low_impact(self):
        s, a, p = fixture(ood=True)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)

    def test_uncalibrated_predictions_escalate(self):
        s, a, p = fixture(calibrated=False)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)

    def test_stale_model_snapshot_binding_escalates(self):
        s, a, p = fixture()
        changed = EvidenceSnapshot("new-evidence", s.case_id, s.captured_at,
                                   s.source_ids, True, True)
        self.assertEqual(screen_action(changed, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)

    def test_wide_interval_escalates(self):
        s, a, p = fixture(upper=8.0, width=7.0)
        self.assertEqual(screen_action(s, a, p, {"auth-service": 10.0}).decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)


if __name__ == "__main__":
    unittest.main()
