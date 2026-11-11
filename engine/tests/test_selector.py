"""Tests for model-to-policy-gate-to-selection wiring, without execution."""
import unittest
from datetime import datetime, timezone, timedelta

from predict_shield.ai_contracts import (
    EvidenceSnapshot, CandidateAction, ActionPrediction, Interval, ActionTier
)
from predict_shield.action_gate import GateDecision
from predict_shield.selector import select_action

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


class PolicyConstrainedSelectionTests(unittest.TestCase):
    """Guard against optimizing learned scores at the expense of safety."""

    def setUp(self):
        """Create test-only current evidence and a small set of action candidates."""
        self.snapshot = EvidenceSnapshot("s-1", "case-1", NOW, ("probe-a", "probe-b"), True, True)
        self.actions = (
            CandidateAction("resync", ActionTier.AUTOMATIC, ("auth",), "revoked"),
            CandidateAction("restart", ActionTier.AUTOMATIC, ("auth",), "revoked"),
        )

    def predict(self, action, risk, failures, *, supported=True):
        """Produce one calibrated model fixture for exact controlled assertions."""
        return ActionPrediction(
            action_id=action,
            snapshot_id=self.snapshot.snapshot_id,
            model_name="test-regressor",
            model_version="test",
            predicted_at=NOW + timedelta(seconds=1),
            residual_risk=Interval(max(0, risk-.02), risk, min(1, risk+.02)),
            additional_errors={"auth": Interval(max(0, failures-0.1), failures, failures+0.1)},
            out_of_distribution=False,
            calibration_supported=supported,
        )

    def test_lower_risk_not_always_preferred_when_disruption_high(self):
        """Risk and disruption must both affect the ranking of eligible actions."""
        predictions = (
            self.predict("resync", 0.20, 1.0),
            self.predict("restart", 0.11, 5.0),
        )
        selection = select_action(self.snapshot, self.actions, predictions,
                                  {"auth": 10.0}, disruption_weight=1.0)
        self.assertEqual(selection.selected.action_id, "resync")
        self.assertFalse(selection.abstained)

    def test_forbidden_action_never_selected_even_if_model_likes_it(self):
        """A model cannot bypass a prohibited policy tier."""
        actions = (
            CandidateAction("forbidden", ActionTier.PROHIBITED, ("auth",), "revoked"),
            self.actions[0],
        )
        predictions = (
            self.predict("forbidden", 0.0, 0.0),
            self.predict("resync", 0.5, 1.0),
        )
        selection = select_action(self.snapshot, actions, predictions, {"auth": 10.0})
        self.assertEqual(selection.selected.action_id, "resync")
        self.assertEqual(selection.screened["forbidden"].decision, GateDecision.REJECT)

    def test_missing_model_abstains_without_execution(self):
        """Untrained systems must not silently substitute invented confidence."""
        selection = select_action(self.snapshot, self.actions, (), {"auth": 10.0})
        self.assertTrue(selection.abstained)
        self.assertIsNone(selection.selected)

    def test_ood_or_uncalibrated_model_abstains(self):
        """Unsupported prediction coverage prevents automatic selection."""
        selection = select_action(self.snapshot, self.actions,
                                  (self.predict("resync", 0.1, 1, supported=False),),
                                  {"auth": 10.0})
        self.assertTrue(selection.abstained)

    def test_unknown_budget_abstains(self):
        """Missing service continuity evidence cannot be overridden by a score."""
        selection = select_action(self.snapshot, self.actions,
                                  (self.predict("resync", 0.1, 1),), {})
        self.assertTrue(selection.abstained)

    def test_approval_tier_never_automatically_selected(self):
        """A named human approval requirement is separate from automatic dispatch."""
        actions = (CandidateAction("resync", ActionTier.APPROVAL, ("auth",), "revoked"),)
        selection = select_action(self.snapshot, actions,
                                  (self.predict("resync", 0.1, 1),), {"auth": 10.0})
        self.assertTrue(selection.abstained)
        self.assertEqual(selection.screened["resync"].decision,
                         GateDecision.PROPOSE_FOR_APPROVAL)


if __name__ == "__main__":
    unittest.main()
