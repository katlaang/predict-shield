"""No-network integration checks: calibrated prediction -> gate -> action ranking.

The mock regressors are unit-test fixtures, not a trained scientific model.
No security action is executed by these tests.
"""
import unittest
from datetime import datetime, timezone

from model_adapter import predictions_from_bundle, load_local_bundle
from train import FEATURES
from predict_shield.ai_contracts import CandidateAction, ActionTier, EvidenceSnapshot
from predict_shield.action_gate import GateDecision
from predict_shield.selector import select_action


class FakeActionModel:
    """Return fixed toy estimates to test only model-to-gate interface wiring."""

    def __init__(self, values):
        """Preserve per-action estimates for the four fixed one-hot columns."""
        self.values = values

    def predict(self, rows):
        """Select the declared mock estimate by last four action indicator columns."""
        output = []
        for row in rows:
            action_index = next(i for i, val in enumerate(row[-4:]) if val == 1)
            output.append(self.values[action_index])
        return output


class ModelDecisionIntegrationTests(unittest.TestCase):
    """Keep authorization and evidence checks independent of learned predictions."""

    def setUp(self):
        """Create a synthetic, complete evidence snapshot and trusted mock bundle."""
        self.snapshot = EvidenceSnapshot(
            "snapshot-test", "run-test",
            datetime(2026, 11, 10, tzinfo=timezone.utc),
            ("probe-a", "inventory-a", "inventory-b"),
            trusted=True, scope_complete=True,
        )
        self.pre = {
            "run_id": "run-test",
            "experiment_type": "real_kafka_multijvm_lab",
            "oracle_features_excluded": True,
            "features": {
                "cache_ttl_ms": 6000,
                "requested_rps": 20,
                "visible_enforcement_processes": 3,
                "measurement_seconds": 4,
            },
            "external_deny_observations": [
                {"http_status": 403}, {"http_status": 200}, {"http_status": 403},
            ],
        }
        self.bundle = {
            "schema": "predict-shield/mechanism-model-bundle/1",
            "features": list(FEATURES),
            "training_fingerprint": "unit-test-only",
            "calibration_group_count": 20,
            "radii": {"label_security_exposure": .02,
                      "label_absolute_failed_requests": 2.0},
            "numeric_feature_bounds": {
                "cache_ttl_ms": [2500, 15000],
                "requested_rps": [10, 65],
                "gateway_visible_enforcer_count": [3, 4],
                "initial_gateway_allowed_fraction": [0, 1],
                "operator_observed_count": [0, 4],
                "operator_missing_count": [0, 4],
                "operator_revision_spread": [0, 100],
                "operator_max_cache_age_ms": [0, 100000],
                "operator_refresh_failure_count": [0, 4],
                "operator_pending_callback_count": [0, 100],
                "operator_handled_event_spread": [0, 100],
            },
            "models": {
                "label_security_exposure": FakeActionModel([.20, .10, .02, .90]),
                "label_absolute_failed_requests": FakeActionModel([8.0, 18.0, 60.0, 2.0]),
            },
        }
        self.actions = (
            CandidateAction("resync_policy", ActionTier.AUTOMATIC,
                            ("authorization",), "Deny revoked access"),
            CandidateAction("restart_enforcer", ActionTier.AUTOMATIC,
                            ("authorization",), "Deny revoked access"),
        )

    def test_typed_predictions_reach_hard_gate_and_rank(self):
        """A calibrated mock predictor can propose but never execute a candidate."""
        predictions = predictions_from_bundle(
            self.bundle, self.pre, self.snapshot, self.actions)
        selection = select_action(
            self.snapshot, self.actions, predictions, {"authorization": 50.0})
        self.assertFalse(selection.abstained)
        # With the mock's lower residual risk, restart is ranked above
        # resync under this intentionally synthetic safety-gate fixture.
        self.assertEqual(selection.selected.action_id, "restart_enforcer")
        self.assertTrue(all(item.training_fingerprint == "unit-test-only"
                            for item in predictions))
        # The model predicts absolute failed HTTP request counts directly;
        # neither the interval nor its radius is scaled by scheduled RPS.
        predicted = predictions[0].additional_errors["authorization"]
        self.assertEqual(predicted.lower, 6.0)
        self.assertEqual(predicted.estimate, 8.0)
        self.assertEqual(predicted.upper, 10.0)

    def test_incomplete_scope_must_abstain_even_if_model_confident(self):
        """The actual gateway-only experimental setting cannot assert complete scope."""
        incomplete = EvidenceSnapshot(
            self.snapshot.snapshot_id, self.snapshot.case_id,
            self.snapshot.captured_at, self.snapshot.source_ids, True, False,
        )
        predictions = predictions_from_bundle(
            self.bundle, self.pre, incomplete, self.actions)
        selection = select_action(incomplete, self.actions, predictions,
                                  {"authorization": 50.0})
        self.assertTrue(selection.abstained)
        self.assertIsNone(selection.selected)
        self.assertTrue(all(x.decision == GateDecision.ESCALATE_FOR_EVIDENCE
                            for x in selection.screened.values()))

    def test_future_oracle_in_feature_input_rejected(self):
        """The adapter explicitly refuses raw oracle or post-action features."""
        tampered = {**self.pre, "oracle": {"all_revoked_access_denied": True}}
        with self.assertRaises(ValueError):
            predictions_from_bundle(self.bundle, tampered, self.snapshot,
                                    self.actions)

    def test_hidden_fault_metadata_is_rejected(self):
        """The actual injected fault type and target must not enter a model call."""
        tampered = {**self.pre, "features": {
            **self.pre["features"], "fault_mode": "loss"
        }}
        with self.assertRaises(ValueError):
            predictions_from_bundle(self.bundle, tampered, self.snapshot, self.actions)

    def test_ood_model_abstains(self):
        """A condition outside registered training support blocks automatic action."""
        pre = dict(self.pre)
        pre["features"] = {**pre["features"], "cache_ttl_ms": 30000}
        predictions = predictions_from_bundle(
            self.bundle, pre, self.snapshot, self.actions)
        self.assertTrue(all(p.out_of_distribution for p in predictions))
        selection = select_action(
            self.snapshot, self.actions, predictions, {"authorization": 50.0})
        self.assertTrue(selection.abstained)


if __name__ == "__main__":
    unittest.main()
