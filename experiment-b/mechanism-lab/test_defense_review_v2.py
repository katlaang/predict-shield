"""Synthetic-only checks: no model fitting, attack simulation or field efficacy."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from defense_review_v2 import (
    EXPECTED_NODES, inspect_operator_evidence, check_model_reliability,
    review_recommendation,
)
from test_broker_observer_v1 import valid_broker


def observations(*, now=100.0, paused=False, divergent=False):
    rows = []
    for i, node in enumerate(EXPECTED_NODES):
        rows.append({
            "node": node, "observed": True, "observed_at_monotonic": now-0.3,
            "consumer_state_observed": True, "consumer_running": True,
            "consumer_paused": bool(paused and i == 1),
            "consumer_pause_requested": bool(paused and i == 1),
            "broker_consumer_lag_measured": False,
            "applied_revision": 2 if divergent and i == 1 else 3,
            "handled_events": 4,
            "cache_age_ms": 100, "scheduled_callbacks_pending": 0,
            "refresh_failed": False,
        })
    return rows


def report(*, security=.95, disruption=.92):
    return {
        "training_fingerprint": "synthetic-123",
        "test_used_for_training_or_calibration": False,
        "metrics": {
            "label_security_exposure": {
                "nominal_coverage": .9,
                "heldout_configuration_group_coverage": security,
            },
            "label_absolute_failed_requests": {
                "nominal_coverage": .9,
                "heldout_configuration_group_coverage": disruption,
            },
        },
    }


def predictions(*, resync=.05, restart=.01, restart_impact=30):
    out = []
    for name, risk, failures in (
        ("resync_policy", resync, 3),
        ("restart_enforcer", restart, restart_impact),
        ("gateway_restrict", .5, 12),
        ("monitor_only", .95, 0),
    ):
        out.append(SimpleNamespace(
            action_id=name, out_of_distribution=False,
            calibration_supported=True,
            residual_risk=SimpleNamespace(
                lower=0., estimate=risk / 2, upper=risk),
            additional_errors={"authorization": SimpleNamespace(
                lower=0., estimate=failures / 2, upper=failures)},
        ))
    return tuple(out)


def assess(*, rows=None, evaluation=None, selected="resync_policy",
           model_predictions=None, now=100., budget=25., eligible=None):
    return review_recommendation(
        pre_action={
            "operator_observations": observations() if rows is None else rows,
            "broker_observation": valid_broker(now=now),
        },
        selected_action=selected,
        predictions=predictions() if model_predictions is None else model_predictions,
        eligible_actions=tuple(eligible or ("resync_policy", "restart_enforcer",
                                            "gateway_restrict", "monitor_only")),
        bundle={"training_fingerprint": "synthetic-123"},
        model_evaluation=report() if evaluation is None else evaluation,
        remaining_budget=budget, now_monotonic=now,
    )


class EvidenceReviewTests(unittest.TestCase):
    def test_valid_complete_observation_can_review_low_risk_resync(self):
        x = assess()
        self.assertEqual(x["status"], "ELIGIBLE_FOR_LAB_REVIEWED_ACTION")
        self.assertEqual(x["operator_evidence"]["lag_ground_truth"], "UNKNOWN")
        self.assertFalse(x["automatic_production_execution_authorized"])
        self.assertFalse(x["post_action_resolution_verified"])

    def test_missing_old_telemetry_fails_closed(self):
        x = assess(rows=[])
        self.assertEqual(x["status"], "HUMAN_REVIEW_REQUIRED")
        self.assertIn("INCOMPLETE_OPERATOR_INVENTORY", x["reasons"])

    def test_listener_paused_blocks_resync_no_fault_label_needed(self):
        x = assess(rows=observations(paused=True))
        self.assertIn("CONSUMER_PAUSED_OR_NOT_RUNNING", x["reasons"])
        self.assertIn("RESYNC_CANNOT_RESTART_PAUSED_CONSUMER", x["reasons"])
        self.assertEqual(x["operator_evidence"]["paused_nodes"], ["enforcer-b"])
        self.assertFalse(x["may_proceed_to_independent_lab_policy_gate"])

    def test_revision_divergence_is_signal_not_fabricated_fault(self):
        x = assess(rows=observations(divergent=True))
        self.assertEqual(x["status"], "ELIGIBLE_FOR_LAB_REVIEWED_ACTION")
        self.assertIn("REVISION_DIVERGENCE_OBSERVED",
                      x["operator_evidence"]["pre_action_signals"])
        self.assertFalse(x["operator_evidence"]["fault_identity_known"])

    def test_stale_or_untimed_observations_block(self):
        rows = observations()
        rows[0]["observed_at_monotonic"] = 90.
        x = assess(rows=rows)
        self.assertIn("STALE_OR_UNTIMED_TELEMETRY", x["reasons"])
        rows[0]["observed_at_monotonic"] = None
        self.assertEqual(assess(rows=rows)["status"], "HUMAN_REVIEW_REQUIRED")

    def test_duplicate_and_replaced_inventory_block(self):
        rows = observations()
        rows[0]["node"] = "enforcer-hidden"
        x = assess(rows=rows)
        self.assertIn("DUPLICATE_OPERATOR_NODE", x["reasons"])
        self.assertIn("INVENTORY_IDENTITY_MISMATCH", x["reasons"])

    def test_oracle_and_fault_label_in_telemetry_block(self):
        rows = observations()
        rows[0]["fault_mode"] = "loss"
        x = assess(rows=rows)
        self.assertIn("PRIVILEGED_TELEMETRY_PRESENT", x["reasons"])

    def test_unreliable_security_intervals_block_even_when_impact_looks_safe(self):
        x = assess(evaluation=report(security=.70))
        self.assertEqual(x["status"], "HUMAN_REVIEW_REQUIRED")
        self.assertIn("COVERAGE_SHORTFALL_label_security_exposure", x["reasons"])

    def test_without_fingerprint_anchored_report_fails_closed(self):
        bad = report()
        bad["training_fingerprint"] = "other-artifact"
        x = assess(evaluation=bad)
        self.assertIn("TRAINING_FINGERPRINT_MISMATCH", x["reasons"])
        self.assertEqual(x["model_reliability"]["status"], "NOT_VERIFIED")

    def test_selected_action_predicted_unresolved_must_escalate(self):
        x = assess(model_predictions=predictions(resync=.9))
        self.assertIn("SELECTED_ACTION_PREDICTED_UNRESOLVED", x["reasons"])
        self.assertTrue(x["requires_human_review"])

    def test_restart_beyond_disruption_budget_needs_human_not_silent_restart(self):
        x = assess(selected="restart_enforcer",
                   model_predictions=predictions(restart_impact=30))
        self.assertIn("RESTART_REQUIRES_HUMAN_APPROVAL", x["reasons"])
        self.assertIn("SELECTED_ACTION_EXCEEDS_DISRUPTION_BUDGET", x["reasons"])
        self.assertFalse(x["may_proceed_to_independent_lab_policy_gate"])

    def test_monitor_only_not_counted_as_remediation(self):
        x = assess(selected="monitor_only")
        self.assertIn("MONITOR_ONLY_IS_NOT_REMEDIATION", x["reasons"])
        self.assertFalse(x["post_action_resolution_verified"])

    def test_unsafe_chosen_action_cannot_be_rescued_by_other_safe_action(self):
        x = assess(model_predictions=predictions(resync=.80))
        self.assertEqual(x["status"], "HUMAN_REVIEW_REQUIRED")
        self.assertIn("SELECTED_ACTION_PREDICTED_UNRESOLVED", x["reasons"])

    def test_no_bounded_effective_option_escalates(self):
        x = assess(model_predictions=predictions(resync=.5,restart=.2))
        self.assertIn("NO_BOUNDED_EFFECTIVE_AUTOMATIC_OPTION", x["reasons"])

    def test_missing_broker_evidence_escalates(self):
        result = review_recommendation(
            pre_action={"operator_observations": observations()},
            selected_action="resync_policy",
            predictions=predictions(),
            eligible_actions=("resync_policy", "restart_enforcer",
                              "gateway_restrict", "monitor_only"),
            bundle={"training_fingerprint": "synthetic-123"},
            model_evaluation=report(), remaining_budget=25.,
            now_monotonic=100.)
        self.assertIn("INDEPENDENT_BROKER_EVIDENCE_UNAVAILABLE", result["reasons"])
        self.assertTrue(result["requires_human_review"])

    def test_positive_broker_backlog_is_preaction_signal_not_success(self):
        from test_broker_observer_v1 import valid_broker
        result = review_recommendation(
            pre_action={
                "operator_observations": observations(),
                "broker_observation": valid_broker(now=100., lag=4),
            }, selected_action="resync_policy", predictions=predictions(),
            eligible_actions=("resync_policy", "restart_enforcer",
                              "gateway_restrict", "monitor_only"),
            bundle={"training_fingerprint": "synthetic-123"},
            model_evaluation=report(), remaining_budget=25.,
            now_monotonic=100.)
        self.assertEqual(result["broker_offset_evidence"]["status"], "MEASURED")
        self.assertIn("BROKER_COMMITTED_BACKLOG_OBSERVED",
                      result["operator_evidence"]["pre_action_signals"])
        self.assertFalse(result["post_action_resolution_verified"])

    def test_false_broker_lag_claim_is_rejected(self):
        rows = observations()
        rows[0]["broker_consumer_lag_measured"] = True
        x = assess(rows=rows)
        self.assertIn("MISLABELED_BROKER_LAG", x["reasons"])

    def test_invalid_model_probability_interval_rejected(self):
        preds = list(predictions())
        preds[0].residual_risk.upper = -1.
        with self.assertRaisesRegex(ValueError, "Invalid residual-risk"):
            assess(model_predictions=tuple(preds))

    def test_future_timestamp_is_rejected(self):
        rows = observations()
        rows[0]["observed_at_monotonic"] = 102
        self.assertIn("STALE_OR_UNTIMED_TELEMETRY", assess(rows=rows)["reasons"])


if __name__ == "__main__":
    unittest.main()
