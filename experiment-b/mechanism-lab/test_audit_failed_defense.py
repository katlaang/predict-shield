"""Synthetic contract tests. They do not score new attacks or physical defenses."""
import copy
import unittest

from audit_failed_defense import (
    inspect_frozen_proposal, heldout_calibration_audit, audit_failed_physical_cohort,
)
from paired_defense_eval import ACTIONS
from test_paired_defense_eval import FakeModel, PRE, sample_rows


def bundle(*, restart_failures=16.84, radius=12.28):
    bounds = {k: [float(PRE[k]) - 1., float(PRE[k]) + 1.]
              for k in PRE if k != "routing_profile"}
    return {
        "schema": "predict-shield/mechanism-model-bundle/1",
        "training_group_count": 60, "calibration_group_count": 20,
        "not_certified_for_automatic_execution": True,
        "numeric_feature_bounds": bounds,
        "radii": {
            "label_path_exposure": 0.26,
            "label_security_exposure": 0.,
            "label_absolute_failed_requests": radius,
        },
        "models": {
            "label_path_exposure": FakeModel({
                "resync_policy": .16, "restart_enforcer": .18,
                "gateway_restrict": .05, "monitor_only": .20,
            }),
            "label_security_exposure": FakeModel({
                "resync_policy": 1.0, "restart_enforcer": 0.0,
                "gateway_restrict": 1.0, "monitor_only": 1.0,
            }),
            "label_absolute_failed_requests": FakeModel({
                "resync_policy": 0., "restart_enforcer": restart_failures,
                "gateway_restrict": 20., "monitor_only": 0.,
            })
        }
    }


def report():
    return {"metrics": {
        name: {"nominal_coverage": .90,
               "heldout_configuration_group_coverage": actual,
               "conformal_absolute_error_radius": radius}
        for name, actual, radius in (
            ("label_security_exposure", .70, 0.),
            ("label_path_exposure", .60, .26),
            ("label_absolute_failed_requests", .90, 12.28),
        )
    }}


def old_result(rows):
    return {
        "choices": [
            {"configuration_id": rows[0]["group"], "repeat": rows[0]["repeat"],
             "selected_actions": {"learned_policy": "resync_policy"}}
        ]
    }


class DefenseFailureAuditTests(unittest.TestCase):
    def test_predicted_restart_best_but_safety_gate_disqualifies(self):
        data = inspect_frozen_proposal(bundle(), PRE,
                                       restart_permitted=True,
                                       disruption_budget=25)
        self.assertEqual(data["selected"], "resync_policy")
        self.assertTrue(data["selected_action_predicted_unresolved"])
        self.assertTrue(data["requires_operator_escalation"])
        self.assertEqual(data["potentially_effective_action_blocked_by_disruption_gate"],
                         ["restart_enforcer"])
        restart = data["options"]["restart_enforcer"]
        resync = data["options"]["resync_policy"]
        self.assertLess(restart["predicted_weighted_cost"],
                        resync["predicted_weighted_cost"])
        self.assertGreater(restart["predicted_failure_upper_bound"], 25)
        self.assertEqual(restart["gate_reason"],
                         "DISRUPTION_UPPER_BOUND_EXCEEDS_BUDGET")
        self.assertFalse(data["automated_execution_permitted"])

    def test_policy_denies_restart_even_when_disruption_bound_fits(self):
        data = inspect_frozen_proposal(bundle(restart_failures=1.,radius=1.),
                                       PRE, restart_permitted=False,
                                       disruption_budget=25)
        self.assertEqual(data["options"]["restart_enforcer"]["gate_reason"],
                         "PROHIBITED_BY_POLICY")
        self.assertNotEqual(data["selected"], "restart_enforcer")

    def test_no_unsafe_safety_gate_relaxation(self):
        data = inspect_frozen_proposal(bundle(radius=12.28),
                                       PRE, restart_permitted=True,
                                       disruption_budget=25)
        self.assertFalse(data["options"]["restart_enforcer"]["eligible_for_selector"])
        self.assertEqual(data["selected"], "resync_policy")

    def test_no_ood_model_can_authorize_execution(self):
        pre = dict(PRE, cache_ttl_ms=30000000)
        data = inspect_frozen_proposal(bundle(), pre,
                                       restart_permitted=True, disruption_budget=25)
        self.assertIsNone(data["selected"])
        self.assertTrue(data["requires_operator_escalation"])
        self.assertFalse(data["automated_execution_permitted"])

    def test_calibration_shortfall_reported_without_retraining(self):
        out = heldout_calibration_audit(report())
        self.assertEqual(out["status"], "PRIOR_HELDOUT_RELIABILITY_FAILURE")
        self.assertEqual(set(out["shortfall_labels"]),
                         {"label_security_exposure", "label_path_exposure"})
        self.assertFalse(out["production_model_qualification"])

    def test_posthoc_audit_reproduces_original_selection(self):
        rows = sample_rows()
        data = audit_failed_physical_cohort(
            rows, bundle(), old_result(rows), report())
        self.assertEqual(data["paired_episodes"], 1)
        self.assertFalse(data["new_test_performed"])
        entry = data["per_episode"][0]
        self.assertEqual(entry["decision_explanation"]["selected"], "resync_policy")
        self.assertEqual(entry["decision_explanation"][
            "potentially_effective_action_blocked_by_disruption_gate"],
            ["restart_enforcer"])
        self.assertFalse(data["future_model_qualified_for_autonomous_actions"])

    def test_frozen_report_mismatch_rejected(self):
        rows = sample_rows()
        altered = old_result(rows)
        altered["choices"][0]["selected_actions"]["learned_policy"] = "restart_enforcer"
        with self.assertRaisesRegex(ValueError, "Reproduced model selection"):
            audit_failed_physical_cohort(rows, bundle(), altered, report())

    def test_future_outcomes_cannot_change_past_choice(self):
        rows = sample_rows()
        a = audit_failed_physical_cohort(rows, bundle(), old_result(rows), report())
        changed = copy.deepcopy(rows)
        for row in changed:
            row["label_security_exposure"] = 1.0 - row["label_security_exposure"]
            row["label_path_exposure"] = 1.0 - row["label_path_exposure"]
        b = audit_failed_physical_cohort(changed, bundle(), old_result(rows), report())
        self.assertEqual(
            a["per_episode"][0]["decision_explanation"],
            b["per_episode"][0]["decision_explanation"])
        self.assertNotEqual(
            a["per_episode"][0]["observed_counterfactual_matched_lab_outcomes"],
            b["per_episode"][0]["observed_counterfactual_matched_lab_outcomes"])

    def test_incomplete_measured_actions_rejected(self):
        rows = sample_rows()[:-1]
        with self.assertRaisesRegex(ValueError, "Incomplete matched"):
            audit_failed_physical_cohort(rows, bundle(), old_result(rows), report())


if __name__ == "__main__":
    unittest.main()
