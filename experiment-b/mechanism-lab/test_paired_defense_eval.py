"""Synthetic CONTRACT tests only. No attack traffic or real measured AI superiority."""
import copy
import unittest

from paired_defense_eval import (
    ACTIONS, evaluate_paired, make_trusted_lab_model_policy,
)

HEX = "a" * 64
PRE = {
    "cache_ttl_ms": 30000,
    "requested_rps": 10,
    "gateway_visible_enforcer_count": 4,
    "initial_gateway_allowed_fraction": 0.5,
    "routing_profile": "balanced",
}
MEASURED = {
    "restart_enforcer": (0.1, 0., 6),
    "resync_policy": (0.8, 1., 0),
    "gateway_restrict": (0.2, 1., 12),
    "monitor_only": (1.0, 1., 0),
}


def sample_rows(restart_permitted=True, group="test-A", partition="test"):
    out = []
    for action in ACTIONS:
        path, security, failures = MEASURED[action]
        out.append({
            "group": group, "partition": partition, "repeat": 0,
            "action": action, "restart_permitted": restart_permitted,
            "absolute_error_budget_requests": 20,
            "pre_action": dict(PRE),
            "label_path_exposure": path,
            "label_security_exposure": security,
            "label_absolute_failed_requests": failures,
            "fault": "loss", "target": "enforcer-b",
        })
    return out


def compare(rows, chooser):
    return evaluate_paired(rows, chooser, model_fingerprint=HEX,
                           dataset_fingerprint="b" * 64)


class FakeModel:
    def __init__(self, predictions):
        self.predictions = predictions

    def predict(self, matrix):
        # Last four vector elements are action one-hot as trained by train.py.
        action_index = matrix[0][-4:].index(1.0)
        action = ACTIONS[action_index]
        return [self.predictions[action]]


class PairedDefenseEvaluationTests(unittest.TestCase):
    def test_learned_policy_compared_to_independent_action_outcomes(self):
        r = compare(sample_rows(), lambda context, eligible: "restart_enforcer")
        self.assertEqual(r["status"], "EXPLORATORY_HISTORICAL_ONLY")
        self.assertEqual(r["paired_replays"], 1)
        self.assertEqual(r["policies"]["learned_policy"]["successful_replays"], 1)
        self.assertLess(r["policies"]["learned_policy"]["mean_configuration_cost"],
                        r["policies"]["monitor_only"]["mean_configuration_cost"])
        self.assertFalse(r["prospective_superiority_established"])
        self.assertFalse(r["execution_performed"])

    def test_model_never_sees_outcomes_or_fault_label(self):
        observed = []
        def choose(ctx, eligible):
            observed.append(set(ctx))
            self.assertEqual(set(ctx), {"pre_action", "restart_permitted",
                                        "absolute_error_budget_requests"})
            self.assertNotIn("fault", ctx["pre_action"])
            self.assertNotIn("label_security_exposure", ctx["pre_action"])
            self.assertEqual(tuple(eligible), tuple(ACTIONS))
            return "monitor_only"
        compare(sample_rows(), choose)
        self.assertEqual(len(observed), 1)

    def test_disallowed_restart_is_never_chosen(self):
        r = compare(sample_rows(restart_permitted=False),
                    lambda context, eligible: "restart_enforcer")
        self.assertEqual(r["policies"]["learned_policy"]["prohibited_recommendations"], 1)
        self.assertEqual(r["choices"][0]["selected_actions"]["learned_policy"], "monitor_only")
        self.assertNotIn("restart_enforcer", r["choices"][0]["allowed_actions"])

    def test_abstention_fallback_is_not_free(self):
        r = compare(sample_rows(), lambda context, eligible: None)
        self.assertEqual(r["policies"]["learned_policy"]["abstentions"], 1)
        self.assertEqual(r["choices"][0]["selected_actions"]["learned_policy"], "monitor_only")
        self.assertEqual(r["policies"]["learned_policy"]["mean_configuration_cost"],
                         r["policies"]["monitor_only"]["mean_configuration_cost"])

    def test_pair_incomplete_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete paired"):
            compare(sample_rows()[:-1], lambda *_: "monitor_only")

    def test_duplicate_action_rejected(self):
        rows = sample_rows()
        with self.assertRaisesRegex(ValueError, "Duplicate measured action"):
            compare(rows + [copy.deepcopy(rows[0])], lambda *_: "monitor_only")

    def test_group_split_leakage_rejected(self):
        rows = sample_rows()
        rows += sample_rows(group="test-A", partition="train")
        for row in rows[-4:]:
            row["repeat"] = 1
        with self.assertRaisesRegex(ValueError, "crosses"):
            compare(rows, lambda *_: "monitor_only")

    def test_budget_mismatch_rejected(self):
        rows = sample_rows()
        rows[2]["absolute_error_budget_requests"] = 200
        with self.assertRaisesRegex(ValueError, "Mismatched disruption budgets"):
            compare(rows, lambda *_: "monitor_only")

    def test_oracle_leak_pre_action_rejected(self):
        rows = sample_rows()
        rows[0]["pre_action"]["post_action"] = 0
        with self.assertRaisesRegex(ValueError, "oracle leakage"):
            compare(rows, lambda *_: "monitor_only")

    def test_missing_or_nan_independent_outcome_rejected(self):
        rows = sample_rows()
        rows[0]["label_security_exposure"] = float("nan")
        with self.assertRaisesRegex(ValueError, "Missing or non-finite"):
            compare(rows, lambda *_: "monitor_only")

    def test_no_test_partition_rejected(self):
        rows = sample_rows(partition="train")
        with self.assertRaisesRegex(ValueError, "No held-out"):
            compare(rows, lambda *_: "monitor_only")

    def test_untrusted_model_bundle_rejected(self):
        with self.assertRaisesRegex(ValueError, "calibrated lab-only"):
            make_trusted_lab_model_policy({"schema": "unknown"})

    def test_trusted_model_policy_uses_only_pre_action(self):
        bounds = {k: [float(PRE[k]) - 1., float(PRE[k]) + 1.]
                  for k in PRE if k != "routing_profile"}
        # predict restart as best by cost, not by seeing its actual outcome.
        bundle = {
            "schema": "predict-shield/mechanism-model-bundle/1",
            "training_group_count": 60, "calibration_group_count": 20,
            "not_certified_for_automatic_execution": True,
            "numeric_feature_bounds": bounds,
            "models": {
                "label_path_exposure": FakeModel({
                    "resync_policy": .7, "restart_enforcer": .1,
                    "gateway_restrict": .3, "monitor_only": .9}),
                "label_security_exposure": FakeModel({
                    "resync_policy": 1., "restart_enforcer": 0.,
                    "gateway_restrict": 1., "monitor_only": 1.}),
                "label_absolute_failed_requests": FakeModel({
                    "resync_policy": 0., "restart_enforcer": 5.,
                    "gateway_restrict": 15., "monitor_only": 0.}),
            }
        }
        chooser = make_trusted_lab_model_policy(bundle)
        r = compare(sample_rows(), chooser)
        self.assertEqual(r["choices"][0]["selected_actions"]["learned_policy"], "restart_enforcer")

    def test_ood_learned_policy_abstains(self):
        bounds = {k: [0., 1.] for k in PRE if k != "routing_profile"}
        bundle = {
            "schema": "predict-shield/mechanism-model-bundle/1",
            "training_group_count": 60, "calibration_group_count": 20,
            "not_certified_for_automatic_execution": True,
            "numeric_feature_bounds": bounds,
            "models": {k: FakeModel({a: 0. for a in ACTIONS})
                       for k in ("label_path_exposure", "label_security_exposure",
                                 "label_absolute_failed_requests")},
        }
        r = compare(sample_rows(), make_trusted_lab_model_policy(bundle))
        self.assertEqual(r["policies"]["learned_policy"]["abstentions"], 1)
        self.assertEqual(r["choices"][0]["selected_actions"]["learned_policy"], "monitor_only")


if __name__ == "__main__":
    unittest.main()
