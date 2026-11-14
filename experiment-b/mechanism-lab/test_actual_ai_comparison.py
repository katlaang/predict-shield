"""Synthetic UNIT fixtures, not measured physical results or AI effectiveness."""
import tempfile
import unittest
from pathlib import Path

from ai_comparison_plan import build, validate, digest, COUNTS
from actual_ai_comparison import evaluate, read_measured
from decision_eval import ACTIONS


def synthetic_rows():
    configs, _ = build()
    rows = []
    for cfg in configs:
        for action in ACTIONS:
            # Artificial labels exist only to test grouping, model fitting,
            # and report contracts. They must never become public results.
            value = float(action != "monitor_only")
            rows.append({
                "group": cfg["configuration_id"],
                "partition": cfg["partition"],
                "repeat": 0,
                "action": action,
                "restart_permitted": cfg["restart_permitted"],
                "absolute_error_budget_requests": 25,
                "pre_action": {
                    "cache_ttl_ms": cfg["cache_ttl_ms"],
                    "requested_rps": cfg["requested_rps"],
                    "gateway_visible_enforcer_count": cfg["visible_enforcement_processes"],
                    "initial_gateway_allowed_fraction": 0.1,
                    "routing_profile": cfg["routing_profile"],
                },
                "label_path_exposure": value,
                "label_security_exposure": value,
                "label_absolute_failed_requests": value * 2,
            })
    return rows


class AIPhysicalPilotTest(unittest.TestCase):
    def test_plan_frozen_before_outcomes_and_balanced(self):
        c1, t1 = build()
        c2, t2 = build()
        self.assertEqual((c1, t1), (c2, t2))
        self.assertEqual(digest(c1, t1), digest(c2, t2))
        self.assertEqual(len(c1), 24)
        self.assertEqual(len(t1), 96)
        self.assertEqual({p: sum(x["partition"] == p for x in c1)
                          for p in COUNTS}, COUNTS)
        self.assertEqual(len({(x["fault_mode"], x["complexity_stratum"])
                              for x in c1}), 12)
        self.assertTrue(all(t["execution_status"] == "PLANNED_NOT_EXECUTED"
                            for t in t1))

    def test_plan_rejects_missing_action(self):
        cfg, trials = build()
        with self.assertRaisesRegex(ValueError, "96 four-action"):
            validate(cfg, trials[:-1])

    def test_cannot_learn_without_actual_stream_files(self):
        with tempfile.TemporaryDirectory() as path:
            with self.assertRaisesRegex(ValueError, "Four streams"):
                read_measured(Path(path))

    def test_synthetic_fitting_contract_is_not_a_scientific_claim(self):
        rows = synthetic_rows()
        report = evaluate(rows, {
            "source_commit_sha": "a" * 40,
            "registration_sha256": "b" * 64,
            "executed_physical_action_replays": 96,
            "independently_configured_groups": 24,
            "four_streams_per_trial_verified": False,
            "oracle_used_in_model_inputs": False,
        })
        self.assertEqual(report["train_groups"], 12)
        self.assertEqual(report["calibration_groups"], 6)
        self.assertEqual(report["heldout_groups"], 6)
        self.assertEqual(len(report["test_group_decisions"]), 6)
        self.assertTrue(report["exploratory_only_not_superiority_proof"])
        self.assertFalse(report["critical_infrastructure_field_evidence"])
        self.assertIn(report["locked_comparator_selected_using_calibration_only"],
                      report["heldout_per_comparator_mean_regret"])

    def test_no_missing_label_or_action_can_be_hidden(self):
        rows = synthetic_rows()
        rows.pop()
        with self.assertRaisesRegex(ValueError, "Missing measured physical action"):
            evaluate(rows, {})

    def test_duplicate_configuration_arm_fails(self):
        rows = synthetic_rows()
        rows.append(dict(rows[0]))
        with self.assertRaisesRegex(ValueError, "Duplicate action"):
            evaluate(rows, {})


if __name__ == "__main__":
    unittest.main()
