"""No-network tests for the grouped mechanism training-data protocol."""
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from collect import assess_gateway, load_plan, separate_records, write_trial_records
from plan import ACTIONS, PARTITIONS, create_plan, save_plan, validate_plan


class MechanismDatasetTests(unittest.TestCase):
    """Guard execution metadata, oracle segregation and preregistration."""

    def test_plan_is_deterministic_and_grouped(self):
        """Exactly 100 config groups yield 1,200 reproducible planned runs."""
        first = create_plan(98765)
        self.assertEqual(first, create_plan(98765))
        configs, trials = first
        self.assertEqual(len(configs), 100)
        self.assertEqual(len(trials), 1200)
        self.assertEqual(Counter(c["partition"] for c in configs), PARTITIONS)
        for i in range(0, 1200, 4):
            group = trials[i:i+4]
            self.assertEqual({x["action_id"] for x in group}, set(ACTIONS))
            self.assertEqual(len({x["initial_state_seed"] for x in group}), 1)

    def test_no_manifest_oracle_labels(self):
        """Manifest never substitutes for an executed measurement."""
        _, trials = create_plan()
        self.assertTrue(all(x["execution_status"] == "PLANNED_NOT_EXECUTED"
                            and "oracle_result" not in x for x in trials))

    def test_invalid_split_rejected(self):
        """A trial cannot move between train, calibration or held-out test groups."""
        configs, trials = create_plan()
        corrupted = [dict(item) for item in trials]
        corrupted[0]["partition"] = ("test" if trials[0]["partition"] != "test"
                                     else "train")
        with self.assertRaises(ValueError):
            validate_plan(configs, corrupted)

    def test_plan_file_roundtrip(self):
        """Generated plan is persisted without reordering or lost IDs."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            save_plan(path, 123)
            configs, trials = load_plan(path)
            self.assertEqual((configs, trials), create_plan(123))
            metadata = json.loads((path / "protocol.json").read_text())
            self.assertFalse(metadata["outcomes_collected"])

    def test_gateway_deny_is_not_full_verification(self):
        """Clean gateway probes cannot certify an omitted enforcement target."""
        status, _ = assess_gateway([{"http_status": 403} for _ in range(6)])
        self.assertEqual(status, "INDETERMINATE")
        status, _ = assess_gateway([{"http_status": 403}, {"http_status": 200}])
        self.assertEqual(status, "NOT VERIFIED")

    def test_oracle_truth_is_not_copied_to_pre_action_features(self):
        """Separate streams keep the privately observed target truth out of inputs."""
        configs, trials = create_plan()
        c = configs[0]
        trial = trials[0]
        oracle = {
            "inventory_complete": True, "all_revoked_access_denied": False,
            "targets": [{"node": "private-target", "direct_probe_http": 200}]
        }
        probes = [{"http_status": 403, "result": {"decision": "DENY"}}]
        observed = {
            "action": trial["action_id"], "fault_mode": c["fault_mode"],
            "before": {"verifier_gateway_probes": probes, "oracle": oracle},
            "after": {"verifier_gateway_probes": probes, "oracle": oracle},
            "operations": {"attempts": 40, "non_200_requests": 7,
                           "measured_rps": 25.0, "latency_p95_ms": 12.0,
                           "post_window_recovery_wait_seconds": 0.0}
        }
        records = separate_records(c, trial, observed)
        self.assertEqual(records["verification"]["outcome"], "INDETERMINATE")
        self.assertFalse(records["oracle"]["actual_revoked_access_denied"])
        self.assertNotIn("actual_revoked_access_denied",
                         json.dumps(records["pre_action"]))
        self.assertEqual(records["operations"]["failed_requests"], 7)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            write_trial_records(path, records)
            self.assertEqual(len(list((path / "oracle").glob("*.json"))), 1)
            with self.assertRaises(FileExistsError):
                write_trial_records(path, records)

    def test_incomplete_oracle_refuses_a_label(self):
        """Missing oracle inventory never becomes a failed-or-passed label."""
        configs, trials = create_plan()
        c = configs[0]
        t = trials[0]
        sample = {
            "action": t["action_id"], "fault_mode": c["fault_mode"],
            "before": {"verifier_gateway_probes": [], "oracle": {}},
            "after": {"verifier_gateway_probes": [], "oracle": {
                "inventory_complete": False,
                "all_revoked_access_denied": True,
            }},
            "operations": {"attempts": 1, "non_200_requests": 0,
                           "measured_rps": 1, "latency_p95_ms": 1,
                           "post_window_recovery_wait_seconds": 0}
        }
        with self.assertRaises(ValueError):
            separate_records(c, t, sample)


if __name__ == "__main__":
    unittest.main()
