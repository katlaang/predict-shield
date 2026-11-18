"""Repeatable manifest tests; no Java container or external service required."""
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from generate_manifest import (
    ACTIONS, FAULTS, SCHEMA_VERSION, generate_configurations,
    generate_plan, validate_plan, write_manifest,
)


class ExperimentManifestTests(unittest.TestCase):
    """Ensure the lab design cannot silently leak data or invent outcomes."""

    def test_exact_configuration_and_trial_counts(self):
        """The agreed 100 x 4 x 3 plan produces exactly 1,200 planned runs."""
        configurations, trials = generate_plan()
        self.assertEqual(len(configurations), 100)
        self.assertEqual(len(trials), 1200)
        self.assertEqual(Counter(c["split"] for c in configurations),
                         {"train": 60, "calibration": 20, "test": 20})

    def test_repeatable_with_same_seed(self):
        """Identical experiment seeds yield bit-for-bit identical plan objects."""
        self.assertEqual(generate_plan(123456), generate_plan(123456))

    def test_seed_change_changes_conditions(self):
        """A new declared seed produces different sampled conditions."""
        self.assertNotEqual(generate_configurations(2), generate_configurations(3))

    def test_four_actions_replayed_with_identical_starting_seed(self):
        """Every comparable action within a repeat shares a starting seed."""
        _, trials = generate_plan()
        for i in range(0, len(trials), 4):
            group = trials[i:i + 4]
            self.assertEqual({t["action_id"] for t in group}, set(ACTIONS))
            self.assertEqual(len({t["trial_seed"] for t in group}), 1)
            self.assertEqual(len({t["configuration_id"] for t in group}), 1)
            self.assertEqual(len({t["repeat"] for t in group}), 1)

    def test_configuration_group_remains_in_one_partition(self):
        """Repeated conditions cannot appear across model evaluation splits."""
        configs, trials = generate_plan()
        lookup = {c["configuration_id"]: c["split"] for c in configs}
        self.assertTrue(all(t["split"] == lookup[t["configuration_id"]] for t in trials))

    def test_generator_never_populates_outcomes(self):
        """Planned runs must never be mistaken for observed or predicted outcomes."""
        _, trials = generate_plan()
        for t in trials:
            self.assertEqual(t["status"], "PLANNED_NOT_EXECUTED")
            self.assertIsNone(t["oracle_record_id"])
            self.assertIsNone(t["verification_record_id"])
            self.assertIsNone(t["operational_outcome_record_id"])
            self.assertIsNone(t["pre_action_prediction_record_id"])

    def test_generated_configurations_fit_java_validation_bounds(self):
        """Every generated value is accepted by the Java scenario record limits."""
        configs = generate_configurations()
        for c in configs:
            self.assertIn(c["fault_family"], FAULTS)
            self.assertTrue(2 <= c["enforcement_points"] <= 8)
            self.assertTrue(1 <= c["stale_points"] < c["enforcement_points"])
            self.assertTrue(50 <= c["cache_ttl_ms"] <= 5000)
            self.assertTrue(0 <= c["propagation_delay_ms"] <= 5000)
            self.assertTrue(1 <= c["traffic_rps"] <= 1000)
            self.assertTrue(1 <= c["dependency_depth"] <= 6)
            self.assertTrue(1 <= c["redundancy"] <= c["enforcement_points"])

    def test_manifest_roundtrip_and_metadata(self):
        """Writer records the plan accurately without claiming any measurements."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            metadata = write_manifest(output, 77)
            self.assertEqual(metadata["status"], "PLAN_ONLY_NO_ACTIONS_EXECUTED")
            self.assertFalse(metadata["measurements_generated"])
            lines = (output / "trials.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1200)
            self.assertEqual(json.loads(lines[0])["schema_version"], SCHEMA_VERSION)
            self.assertEqual(
                json.loads((output / "manifest.json").read_text(encoding="utf-8"))["trial_count"],
                1200,
            )

    def test_invalid_plan_fails_closed(self):
        """Altered identifiers or missing trials are rejected during generation."""
        configs, trials = generate_plan()
        with self.assertRaises(ValueError):
            validate_plan(configs, trials[:-1])


if __name__ == "__main__":
    unittest.main()
