"""Checkpoint integrity and incomplete-outcome controls.

Tests deliberately use a fake provider. No AI accuracy is measured here.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from run_ai_rule_suggestion import Recorder, write_checkpoint


class FakeModel:
    name = "fixture-only-NOT-AI"

    def complete(self, system, prompt):
        return '{"rules":[],"uncertainty":"fixture"}'


class FailingModel:
    name = "fixture-failure-NOT-AI"

    def complete(self, system, prompt):
        raise RuntimeError("simulated model failure")


class CheckpointTests(unittest.TestCase):
    def test_atomic_checkpoint_and_no_false_efficacy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "checkpoint.json"
            value = {"schema": "predict-shield/ai-rule-development-checkpoint/1",
                     "status": "INCOMPLETE", "held_out_seen": False,
                     "held_out_detection_rate": None, "completed_evaluation": False}
            write_checkpoint(path, value)
            self.assertEqual(json.loads(path.read_text()), value)
            self.assertFalse(path.with_name(path.name + ".tmp").exists())
            value["status"] = "RULES_FROZEN_HELD_OUT_NOT_SCORED"
            write_checkpoint(path, value)
            self.assertEqual(json.loads(path.read_text())["status"], value["status"])

    def test_exchange_callback_runs_on_reply(self):
        observed = []
        model = Recorder(FakeModel(), on_exchange=lambda records: observed.append(list(records)))
        self.assertEqual(json.loads(model.complete("system", "prompt"))["rules"], [])
        self.assertEqual(len(observed), 1)
        self.assertEqual(len(observed[0]), 1)
        self.assertIn("prompt_sha256", observed[0][0])
        self.assertIsNotNone(observed[0][0]["reply"])

    def test_exception_is_saved_for_auditors_not_reported_as_success(self):
        seen = []
        model = Recorder(FailingModel(), on_exchange=lambda records: seen.append(list(records)))
        with self.assertRaisesRegex(RuntimeError, "simulated model failure"):
            model.complete("system", "prompt")
        self.assertEqual(len(seen), 1)
        self.assertIsNone(seen[0][0]["reply"])
        self.assertIn("simulated model failure", seen[0][0]["error"])


if __name__ == "__main__":
    unittest.main()
