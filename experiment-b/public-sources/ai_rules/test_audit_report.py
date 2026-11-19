"""Independent audit arithmetic, failure and zero-detection controls."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from audit_report import inspect, _canonical_sha


def example():
    reg = {
        "commit": "test-commit",
        "targets": ["T1112", "T1003.001"],
        "development": [
            {"file": "dev-one", "technique": "T1112"},
            {"file": "dev-two", "technique": "T1003.001"},
        ],
        "held_out": [
            {"file": "one", "technique": "T1112"},
            {"file": "two", "technique": "T1003.001"},
        ],
    }
    raw = json.dumps(reg).encode()
    rules = [{"rule_id": "ai-t1112-1", "technique": "T1112", "event_type": "registry_set"}]
    sha = _canonical_sha(rules)
    report = {
        "schema": "predict-shield/ai-rule-suggestion/1",
        "model": "ollama:verified-fixture-model",
        "split_commit": reg["commit"],
        "split_sha256": hashlib.sha256(raw).hexdigest(),
        "accepted_rules": rules,
        "accepted_set_sha256": sha,
        "model_exchanges": [{"prompt_sha256": "test"}, {"prompt_sha256": "test2"}],
        "techniques": {
            "T1112": {"gate": [{"accepted": True, "rule": rules[0]}]},
            "T1003.001": {"gate": []},
        },
        "held_out": [
            {"file": "one", "technique": "T1112", "events": 7, "detected": True,
             "own_rule_hits": 2, "other_technique_alerts": []},
            {"file": "two", "technique": "T1003.001", "events": 9, "detected": False,
             "own_rule_hits": 0, "other_technique_alerts": []},
        ],
        "summary": {
            "held_out_recordings": 2,
            "held_out_detected": 1,
            "held_out_events": 16,
            "accepted_rules": 1,
            "accepted_set_sha256": sha,
            "recordings_with_other_technique_alerts": 0,
            "by_technique": {
                "T1112": {"held_out_recordings": 1, "detected": 1, "accepted_rules": 1},
                "T1003.001": {"held_out_recordings": 1, "detected": 0, "accepted_rules": 0},
            },
        },
    }
    return report, reg, raw


class AuditTests(unittest.TestCase):
    def test_correct_counts_and_unproven_claims(self):
        report, reg, raw = example()
        a = inspect(report, reg, raw)
        self.assertTrue(a["report_structurally_consistent"], a["issues"])
        self.assertEqual(a["reported_scenario_detection"]["detected"], 1)
        self.assertEqual(a["reported_scenario_detection"]["denominator"], 2)
        self.assertFalse(a["event_level_detection_recall_established"])
        self.assertFalse(a["false_positive_rate_established"])

    def test_zero_success_still_structurally_valid(self):
        report, reg, raw = example()
        report["accepted_rules"] = []
        report["accepted_set_sha256"] = _canonical_sha([])
        report["techniques"]["T1112"]["gate"] = []
        report["held_out"][0]["detected"] = False
        report["held_out"][0]["own_rule_hits"] = 0
        report["summary"]["held_out_detected"] = 0
        report["summary"]["accepted_rules"] = 0
        report["summary"]["accepted_set_sha256"] = _canonical_sha([])
        report["summary"]["by_technique"]["T1112"]["detected"] = 0
        report["summary"]["by_technique"]["T1112"]["accepted_rules"] = 0
        a = inspect(report, reg, raw)
        self.assertTrue(a["report_structurally_consistent"], a["issues"])
        self.assertEqual(a["reported_scenario_detection"]["detected"], 0)

    def test_undercount_and_missing_record_not_accepted(self):
        report, reg, raw = example()
        report["held_out"] = report["held_out"][:1]
        self.assertFalse(inspect(report, reg, raw)["report_structurally_consistent"])
        report, reg, raw = example()
        report["summary"]["held_out_detected"] = 2
        self.assertFalse(inspect(report, reg, raw)["report_structurally_consistent"])

    def test_invalid_trusted_source_and_freeze_proof_detected(self):
        report, reg, raw = example()
        report["split_sha256"] = "0" * 64
        self.assertFalse(inspect(report, reg, raw)["report_structurally_consistent"])
        report, reg, raw = example()
        report["accepted_set_sha256"] = "0" * 64
        self.assertFalse(inspect(report, reg, raw)["report_structurally_consistent"])

    def test_model_stub_or_no_evaluation_rejected(self):
        report, reg, raw = example()
        report["model"] = "stub-no-model"
        self.assertFalse(inspect(report, reg, raw)["report_structurally_consistent"])
        report, reg, raw = example()
        report["held_out"][0]["detected"] = "yes"
        self.assertFalse(inspect(report, reg, raw)["report_structurally_consistent"])

    def test_false_benign_claim_not_inferred(self):
        report, reg, raw = example()
        report["held_out"][1]["other_technique_alerts"] = [{"rule": "unexpected"}]
        report["summary"]["recordings_with_other_technique_alerts"] = 1
        a = inspect(report, reg, raw)
        self.assertTrue(a["report_structurally_consistent"], a["issues"])
        self.assertEqual(a["recordings_with_unrelated_technique_alerts"], 1)
        self.assertFalse(a["false_positive_rate_established"])


if __name__ == "__main__":
    unittest.main()
