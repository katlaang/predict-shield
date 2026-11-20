"""Regression tests for prospective cohort preflight; fixtures are fictitious."""
import copy
import unittest
from fresh_cohort_preflight import validate

def entry(name, label, split, group):
    result = {"recording_id": name, "sha256": ({"dev": "a", "attack": "b", "benign": "c"}[name] * 64),
              "publisher": "example", "campaign_id": group,
              "environment_id": "lab", "label": label,
              "source_url": "https://example.invalid/" + name,
              "reviewer_id": "external-reviewer", "split": split}
    if label == "attack":
        result["attack_technique"] = "T0000"
    return result

def manifest():
    return {"recordings": [entry("dev", "attack", "development", "one"),
                           entry("attack", "attack", "test", "two"),
                           entry("benign", "benign", "test", "three")],
            "independent_label_method": "independent pre-registered review",
            "frozen_protocol_sha256": "d" * 64,
            "model_has_access_to_test_content": False}

class FreshCohortPreflightTests(unittest.TestCase):
    def test_valid_structural_preflight_is_not_performance_evidence(self):
        result = validate(manifest(), {})
        self.assertTrue(result["eligible"])
        self.assertFalse(result["fresh_model_performance_established"])
        self.assertTrue(result["manual_source_authentication_required"])

    def test_rejects_historical_hash_reuse(self):
        item = manifest()
        historical = {"held_out": [{"sha256": "b" * 64}]}
        self.assertFalse(validate(item, historical)["eligible"])

    def test_rejects_historical_url_reuse(self):
        item = manifest()
        historical = {"development": [{"url": item["recordings"][1]["source_url"]}]}
        self.assertFalse(validate(item, historical)["eligible"])

    def test_rejects_group_leakage(self):
        item = manifest()
        item["recordings"][1]["campaign_id"] = "one"
        self.assertFalse(validate(item, {})["eligible"])

    def test_rejects_missing_benign_denominator(self):
        item = manifest()
        item["recordings"].pop()
        self.assertFalse(validate(item, {})["eligible"])

    def test_rejects_missing_attack_denominator(self):
        item = manifest()
        item["recordings"][1]["label"] = "benign"
        item["recordings"][1].pop("attack_technique")
        self.assertFalse(validate(item, {})["eligible"])

    def test_rejects_test_data_access(self):
        item = manifest()
        item["model_has_access_to_test_content"] = True
        self.assertFalse(validate(item, {})["eligible"])

    def test_rejects_unidentified_independent_reviewer(self):
        item = manifest()
        item["recordings"][1]["reviewer_id"] = ""
        self.assertFalse(validate(item, {})["eligible"])

if __name__ == "__main__":
    unittest.main()
