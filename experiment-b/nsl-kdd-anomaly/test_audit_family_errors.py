"""Unit checks use synthetic report-shaped arithmetic, NOT new benchmark outcomes."""
import importlib.util
import hashlib
import json
import pathlib
import unittest

MODULE = pathlib.Path(__file__).with_name("audit_family_errors.py")
spec = importlib.util.spec_from_file_location("audit_family_errors", MODULE)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def fixture():
    return {
        "schema": audit_module.SCHEMA,
        "TP": 8580, "FN": 4253, "FP": 274, "TN": 9437, "test_rows": 22544,
        "fit_normal_only": True,
        "external_current_critical_infrastructure_effectiveness_established": False,
        "test_attack_recall": 8580 / 12833,
        "test_false_positive_rate": 274 / 9711,
        "test_precision": 8580 / 8854,
        "unseen_attack_type_recall": 0.0,
        "operational_attack_detection_established": False,
        "zero_day_detection_established": False,
        "per_attack_type": {
            "alpha": {"tested": 8580, "detected": 8580},
            "beta": {"tested": 4253, "detected": 0}
        },
        "unseen_attack_type_names": ["beta"],
        "unseen_attack_type_rows": 4253,
        "unseen_attack_type_TP": 0,
        "unseen_attack_type_FN": 4253
    }


class AuditTests(unittest.TestCase):
    def test_counts_and_zero_recall(self):
        result = audit_module.audit(fixture())
        self.assertEqual(result["attacks_missed"], 4253)
        self.assertEqual(result["zero_recall_families"][0]["attack_type"], "beta")
        self.assertFalse(result["new_holdout"])
        self.assertFalse(result["threshold_changed"])

    def test_raw_bytes_fingerprint_matches_file(self):
        report = fixture()
        raw = json.dumps(report, indent=2).encode()
        result = audit_module.audit(report, raw_bytes=raw)
        self.assertEqual(result["raw_source_file_sha256"], hashlib.sha256(raw).hexdigest())

    def test_reject_raw_bytes_mismatch(self):
        with self.assertRaises(ValueError):
            audit_module.audit(fixture(), raw_bytes=b'{}')

    def test_missed_shares_and_order(self):
        report = fixture()
        report["per_attack_type"] = {
            "alpha": {"tested": 8580, "detected": 8580},
            "beta": {"tested": 4000, "detected": 0},
            "gamma": {"tested": 253, "detected": 0}
        }
        report["unseen_attack_type_names"] = ["beta", "gamma"]
        result = audit_module.audit(report)
        ranked = result["families_ranked_by_missed_count"]
        self.assertEqual([r["attack_type"] for r in ranked], ["beta", "gamma", "alpha"])
        self.assertAlmostEqual(sum(r["share_of_all_missed_attacks"] for r in ranked), 1.0)

    def test_wrong_schema(self):
        report = fixture()
        report["schema"] = "some-other-producer"
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_detected_cannot_exceed_tested(self):
        report = fixture()
        report["per_attack_type"]["beta"]["detected"] = 4254
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_family_cannot_have_zero_tested(self):
        report = fixture()
        report["per_attack_type"]["beta"]["tested"] = 0
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_unseen_totals_consistent(self):
        report = fixture()
        report["unseen_attack_type_FN"] = 4252
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_empty_unseen_list(self):
        report = fixture()
        report["unseen_attack_type_names"] = []
        report["unseen_attack_type_rows"] = 0
        report["unseen_attack_type_FN"] = 0
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_missing_unseen_list(self):
        report = fixture()
        del report["unseen_attack_type_names"]
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_zero_day_claim_must_remain_false(self):
        report = fixture()
        report["zero_day_detection_established"] = True
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_critical_infrastructure_claim_must_remain_false(self):
        report = fixture()
        report["external_current_critical_infrastructure_effectiveness_established"] = True
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_modified_rates(self):
        for field in ("test_attack_recall", "test_false_positive_rate",
                      "test_precision", "unseen_attack_type_recall"):
            report = fixture()
            report[field] = 0.99
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit_module.audit(report)

    def test_reject_inconsistent_family_totals(self):
        report = fixture()
        report["per_attack_type"]["beta"]["tested"] = 4252
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_inconsistent_unseen_roster(self):
        report = fixture()
        report["unseen_attack_type_names"] = ["alpha"]
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_false_field_claim(self):
        report = fixture()
        report["operational_attack_detection_established"] = True
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_modified_frozen_counts(self):
        report = fixture()
        report["TP"] += 1
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_missing_family_evidence(self):
        report = fixture()
        report.pop("per_attack_type")
        with self.assertRaises(ValueError):
            audit_module.audit(report)

    def test_reject_negative_and_boolean_counts(self):
        for invalid in (-1, True):
            report = fixture()
            report["per_attack_type"]["beta"]["detected"] = invalid
            with self.assertRaises(ValueError):
                audit_module.audit(report)


if __name__ == "__main__":
    unittest.main()
