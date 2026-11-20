"""Unit checks use synthetic report-shaped arithmetic, NOT new benchmark outcomes."""
import importlib.util
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
