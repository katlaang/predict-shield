"""Synthetic fixture contract tests only. No real-world detection rates are claimed."""
import copy
import json
import unittest

from test_fit_evaluate import CTU13Tests
from unsupervised_detector import _cutoff, fit_and_evaluate, detect_unlabeled


class UnsupervisedFlowDetectorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = CTU13Tests("test_only_predefined_flow_features")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def fitted(self):
        data = self.fixture.manifest
        return fit_and_evaluate(data, json.dumps(data).encode(), self.fixture.root)

    def test_learns_normal_only_without_any_signature_rules(self):
        model, bundle, report = self.fitted()
        self.assertEqual(report["train_known_botnet_flows_used"], 0)
        self.assertFalse(bundle["explicit_signatures_used_for_detection"])
        self.assertFalse(bundle["production_deployable"])
        self.assertFalse(report["independently_authenticated_labels"])
        self.assertEqual(report["test_flows"], 4)
        self.assertEqual(sum(report[k] for k in ("TP", "FP", "FN", "TN")), 4)

    def test_freezing_threshold_does_not_read_test_labels(self):
        model, bundle, report = self.fitted()
        path = self.fixture.root / "scenario-unseen.binetflow"
        text = path.read_text()
        path.write_text(text.replace("From-Botnet-V42", "From-Normal-V42", 1))
        import hashlib
        self.fixture.entries[-1]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        _, changed_bundle, changed_report = self.fitted()
        self.assertEqual(bundle["threshold"], changed_bundle["threshold"])
        self.assertEqual(report["calibration_false_positives"],
                         changed_report["calibration_false_positives"])

    def test_unlabeled_scoring_never_authorizes_actions(self):
        model, bundle, _ = self.fitted()
        records = [{"Dur": 50.0, "TotPkts": 500, "TotBytes": 45000,
                    "SrcBytes": 20000, "Proto": "tcp"}]
        scored = detect_unlabeled(model, bundle, records)
        self.assertEqual(len(scored), 1)
        self.assertIn("investigation_candidate", scored[0])
        self.assertFalse(scored[0]["attack_confirmed"])
        self.assertFalse(scored[0]["defensive_action_authorized"])
        self.assertEqual(scored[0]["detection_method"], "learned_unsupervised_anomaly")

    def test_attack_ground_truth_cannot_enter_inference(self):
        model, bundle, _ = self.fitted()
        with self.assertRaisesRegex(ValueError, "ground-truth"):
            detect_unlabeled(model, bundle, [{"Label": "From-Botnet-V42"}])
        with self.assertRaisesRegex(ValueError, "unauthorized"):
            detect_unlabeled(model, dict(bundle, decision_authorized=True), [])

    def test_cutoff_respects_false_alarm_limit_and_ties(self):
        values = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        threshold = _cutoff(values, 0.1)
        self.assertLessEqual(sum(x > threshold for x in values), 1)
        self.assertEqual(_cutoff([0.7] * 10, 0.1), 0.7)
        self.assertEqual(_cutoff(values, 0), 1.0)

    def test_missing_calibration_benign_data_is_not_silently_accepted(self):
        data = self.fixture.manifest
        data["sample_cap_per_label_per_scenario"] = 1
        with self.assertRaisesRegex(ValueError, "insufficient benign"):
            self.fitted()


if __name__ == "__main__":
    unittest.main()
