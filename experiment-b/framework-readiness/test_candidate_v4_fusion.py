import unittest

from candidate_v4_fusion import calibrate_gates, evaluate_gates, SIGNALS


def benign_rows(n=2000):
    return [dict(role="calibration", label="benign",
                 truth_basis="independently_reviewed_event",
                 request_novelty=0.0, host_novelty=0.0,
                 response_shift=50.0, learned_anomaly=0.05,
                 fused_statistic=25.7)
            for _ in range(n)]


class CandidateV4Tests(unittest.TestCase):
    def test_saturated_response_does_not_suppress_strong_host_novelty(self):
        data = benign_rows()
        cfg = calibrate_gates(data)
        obs = dict(data[0])
        obs["host_novelty"] = 1.0
        result = evaluate_gates(obs, cfg)
        self.assertTrue(result["alert"])
        self.assertIn("host_novelty", result["evidence"])
        self.assertNotIn("response_shift", result["evidence"])

    def test_strong_learned_anomaly_can_alert_independently(self):
        cfg = calibrate_gates(benign_rows())
        obs = dict(benign_rows(1)[0], learned_anomaly=0.95)
        result = evaluate_gates(obs, cfg)
        self.assertEqual(result["status"], "ALERT")
        self.assertIn("learned_anomaly", result["evidence"])

    def test_empirical_union_budget_is_bounded(self):
        data = benign_rows()
        for i, row in enumerate(data):
            for k in SIGNALS:
                row[k] = float(i)
        cfg = calibrate_gates(data, alert_budget=0.005)
        self.assertLessEqual(cfg["calibration_alert_rate"], 0.005)

    def test_missing_features_abstain_instead_of_false_no_alert(self):
        cfg = calibrate_gates(benign_rows())
        obs = dict(benign_rows(1)[0])
        del obs["request_novelty"]
        result = evaluate_gates(obs, cfg)
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertFalse(result["alert"])

    def test_reject_mislabeled_calibration(self):
        rows = benign_rows()
        rows[0]["label"] = "attack"
        with self.assertRaisesRegex(ValueError, "benign-only"):
            calibrate_gates(rows)

    def test_reject_small_calibration(self):
        with self.assertRaises(ValueError):
            calibrate_gates(benign_rows(100))

    def test_reject_nonfinite_evidence(self):
        rows = benign_rows()
        rows[0]["learned_anomaly"] = float("inf")
        with self.assertRaises(ValueError):
            calibrate_gates(rows)

    def test_fully_saturated_benign_stays_quiet(self):
        rows = benign_rows()
        cfg = calibrate_gates(rows)
        self.assertEqual(cfg["calibration_alerts"], 0)
        self.assertEqual(evaluate_gates(rows[0], cfg)["status"], "NO_ALERT")


if __name__ == "__main__":
    unittest.main()
