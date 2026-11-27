import tempfile
import unittest
from pathlib import Path

from cohort_guard import audit
from frozen_evaluator import evaluate, frozen_threshold
from test_cohort_guard import digest, manifest


def scored_manifest():
    m = manifest(with_population=True)
    for i, r in enumerate(m["rows"]):
        if r["role"] == "calibration":
            r["score"] = float(i % 20)
        elif r["role"] == "test":
            r["score"] = 100.0 if r["label"] == "attack" else float(i % 20)
    return m


class FrozenEvaluationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "fixture.txt").write_text("fixtures", encoding="utf-8")

    def run_eval(self, m):
        return evaluate(m, self.root, model_sha256=digest("frozen-model"))

    def test_threshold_is_set_on_calibration_only(self):
        m = scored_manifest()
        a = self.run_eval(m)
        self.assertEqual(a["test"]["attacks"], 30)
        self.assertEqual(a["test"]["detected"], 30)
        self.assertEqual(a["test"]["benign"], 1000)
        self.assertLessEqual(a["calibration"]["calibration_alert_rate"], .005)
        threshold = a["calibration"]["threshold"]

        for r in m["rows"]:
            if r["role"] == "test":
                r["score"] = -1000.0 if r["label"] == "attack" else 1000.0
        b = self.run_eval(m)
        self.assertEqual(b["calibration"]["threshold"], threshold)
        self.assertEqual(b["test"]["detected"], 0)
        self.assertEqual(b["test"]["false_alerts"], 1000)

    def test_reject_unverified_final_labels(self):
        m = scored_manifest()
        m["rows"][-1]["truth_basis"] = "publisher_scenario"
        with self.assertRaisesRegex(ValueError, "cohort admission failed"):
            self.run_eval(m)

    def test_reject_cross_split_campaign(self):
        m = scored_manifest()
        m["rows"][-1]["capture_group"] = "cal-session"
        with self.assertRaisesRegex(ValueError, "cohort admission failed"):
            self.run_eval(m)

    def test_reject_missing_test_scores(self):
        m = scored_manifest()
        del m["rows"][-1]["score"]
        with self.assertRaisesRegex(ValueError, "test scores missing"):
            self.run_eval(m)

    def test_reject_missing_model_fingerprint(self):
        with self.assertRaisesRegex(ValueError, "model SHA-256"):
            evaluate(scored_manifest(), self.root, model_sha256="unknown")

    def test_reject_insufficient_calibration(self):
        with self.assertRaisesRegex(ValueError, "at least 1000"):
            frozen_threshold([0.1] * 900)

    def test_threshold_calibration_bound_even_with_ties(self):
        c = frozen_threshold([float(i % 100) for i in range(2000)], .005)
        self.assertLessEqual(c["calibration_alert_rate"], .005)

    def test_reject_nan_and_bad_budget(self):
        with self.assertRaises(ValueError):
            frozen_threshold([float("nan")] * 1000)
        with self.assertRaises(ValueError):
            frozen_threshold([1.0] * 1000, 0)


if __name__ == "__main__":
    unittest.main()
