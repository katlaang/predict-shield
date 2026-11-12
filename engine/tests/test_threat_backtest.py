import json
import tempfile
import unittest
from pathlib import Path

from predict_shield.threat_backtest import average_precision, evaluate_proxy


class TemporalBacktestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.ep = root / "epss.csv"
        self.ep.write_text("cve,epss\nCVE-2026-0001,0.9\n"
                           "CVE-2026-0002,0.1\nCVE-2026-0003,0.6\n")
        self.before = root / "before.json"
        self.before.write_text(json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2026-0003", "dateAdded": "2026-10-15"}]}))
        self.after = root / "after.json"
        self.after.write_text(json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2026-0003", "dateAdded": "2026-10-15"},
            {"cveID": "CVE-2026-0001", "dateAdded": "2026-11-20"},
            {"cveID": "CVE-2026-0002", "dateAdded": "2027-01-03"}]}))
        self.assets = root / "assets.json"
        self.assets.write_text(json.dumps([
            {"asset_id": "a", "cve": "CVE-2026-0001", "criticality": 0.7, "exposure": 0.8},
            {"asset_id": "b", "cve": "CVE-2026-0002", "criticality": 0.5, "exposure": 0.5},
            {"asset_id": "c", "cve": "CVE-2026-0003", "criticality": 1.0, "exposure": 1.0},
        ]))
        self.kwargs = dict(epss_file=str(self.ep), epss_date="2026-11-01",
                           kev_before_file=str(self.before), kev_before_date="2026-11-01",
                           kev_after_file=str(self.after), kev_after_date="2026-12-10",
                           assets_file=str(self.assets), as_of="2026-11-01",
                           horizon_days=30, top_k=1)

    def test_only_new_kev_additions_are_positive(self):
        report = evaluate_proxy(**self.kwargs)
        self.assertEqual(report["candidate_asset_cve_pairs"], 2)
        self.assertEqual(report["positive_pairs"], 1)
        self.assertEqual(report["results"]["epss_only"]["average_precision"], 1.0)
        self.assertEqual(report["results"]["epss_only"]["precision_at_k"], 1.0)
        self.assertFalse(report["trained_ai_model"])

    def test_rejects_future_feature_snapshot(self):
        kw = dict(self.kwargs, epss_date="2026-11-02")
        with self.assertRaisesRegex(ValueError, "look-ahead"):
            evaluate_proxy(**kw)

    def test_rejects_outcome_snapshot_before_horizon(self):
        kw = dict(self.kwargs, kev_after_date="2026-11-15")
        with self.assertRaisesRegex(ValueError, "bracket"):
            evaluate_proxy(**kw)

    def test_no_positive_metrics_explicitly_unknown(self):
        self.after.write_text(json.dumps({"vulnerabilities": []}))
        report = evaluate_proxy(**self.kwargs)
        self.assertEqual(report["positive_pairs"], 0)
        self.assertIsNone(report["results"]["epss_only"]["average_precision"])

    def test_average_precision_rejects_misaligned_arrays(self):
        with self.assertRaises(ValueError):
            average_precision([True], [])


if __name__ == "__main__":
    unittest.main()
