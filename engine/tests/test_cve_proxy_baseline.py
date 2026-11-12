import json
import tempfile
import unittest
from pathlib import Path

from predict_shield.cve_proxy_baseline import evaluate


class CVEProxyBaselineTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        root = Path(self.t.name)
        self.epss = root / "epss.csv"
        self.epss.write_text("#model_version:test,score_date:2026-10-01T00:00:00Z\n"
                             "cve,epss\nCVE-2026-0001,0.9\nCVE-2026-0002,0.2\n"
                             "CVE-2026-0003,0.7\n")
        self.before = root / "before.json"
        self.before.write_text(json.dumps({"vulnerabilities": [
            {"cveID":"CVE-2026-0003","dateAdded":"2026-09-22"}]}))
        self.after = root / "after.json"
        self.after.write_text(json.dumps({"vulnerabilities": [
            {"cveID":"CVE-2026-0003","dateAdded":"2026-09-22"},
            {"cveID":"CVE-2026-0001","dateAdded":"2026-10-15"},
            {"cveID":"CVE-2026-9999","dateAdded":"2026-10-17"},
            {"cveID":"CVE-2026-0002","dateAdded":"2026-12-17"}]}))
        self.args = {"epss_path":str(self.epss),"epss_date":"2026-10-01",
                     "kev_before_path":str(self.before),"kev_before_date":"2026-10-01",
                     "kev_after_path":str(self.after),"kev_after_date":"2026-11-10",
                     "as_of":"2026-10-02","horizon_days":30,"ks":(1,2)}

    def test_future_kev_addition_proxy_not_exploitation(self):
        r = evaluate(**self.args)
        self.assertEqual(r["eligible_cves"], 2)
        self.assertEqual(r["future_kev_additions_all"], 2)
        self.assertEqual(r["future_kev_additions_with_prior_epss"], 1)
        self.assertEqual(r["future_kev_additions_missing_prior_epss"], 1)
        self.assertEqual(r["precision_at_k"]["1"], 1)
        self.assertEqual(r["average_precision"], 1)
        self.assertFalse(r["trained_ai_model"])

    def test_future_feature_rejected(self):
        with self.assertRaisesRegex(ValueError, "look-ahead"):
            evaluate(**{**self.args,"epss_date":"2026-11-01"})

    def test_no_positive_has_null_ap(self):
        self.after.write_text(json.dumps({"vulnerabilities":[]}))
        r = evaluate(**self.args)
        self.assertIsNone(r["average_precision"])
        self.assertEqual(r["precision_at_k"]["1"],0.0)


if __name__ == "__main__":
    unittest.main()
