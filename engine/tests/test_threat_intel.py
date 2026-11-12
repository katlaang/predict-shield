"""Tests for offline temporally constrained threat-context baseline."""
import json
import tempfile
import unittest
from pathlib import Path

from predict_shield.threat_intel import build_report, prioritize, read_epss, read_kev


class ThreatIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.epss = root / "epss.csv"
        self.epss.write_text("#model_version: v2026\ncve,epss,percentile\n"
                             "CVE-2026-0001,0.8,0.9\nCVE-2026-0002,0.1,0.3\n")
        self.kev = root / "kev.json"
        self.kev.write_text(json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2026-0001", "dateAdded": "2026-11-01"},
            {"cveID": "CVE-2026-0002", "dateAdded": "2026-11-20"}]}))
        self.assets = root / "assets.json"
        self.assets.write_text(json.dumps([
            {"asset_id": "gateway-1", "cve": "CVE-2026-0001", "criticality": 1.0, "exposure": 0.7},
            {"asset_id": "node-2", "cve": "CVE-2026-0002", "criticality": 0.5, "exposure": 0.2}]))
        self.root = root

    def test_rejects_future_snapshot_for_both_sources(self):
        with self.assertRaisesRegex(ValueError, "look-ahead"):
            read_epss(self.epss, "2026-11-12", "2026-11-11")
        with self.assertRaisesRegex(ValueError, "look-ahead"):
            read_kev(self.kev, "2026-11-12", "2026-11-11")

    def test_kev_filters_later_additions(self):
        kev, _ = read_kev(self.kev, "2026-11-11", "2026-11-11")
        self.assertIn("CVE-2026-0001", kev)
        self.assertNotIn("CVE-2026-0002", kev)

    def test_rank_and_provenance(self):
        report = build_report(str(self.epss), "2026-11-11", str(self.kev),
                              "2026-11-11", str(self.assets), "2026-11-11")
        self.assertEqual(report["rows"][0]["cve"], "CVE-2026-0001")
        self.assertEqual(len(report["source_provenance"][0]["sha256"]), 64)
        self.assertFalse(report["rows"][0]["calibrated_probability"])
        self.assertFalse(report["rows"][1]["kev_known_exploited"])

    def test_missing_epss_is_unknown_not_zero(self):
        ranked = prioritize([{"asset_id": "a", "cve": "CVE-2026-9999",
                              "criticality": 1, "exposure": 1}],
                            {}, {}, "2026-11-11")
        self.assertIsNone(ranked[0]["heuristic_score"])
        self.assertEqual(ranked[0]["status"], "INSUFFICIENT_EPSS")

    def test_invalid_and_duplicate_values_rejected(self):
        self.epss.write_text("cve,epss\nCVE-2026-0001,1.5\n")
        with self.assertRaises(ValueError):
            read_epss(self.epss, "2026-11-11", "2026-11-11")
        with self.assertRaises(ValueError):
            prioritize([
                {"asset_id": "a", "cve": "CVE-2026-1", "criticality": 1, "exposure": 1},
                {"asset_id": "a", "cve": "CVE-2026-1", "criticality": 1, "exposure": 1}],
                {}, {}, "2026-11-11")


if __name__ == "__main__":
    unittest.main()
