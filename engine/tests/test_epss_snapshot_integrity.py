"""Historical EPSS archive ingestion integrity tests."""
import gzip
import tempfile
import unittest
from pathlib import Path

from predict_shield.threat_intel import read_epss


class ArchivedEPSSIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_official_style_gzip_and_embedded_date(self):
        raw = (b"#model_version:v2026.06.15,score_date:2026-10-01T00:00:00Z\n"
               b"cve,epss,percentile\nCVE-2024-0001,0.25,0.7\n")
        file = self.root / "epss_scores-2026-10-01.csv.gz"
        file.write_bytes(gzip.compress(raw))
        data, meta = read_epss(file, "2026-10-01", "2026-10-02")
        self.assertEqual(data["CVE-2024-0001"], 0.25)
        self.assertEqual(meta["embedded_score_date"], "2026-10-01")
        self.assertTrue(meta["compressed_gzip"])

    def test_reject_newer_feed_mislabeled_as_old(self):
        file = self.root / "epss.csv.gz"
        file.write_bytes(gzip.compress(
            b"#model_version:v2026.06.15,score_date:2026-11-10T00:00:00Z\n"
            b"cve,epss\nCVE-2024-0001,0.2\n"))
        with self.assertRaisesRegex(ValueError, "differs"):
            read_epss(file, "2026-10-01", "2026-10-02")

    def test_legacy_headerless_csv_allowed_but_date_unverified(self):
        file = self.root / "legacy.csv"
        file.write_text("cve,epss\nCVE-2024-0001,0.5\n")
        _, meta = read_epss(file, "2026-10-01", "2026-10-02")
        self.assertIsNone(meta["embedded_score_date"])


if __name__ == "__main__":
    unittest.main()
