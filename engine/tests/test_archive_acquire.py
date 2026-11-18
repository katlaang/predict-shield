import gzip
import json
import tempfile
import unittest
from pathlib import Path

from predict_shield.archive_acquire import acquire, source_url


class PinnedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = {
            "schema": "predict-shield/dated-threat-archive/1",
            "as_of": "2026-10-02",
            "horizon_days": 30,
            "epss": {"repository": "empiricalsec/epss_scores",
                     "commit": "a" * 40,
                     "path": "2026/epss_scores-2026-10-01.csv.gz",
                     "snapshot_date": "2026-10-01",
                     "commit_observed_date": "2026-10-01"},
            "kev_before": {"repository": "cisagov/kev-data",
                     "commit": "b" * 40,
                     "path": "known_exploited_vulnerabilities.json",
                     "snapshot_date": "2026-10-01",
                     "commit_observed_date": "2026-10-01"},
            "kev_after": {"repository": "cisagov/kev-data",
                     "commit": "c" * 40,
                     "path": "known_exploited_vulnerabilities.json",
                     "snapshot_date": "2026-11-10",
                     "commit_observed_date": "2026-11-10"}}
        epss = gzip.compress(b"#model_version:v2026.06.15,score_date:2026-10-01T00:00:00Z\n"
                             b"cve,epss\nCVE-2026-0001,0.2\n")
        before = json.dumps({"dateReleased": "2026-10-01T18:00:00Z",
                             "vulnerabilities": []}).encode()
        after = json.dumps({"dateReleased": "2026-11-10T18:00:00Z",
                            "vulnerabilities": [{"cveID": "CVE-2026-0001",
                                                 "dateAdded": "2026-10-25"}]}).encode()
        self.by_url = {source_url(self.manifest["epss"]): epss,
                       source_url(self.manifest["kev_before"]): before,
                       source_url(self.manifest["kev_after"]): after}

    def test_acquisition_uses_pinned_shas_and_records_hashes(self):
        out = self.root / "data"
        result = acquire(self.manifest, out, fetcher=self.by_url.__getitem__)
        self.assertEqual(set(result["artifacts"]), {"epss", "kev_before", "kev_after"})
        self.assertEqual(result["horizon_end"], "2026-11-01")
        self.assertTrue((out / "epss.csv.gz").exists())
        self.assertEqual(len(result["artifacts"]["epss"]["sha256"]), 64)
        self.assertTrue((out / "acquisition.json").exists())

    def test_feature_commit_cannot_be_later_than_cutoff(self):
        self.manifest["kev_before"]["commit_observed_date"] = "2026-10-03"
        with self.assertRaisesRegex(ValueError, "after the as_of date"):
            acquire(self.manifest, self.root / "data", fetcher=self.by_url.__getitem__)

    def test_unpinned_refs_and_foreign_sources_rejected(self):
        invalid = dict(self.manifest["epss"])
        invalid["commit"] = "main"
        with self.assertRaises(ValueError):
            source_url(invalid)
        invalid["commit"] = "a" * 40
        invalid["repository"] = "thirdparty/epss"
        with self.assertRaises(ValueError):
            source_url(invalid)

    def test_bad_embedded_epss_date_rejected(self):
        url = source_url(self.manifest["epss"])
        self.by_url[url] = gzip.compress(
            b"#model_version:v2026.06.15,score_date:2026-11-01T00:00:00Z\n"
            b"cve,epss\nCVE-2026-0001,0.2\n")
        with self.assertRaisesRegex(ValueError, "differs"):
            acquire(self.manifest, self.root / "data", fetcher=self.by_url.__getitem__)


if __name__ == "__main__":
    unittest.main()
