"""Chronological source-boundary tests; no real training data is invented."""
import gzip
import json
import unittest

from predict_shield.chronological_model import load_window, sample_training
from predict_shield.archive_acquire import source_url


def source(repo, date, sha="a" * 40):
    return {"repository": repo, "snapshot_date": date, "commit_observed_date": date,
            "commit": sha,
            "path": (f"{date[:4]}/epss_scores-{date}.csv.gz"
                     if repo == "empiricalsec/epss_scores" else
                     "known_exploited_vulnerabilities.json")}


class ChronologicalModelTests(unittest.TestCase):
    def setUp(self):
        self.window = {"partition": "train", "as_of": "2026-10-02",
                       "horizon_days": 30,
                       "epss": source("empiricalsec/epss_scores","2026-10-01"),
                       "kev_before": source("cisagov/kev-data","2026-10-01")}
        self.future = source("cisagov/kev-data","2026-11-10","b" * 40)
        ep = gzip.compress(b"#model_version:test,score_date:2026-10-01T00:00:00Z\n"
                           b"cve,epss,percentile\nCVE-2026-0001,0.8,0.99\n"
                           b"CVE-2026-0002,0.05,0.10\nCVE-2026-0003,0.7,0.9\n")
        before = json.dumps({"vulnerabilities":[
            {"cveID":"CVE-2026-0003","dateAdded":"2026-09-20"}]}).encode()
        after = json.dumps({"vulnerabilities":[
            {"cveID":"CVE-2026-0003","dateAdded":"2026-09-20"},
            {"cveID":"CVE-2026-0001","dateAdded":"2026-10-12"},
            {"cveID":"CVE-2026-0002","dateAdded":"2026-12-15"}]}).encode()
        self.data = {source_url(self.window["epss"]): ep,
                     source_url(self.window["kev_before"]): before,
                     source_url(self.future): after}

    def test_keeps_future_labels_out_of_input_features(self):
        result = load_window(self.window, self.future, fetcher=self.data.__getitem__)
        self.assertEqual(result["covered_additions"],1)
        self.assertEqual(len(result["records"]),2)
        self.assertEqual(next(row[3] for row in result["records"] if row[0]=="CVE-2026-0001"),1)
        self.assertTrue(all(len(row[1])==3 for row in result["records"]))

    def test_rejects_later_feature_source(self):
        self.window["kev_before"]["commit_observed_date"]="2026-10-03"
        with self.assertRaisesRegex(ValueError,"after cutoff"):
            load_window(self.window,self.future,fetcher=self.data.__getitem__)

    def test_refuses_nontrain_fit(self):
        row={"partition":"diagnostic","as_of":"2026-10-02",
             "records":[("CVE-2026-0001",[0.2,0.8,0],0.8,1)]}
        with self.assertRaisesRegex(ValueError,"Only predeclared training"):
            sample_training([row])


if __name__ == "__main__":
    unittest.main()
