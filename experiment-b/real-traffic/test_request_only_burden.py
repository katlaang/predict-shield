"""Tests for the honest limitation of request-only real-traffic evaluation."""
import datetime
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import request_only_burden as mod


class RealTrafficTests(unittest.TestCase):
    def test_parse_combined_requests_and_UTC_time(self):
        line = 'IP0001 - - [01/Feb/2026:03:04:05 +0700] "GET /vulnerabilities/sqli/?id=abc%27&Submit=Submit HTTP/1.1" 200 99 "-" "agent"'
        out = mod.parsed_record(line)
        self.assertEqual(out["path"], "/vulnerabilities/sqli/")
        self.assertEqual(out["params"]["id"], "abc'")
        self.assertEqual(out["timestamp"].utcoffset(), datetime.timedelta(hours=7))

    def test_never_invent_post_body(self):
        line = 'IP0001 - - [01/Feb/2026:03:04:05 +0700] "POST /login HTTP/1.1" 200 99 "-" "agent"'
        out = mod.parsed_record(line)
        self.assertEqual(out["method"], "POST")
        self.assertEqual(out["params"], {})

    def test_unknown_root_cannot_be_interpreted_as_false_positive(self):
        with tempfile.TemporaryDirectory() as root:
            data = Path(root) / "log.txt"
            data.write_text("\n".join([
                'IP0001 - - [01/Feb/2026:03:04:05 +0700] "GET /outside-app HTTP/1.1" 200 99 "-" "-"',
                'IP0001 - - [01/Feb/2026:03:04:06 +0700] "GET /vulnerabilities/sqli/?id=%27 HTTP/1.1" 200 99 "-" "-"',
                'IP0001 - - [02/Feb/2026:03:04:06 +0700] "POST /other HTTP/1.1" 200 99 "-" "-"',
            ])+"\n")
            state = {
                "request_profiles": {"paths":["/vulnerabilities/sqli/"],
                   "fields":{"/vulnerabilities/sqli/|id":{"chars":["digit"],"min":1,"max":1}}},
                "thresholds":{"request_novelty":0.0}
            }
            publisher = {"id":"tiny-test","url":"https://example.org","collection_environment":"outside-lab"}
            with patch.object(mod, "verify_frozen", return_value=({"freeze_sha256":"sha"}, state)), \
                 patch.object(mod.registry_module, "verify_file", return_value={
                    "sha256":"abc","verified":True,"bytes":data.stat().st_size}):
                result = mod.score(data, publisher, {"md5":"none"}, Path(root))
            self.assertEqual(result["counts"]["parsed_http_requests"],3)
            self.assertEqual(result["counts"]["requests_with_query"],1)
            self.assertEqual(result["counts"]["requests_without_body_capture"],1)
            self.assertEqual(result["counts"]["unseen_path_requests"],2)
            self.assertEqual(result["counts"]["request_component_alerts"],3)
            self.assertIsNone(result["false_positive_rate"])
            self.assertIsNone(result["attack_recall"])
            self.assertFalse(result["full_dvwa_v3_fused_detector_executed"])
            self.assertFalse(result["cross_site_request_only_performance_validated"])
            self.assertEqual(result["path_vocabulary_overlap_fraction"], 1/3)
            self.assertEqual(result["manual_review"]["sample_alerted_size"], 3)
            self.assertEqual(result["manual_review"]["sample_not_alerted_size"], 0)
            self.assertFalse(result["manual_review"]["completed"])

    def test_empty_and_bad_records_refused(self):
        with tempfile.TemporaryDirectory() as root:
            data=Path(root)/"bad.txt"
            data.write_text("not a request\n")
            with patch.object(mod,"verify_frozen",return_value=(
                {"freeze_sha256":"sha"},
                {"request_profiles":{"paths":[],"fields":{}},
                 "thresholds":{"request_novelty":0}})), \
                 patch.object(mod.registry_module,"verify_file",return_value={
                   "sha256":"abc","verified":True,"bytes":1}):
                with self.assertRaisesRegex(ValueError,"no parseable"):
                    mod.score(data,{"id":"bad","url":"https://example.org",
                                   "collection_environment":"test"},
                              {"md5":"0"*32},Path(root))

    def test_row_limit_is_strict_and_not_silent_sample(self):
        with tempfile.TemporaryDirectory() as root:
            data=Path(root)/"tiny.txt"
            data.write_text("bad\nbad\n")
            with patch.object(mod,"verify_frozen",return_value=(
                 {"freeze_sha256":"sha"},
                 {"request_profiles":{"paths":[],"fields":{}},
                  "thresholds":{"request_novelty":0}})), \
                 patch.object(mod.registry_module,"verify_file",return_value={
                  "sha256":"abc","verified":True,"bytes":1}):
                with self.assertRaisesRegex(ValueError,"max_rows"):
                    mod.score(data,{"id":"tiny","url":"https://example.org",
                                   "collection_environment":"test"},
                              {"md5":"0"*32},Path(root),max_rows=1)


if __name__ == "__main__":
    unittest.main()
