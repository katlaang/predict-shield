"""Synthetic parser contract tests only: no downloaded dataset or detection claims."""
from __future__ import annotations

import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from normalize import normalized_rows

KEY = b"unit-test-non-production-secret-key-123"
LANL_AUTH = (
    "1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success\n"
    "2,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Fail\n"
)
UGR_HEADER = "te,td,sa,da,sp,dp,pr,flg,fwd,stos,pkt,byt\n"
UGR_LINE = "2016-04-01 00:00:00,0.5,192.0.2.1,198.51.100.2,50000,443,6,....,0,0,3,144\n"
REDTEAM = "151648,U748@DOM1,C17693,C728\n"


class OperationalSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def create(self, name, data: str, *, compressed=False):
        path = self.root / name
        if compressed:
            with gzip.open(path, "wt", encoding="utf-8") as out:
                out.write(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def normalize(self, data, kind, *, compressed=False, max_records=100):
        path, digest = self.create("source.gz" if compressed else "source.csv",
                                   data, compressed=compressed)
        return normalized_rows(path, dataset=kind, expected_sha256=digest,
                               pseudonym_key=KEY, max_records=max_records)

    def test_lanl_auth_source_pseudonymized_and_not_inferred_benign(self):
        rows, digest = self.normalize(LANL_AUTH, "lanl-auth")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["label"], "unknown")
        self.assertEqual(rows[0]["truth_basis"], "unverified")
        self.assertEqual(rows[0]["source_line"], 1)
        self.assertEqual(rows[1]["source_line"], 2)
        self.assertEqual(rows[1]["auth_result"], "Fail")
        self.assertNotIn("C625", json.dumps(rows))
        self.assertNotIn("U147", json.dumps(rows))
        self.assertEqual(rows[0]["source_sha256"], digest)

    def test_gzip_auth_counts_first_line_and_cap(self):
        rows, _ = self.normalize(LANL_AUTH, "lanl-auth", compressed=True, max_records=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_line"], 1)

    def test_lanl_redteam_is_partial_truth_not_verified_exploit(self):
        rows, _ = self.normalize(REDTEAM, "lanl-redteam")
        self.assertEqual(rows[0]["label"], "attack")
        self.assertEqual(rows[0]["truth_basis"], "publisher_scenario")
        self.assertFalse(rows[0]["verified_attack"])

    def test_lanl_flows_and_dns(self):
        flow = "1,9,C3090,N10471,C3420,N46,6,3,144\n"
        rows, _ = self.normalize(flow, "lanl-flow")
        self.assertEqual((rows[0]["packets"], rows[0]["bytes"]), (3, 144))
        self.assertNotIn("C3090", json.dumps(rows))
        rows, _ = self.normalize("31,C161,C2109\n", "lanl-dns")
        self.assertEqual(rows[0]["event_type"], "dns")
        self.assertIsNotNone(rows[0]["destination_asset_id"])

    def test_ugr16_named_columns_and_unknown_labels(self):
        rows, _ = self.normalize(UGR_HEADER + UGR_LINE, "ugr16-flow")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_line"], 2)
        self.assertEqual(rows[0]["packets"], 3)
        self.assertEqual(rows[0]["bytes"], 144)
        self.assertEqual(rows[0]["label"], "unknown")
        self.assertNotIn("192.0.2.1", json.dumps(rows))

    def test_ugr16_gzip_named_columns(self):
        rows, _ = self.normalize(UGR_HEADER + UGR_LINE, "ugr16-flow", compressed=True)
        self.assertEqual(rows[0]["source_line"], 2)

    def test_mawilab_categories_are_not_verified_attack_truth(self):
        header = "anomalyID,srcIP,srcPort,dstIP,dstPort,taxonomy,heuristic,distance,nbDetectors,label\n"
        row = "A13,192.0.2.1,33001,198.51.100.2,443,DDoS,heur,1.25,5,anomalous\n"
        rows, _ = self.normalize(header + row, "mawilab-annotation")
        self.assertEqual(rows[0]["source_line"], 2)
        self.assertEqual(rows[0]["publisher_anomaly_category"], "anomalous")
        self.assertEqual(rows[0]["publisher_detector_count"], 5)
        self.assertEqual(rows[0]["label"], "unknown")
        self.assertFalse(rows[0]["verified_attack"])
        self.assertNotIn("192.0.2.1", json.dumps(rows))

    def test_mawilab_notice_does_not_mean_independently_benign(self):
        header = "anomalyID,srcIP,srcPort,dstIP,dstPort,taxonomy,heuristic,distance,nbDetectors,label\n"
        row = "A14,192.0.2.2,1,198.51.100.3,443,ntscSYN,heur,0.1,1,notice\n"
        rows, _ = self.normalize(header + row, "mawilab-annotation", compressed=True)
        self.assertEqual(rows[0]["label"], "unknown")
        self.assertEqual(rows[0]["truth_basis"], "unverified")

    def test_reject_invalid_digest(self):
        path, _ = self.create("a.csv", LANL_AUTH)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            normalized_rows(path, dataset="lanl-auth", expected_sha256="0" * 64,
                            pseudonym_key=KEY, max_records=100)

    def test_reject_symlink_source(self):
        real, digest = self.create("a.csv", LANL_AUTH)
        link = self.root / "alias"
        link.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            normalized_rows(link, dataset="lanl-auth", expected_sha256=digest,
                            pseudonym_key=KEY, max_records=100)

    def test_short_key_and_unbounded_requests_fail_closed(self):
        file, digest = self.create("a.csv", LANL_AUTH)
        with self.assertRaisesRegex(ValueError, "at least 24"):
            normalized_rows(file, dataset="lanl-auth", expected_sha256=digest,
                            pseudonym_key=b"short", max_records=100)
        with self.assertRaisesRegex(ValueError, "Bounded"):
            normalized_rows(file, dataset="lanl-auth", expected_sha256=digest,
                            pseudonym_key=KEY, max_records=0)

    def test_unknown_result_and_bad_integer_rejected(self):
        with self.assertRaisesRegex(ValueError, "result"):
            self.normalize(LANL_AUTH.replace("Success", "Imaginary"), "lanl-auth")
        with self.assertRaisesRegex(ValueError, "Bad integer"):
            self.normalize(UGR_HEADER + UGR_LINE.replace(",3,144", ",x,144"),
                           "ugr16-flow")

    def test_incomplete_row_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected 9 columns"):
            self.normalize("1,C123,C456\n", "lanl-flow")

    def test_source_hash_stable_across_sampling_caps(self):
        path, digest = self.create("a.csv", LANL_AUTH)
        a, hash_a = normalized_rows(path, dataset="lanl-auth",
                                    expected_sha256=digest, pseudonym_key=KEY, max_records=1)
        b, hash_b = normalized_rows(path, dataset="lanl-auth",
                                    expected_sha256=digest, pseudonym_key=KEY, max_records=2)
        self.assertEqual(hash_a, hash_b)
        self.assertEqual(a[0], b[0])

    def test_identity_key_changes_and_is_stable_per_key(self):
        path, digest = self.create("a.csv", LANL_AUTH)
        x, _ = normalized_rows(path, dataset="lanl-auth", expected_sha256=digest,
                               pseudonym_key=KEY, max_records=1)
        y, _ = normalized_rows(path, dataset="lanl-auth", expected_sha256=digest,
                               pseudonym_key=b"another-non-production-secret-12345", max_records=1)
        self.assertNotEqual(x[0]["source_asset_id"], y[0]["source_asset_id"])


if __name__ == "__main__":
    unittest.main()
