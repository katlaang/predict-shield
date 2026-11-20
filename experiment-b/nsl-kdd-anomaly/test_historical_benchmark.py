"""Synthetic protocol tests only; benchmark numbers come from the separate real run."""
import hashlib
import io
import unittest
from unittest.mock import patch

from run_historical_benchmark import cutoff_from_benign, read_pinned, rows


class MockResponse(io.BytesIO):
    status = 200


class NSLKDDBenchmarkTests(unittest.TestCase):
    def test_git_object_digest_pins_immutable_dataset(self):
        sample = b"valid but not real benchmark data\n"
        blob = hashlib.sha1(f"blob {len(sample)}".encode() + bytes([0]) + sample).hexdigest()
        u = ("https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/"
             "27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9/KDDTrain%2B.txt")
        with patch("run_historical_benchmark.urllib.request.urlopen",
                   return_value=MockResponse(sample)):
            data, provenance = read_pinned(u, blob)
        self.assertEqual(sample, data)
        self.assertEqual(provenance["git_blob_sha1_verified"], blob)

    def test_source_byte_mutation_is_refused(self):
        sample = b"real content never supplied by this test"
        u = ("https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/"
             "27bbbdf5c5cccf9970b8b6037a0a9/KDDTrain%2B.txt")
        with self.assertRaises(ValueError):
            read_pinned(u, "0" * 40)

    def test_calibration_cutoff_and_tie_do_not_exceed_fpr_ceiling(self):
        scores = [i / 100 for i in range(100)]
        cutoff = cutoff_from_benign(scores, 0.05)
        self.assertLessEqual(sum(x > cutoff for x in scores), 5)
        self.assertEqual(cutoff_from_benign([0.7] * 100, .05), .7)
        self.assertEqual(cutoff_from_benign(scores, 0), max(scores))

    def test_rejects_noncanonical_row_and_fake_denominator(self):
        bad = b"1,tcp,http,normal\n"
        with self.assertRaises(ValueError):
            rows(bad, expected_count=10000)

    def test_source_urls_cannot_change_hosts(self):
        with self.assertRaisesRegex(ValueError, "Unapproved"):
            read_pinned("https://other.example.net/KDDTrain%2B.txt", "0" * 40)


if __name__ == "__main__":
    unittest.main()
