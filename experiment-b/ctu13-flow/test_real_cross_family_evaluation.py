"""Protocol and claims regression tests, with no source download or field claims."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from real_cross_family_evaluation import PROTOCOL, registered_sources, evaluate


class RealPublishedFlowTests(unittest.TestCase):
    def setUp(self):
        self.protocol = json.loads(PROTOCOL.read_text())

    def test_registration_is_immutable_family_split(self):
        self.assertEqual(len(registered_sources(self.protocol)), 3)
        self.assertEqual({(r["family"], r["split"]) for r in self.protocol["sources"]},
                         {("Rbot", "train"), ("Rbot", "calibration"), ("NSIS.ay", "test")})

    def test_rejects_wrong_source_or_download_extension(self):
        bad = json.loads(json.dumps(self.protocol))
        bad["sources"][0]["url"] = "https://example.com/unsafe.exe"
        with self.assertRaises(ValueError):
            registered_sources(bad)

    def test_rejects_leaked_family_split_or_threshold(self):
        bad = json.loads(json.dumps(self.protocol))
        bad["sources"][0]["family"] = "NSIS.ay"
        with self.assertRaises(ValueError):
            registered_sources(bad)
        bad = json.loads(json.dumps(self.protocol))
        bad["max_calibration_sample_false_positive_rate"] = .2
        with self.assertRaises(ValueError):
            registered_sources(bad)

    def test_fail_closed_on_external_source_failure(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
                "real_cross_family_evaluation.download", side_effect=OSError("network failure")):
            with self.assertRaisesRegex(OSError, "network failure"):
                evaluate(self.protocol, PROTOCOL.read_bytes(), Path(tmp) / "fresh")


if __name__ == "__main__":
    unittest.main()
