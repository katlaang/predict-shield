import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import registry as d


def sample_registry():
    return {"schema": "predict-shield/dataset-registry/1",
            "policy": {"max_automatic_download_mb": 25},
            "datasets": [{"id": "cam", "url": "https://zenodo.org/records/1",
                          "zenodo_record": 1, "license": "CC-BY-4.0",
                          "collection_environment": "lab-a",
                          "files": [{"name": "sample.zip", "md5": "0" * 32,
                                     "approx_mb": 2.0, "ci_default": True}]}]}


class RegistryTests(unittest.TestCase):
    def test_publisher_registry_valid(self):
        r = d.get_registry()
        self.assertIn("cam-lds-v2", [x["id"] for x in r["datasets"]])
        self.assertIn("soc-mld-v2", [x["id"] for x in r["datasets"]])

    def test_unlicensed_cannot_download(self):
        r = sample_registry()
        r["datasets"][0]["license"] = "UNVERIFIED"
        with self.assertRaises(ValueError):
            d.lookup(r, "cam", "sample.zip")

    def test_bad_pins_fail_closed(self):
        r = sample_registry()
        r["datasets"][0]["files"][0]["md5"] = "not-a-hash"
        with self.assertRaises(ValueError):
            d.validate_registry(r)

    def test_reject_default_large_source(self):
        r = sample_registry()
        r["datasets"][0]["files"][0]["approx_mb"] = 160.0
        with self.assertRaises(ValueError):
            d.validate_registry(r)

    def test_validates_published_checksum(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "sample.zip"
            p.write_bytes(b"safe sample")
            record = {"md5": hashlib.md5(p.read_bytes()).hexdigest()}
            self.assertTrue(d.verify_file(p, record)["verified"])
            with self.assertRaises(ValueError):
                d.verify_file(p, {"md5": "0" * 32})

    def test_correlation_unknown_not_benign(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "sample.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("firewall/logs/eve.json", "\n".join([
                    json.dumps({"timestamp": "2026-01-01T00:00:02Z", "src_ip": "10.0.0.9"}),
                    json.dumps({"timestamp": "2026-01-01T00:00:10Z", "src_ip": "10.0.0.1"})]))
                z.writestr("server/logs/wazuh/alerts.json", "\n".join([
                    json.dumps({"timestamp": "2026-01-01T00:00:00Z", "data": {"srcip": "10.0.0.9"}}),
                    json.dumps({"timestamp": "2026-01-01T00:00:00Z", "data": {"srcip": "10.0.0.2"}})]))
            idx = d.archive_index(p)
            self.assertEqual(len(idx["candidates"]), 2)
            result = d.correlate(p, "server/logs/wazuh/alerts.json", "firewall/logs/eve.json")
            self.assertEqual(result["cooccurring_pairs"], 1)
            self.assertEqual(result["pairs"][0]["ground_truth"], "UNKNOWN")
            self.assertIsNone(result["false_positive_rate"])
            self.assertIsNone(result["detection_accuracy"])

    def test_correlation_budget_rejects_dense_match_without_oom(self):
        with tempfile.TemporaryDirectory() as root:
            archive = Path(root) / "dense.zip"
            host = "\n".join(json.dumps({"timestamp": "2026-01-01T00:00:00Z",
                                                "data": {"srcip": "192.0.2.4"}}) for _ in range(105))
            net = "\n".join(json.dumps({"timestamp": "2026-01-01T00:00:00Z",
                                               "src_ip": "192.0.2.4"}) for _ in range(105))
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("a/wazuh.json", host)
                z.writestr("b/eve.json", net)
            with self.assertRaisesRegex(ValueError, "pair budget exceeded"):
                d.correlate(archive, "a/wazuh.json", "b/eve.json")

    def test_exclude_bad_json_and_unsafe_members(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "sample.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("../outside.json", "{}")
                z.writestr("host/wazuh.json", '{"bad":}')
            with zipfile.ZipFile(p) as z:
                with self.assertRaises(ValueError):
                    d.read_json_lines(z, "../outside.json")
                with self.assertRaises(ValueError):
                    d.read_json_lines(z, "host/wazuh.json")

    def test_prevent_false_cross_network_claim(self):
        reg = d.get_registry()
        envs = [x["collection_environment"] for x in reg["datasets"]]
        self.assertEqual(len(envs), len(set(envs)))
        existing = next(x for x in reg["datasets"] if x["id"] == "hikari-2021")
        self.assertIn("already_tested", existing["evaluation_role"])


if __name__ == "__main__":
    unittest.main()
