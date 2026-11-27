import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cohort_guard import SCHEMA, audit


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def manifest(with_population=False):
    rows = [dict(id="tr0", source_id="local", capture_group="train-session",
                 role="train", label="benign", truth_basis="independently_reviewed_event",
                 content_sha256=digest("train0"))]
    if with_population:
        for i in range(1000):
            rows.append(dict(id=f"cal{i}", source_id="local",
                             capture_group="cal-session", role="calibration",
                             label="benign", truth_basis="independently_reviewed_event",
                             content_sha256=digest(f"cal{i}")))
        for i in range(30):
            rows.append(dict(id=f"att{i}", source_id="local",
                             capture_group="test-session", role="test",
                             label="attack", truth_basis="independently_reviewed_event",
                             content_sha256=digest(f"attack{i}")))
        for i in range(1000):
            rows.append(dict(id=f"ben{i}", source_id="local",
                             capture_group="test-session", role="test",
                             label="benign", truth_basis="independently_reviewed_event",
                             content_sha256=digest(f"testben{i}")))
    else:
        rows += [dict(id="cal0", source_id="local", capture_group="cal-session",
                      role="calibration", label="benign",
                      truth_basis="independently_reviewed_event", content_sha256=digest("cal0")),
                 dict(id="te0", source_id="local", capture_group="test-session",
                      role="test", label="unknown", truth_basis="unverified",
                      content_sha256=digest("te0"))]
    return {
        "schema": SCHEMA, "protocol_sha256": digest("registered-protocol"),
        "sources": [dict(id="local", official_url="https://example.org/publisher",
                         rights_status="approved", rights_evidence="documented-test-only",
                         sha256=digest("fixtures"), relative_path="fixture.txt")],
        "rows": rows
    }


class CohortGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "fixture.txt").write_text("fixtures", encoding="utf-8")

    def check(self, m):
        return audit(m, dataset_root=self.root)

    def test_valid_fixture_passes_admission_but_does_not_claim_model_accuracy(self):
        result = self.check(manifest(True))
        self.assertEqual(result["status"], "READY_FOR_EVALUATION")
        self.assertEqual(result["ground_truth_counts"]["test_independent_attack"], 30)
        self.assertEqual(result["ground_truth_counts"]["test_independent_benign"], 1000)
        self.assertIn("no evaluation", result["metric_warning"])

    def test_small_cohort_not_ready(self):
        result = self.check(manifest())
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["counts"]["test_unknown"], 1)
        self.assertEqual(result["ground_truth_counts"].get("test_independent_benign", 0), 0)

    def test_pending_rights_block(self):
        m = manifest(True)
        m["sources"][0]["rights_status"] = "pending"
        self.assertEqual(self.check(m)["status"], "BLOCKED")

    def test_raw_bytes_required(self):
        self.assertEqual(audit(manifest(True))["status"], "BLOCKED")

    def test_source_digest_mismatch_blocks(self):
        m = manifest(True)
        m["sources"][0]["sha256"] = digest("not the file")
        self.assertEqual(self.check(m)["status"], "BLOCKED")

    def test_traversal_path_blocks(self):
        m = manifest(True)
        m["sources"][0]["relative_path"] = "../../etc/passwd"
        self.assertEqual(self.check(m)["status"], "BLOCKED")

    def test_identical_content_cross_split_rejected(self):
        m = manifest()
        m["rows"][2]["content_sha256"] = m["rows"][0]["content_sha256"]
        self.assertEqual(self.check(m)["status"], "REJECTED")
        self.assertTrue(any("identical content" in e for e in self.check(m)["errors"]))

    def test_capture_group_cross_split_rejected(self):
        m = manifest()
        m["rows"][2]["capture_group"] = m["rows"][0]["capture_group"]
        self.assertEqual(self.check(m)["status"], "REJECTED")

    def test_duplicate_event_id_rejected(self):
        m = manifest()
        m["rows"][1]["id"] = m["rows"][0]["id"]
        self.assertEqual(self.check(m)["status"], "REJECTED")

    def test_scenario_labels_not_treated_as_independent_truth(self):
        m = manifest(True)
        for r in m["rows"]:
            if r["role"] == "test" and r["label"] == "benign":
                r["truth_basis"] = "publisher_scenario"
        result = self.check(m)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["ground_truth_counts"].get("test_independent_benign", 0), 0)
        self.assertEqual(result["counts"]["labeled_without_event_truth"], 1000)

    def test_no_protocol_hash_blocks(self):
        m = manifest(True)
        m["protocol_sha256"] = "unregistered"
        self.assertEqual(self.check(m)["status"], "BLOCKED")

    def test_malformed_manifest_fails_closed(self):
        self.assertEqual(audit({"schema": "wrong"})["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
