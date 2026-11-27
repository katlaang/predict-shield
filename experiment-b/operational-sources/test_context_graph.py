"""Synthetic multi-source context tests only; no external telemetry or AI result."""
import json
import tempfile
import hashlib
import unittest
from pathlib import Path

from context_graph import build_graph
from normalize import normalized_rows

SECRET = b"persistent-unit-test-scope-key-123456"


class ObservedContextGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def dataset(self, name: str, kind: str, lines: str, *, key=SECRET):
        raw = self.base / (name + ".csv")
        raw.write_text(lines)
        digest = hashlib.sha256(raw.read_bytes()).hexdigest()
        rows, _ = normalized_rows(raw, dataset=kind, expected_sha256=digest,
                                  pseudonym_key=key, max_records=100)
        out = self.base / (name + ".jsonl")
        out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return out

    def test_correlate_lanl_sources_without_mislabeling_nonredteam(self):
        auth = self.dataset("auth", "lanl-auth",
            "1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Fail\n")
        dns = self.dataset("dns", "lanl-dns", "31,C625,C2109\n")
        flow = self.dataset("flow", "lanl-flow", "1,9,C625,N10471,C2109,N46,6,3,144\n")
        redteam = self.dataset("redteam", "lanl-redteam", "151648,U748@DOM1,C625,C2109\n")
        g = build_graph([auth, dns, flow, redteam])
        self.assertEqual(g["observed_event_count"], 4)
        self.assertEqual(g["source_counts"]["lanl-redteam"], 1)
        self.assertEqual(g["known_partial_publisher_redteam_indicators"], 1)
        self.assertEqual(g["independently_confirmed_attack_count"], 0)
        self.assertIsNone(g["known_benign_denominator"])
        self.assertFalse(g["asset_inventory_complete"])
        self.assertEqual(len(g["nodes"]), 2)
        self.assertTrue(any("observed_auth_failure" in n["observed_event_counts"]
                            for n in g["nodes"]))
        self.assertNotIn("C625", json.dumps(g))
        self.assertNotIn("U748", json.dumps(g))

    def test_reject_different_pseudonymization_secret_scopes(self):
        a = self.dataset("one", "lanl-dns", "31,C1,C2\n")
        b = self.dataset("two", "lanl-dns", "32,C1,C3\n",
                         key=b"totally-distinct-keyed-scope-999")
        with self.assertRaisesRegex(ValueError, "Different pseudonymization keys"):
            build_graph([a,b])

    def test_reject_duplicate_record_across_files(self):
        a = self.dataset("one", "lanl-dns", "31,C1,C2\n")
        b = self.base / "duplicate.jsonl"
        b.write_bytes(a.read_bytes())
        with self.assertRaisesRegex(ValueError, "Duplicate event provenance"):
            build_graph([a,b])

    def test_reject_nonredteam_attack_label(self):
        a = self.dataset("one", "lanl-dns", "31,C1,C2\n")
        r = json.loads(a.read_text())
        r["label"] = "attack"
        r["truth_basis"] = "publisher_scenario"
        a.write_text(json.dumps(r) + "\n")
        with self.assertRaisesRegex(ValueError, "Non-redteam event"):
            build_graph([a])

    def test_mawilab_anomaly_is_not_proven_exploit(self):
        header = "anomalyID,srcIP,srcPort,dstIP,dstPort,taxonomy,heuristic,distance,nbDetectors,label\n"
        row = "A13,192.0.2.1,33001,198.51.100.2,443,DDoS,heur,1.25,5,anomalous\n"
        source = self.dataset("mawi", "mawilab-annotation", header + row)
        g = build_graph([source])
        self.assertEqual(g["independently_confirmed_attack_count"], 0)
        self.assertEqual(g["event_type_counts"]["published_network_anomaly_annotation"], 1)

    def test_event_cap_refuses_hidden_truncation(self):
        a = self.dataset("two", "lanl-dns", "31,C1,C2\n32,C1,C3\n")
        with self.assertRaisesRegex(ValueError, "Event cap"):
            build_graph([a], max_records=1)

    def test_invalid_identity_provenance_refused(self):
        a = self.dataset("one", "lanl-dns", "31,C1,C2\n")
        r = json.loads(a.read_text())
        r["source_asset_id"] = "unhashed-private-ip"
        a.write_text(json.dumps(r) + "\n")
        with self.assertRaisesRegex(ValueError, "Invalid pseudonymous"):
            build_graph([a])

    def test_empty_source_rejected(self):
        empty = self.base / "empty.jsonl"
        empty.write_text("")
        with self.assertRaisesRegex(ValueError, "No admitted"):
            build_graph([empty])


if __name__ == "__main__":
    unittest.main()
