"""Synthetic schema fixtures only. No CTU-13 dataset is bundled or claimed tested."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from fit_evaluate import classify_label, feature, run


HEADERS = ("StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,"
           "sTos,dTos,TotPkts,TotBytes,SrcBytes,Label").split(",")


class CTU13Tests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.entries = []
        for scenario, split in (("scenario-train-a", "train"),
                                ("scenario-train-b", "train"),
                                ("scenario-calibration", "calibration"),
                                ("scenario-unseen", "test")):
            filename = scenario + ".binetflow"
            target = self.root / filename
            with target.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=HEADERS)
                writer.writeheader()
                for i in range(7):
                    attack = i % 3 == 0
                    label = ("Background" if i == 6 else
                             "From-Botnet-V42" if attack else "From-Normal-V42")
                    writer.writerow({
                        "StartTime": "2011/01/01 12:00:00", "Dur": 13 if attack else .2,
                        "Proto": "tcp" if attack else "udp", "SrcAddr": "192.0.2.1",
                        "Sport": "135", "Dir": "->", "DstAddr": "198.51.100.1",
                        "Dport": "8080", "State": "CON", "sTos": "0", "dTos": "0",
                        "TotPkts": 29 if attack else 2,
                        "TotBytes": 12000 if attack else 90,
                        "SrcBytes": 6000 if attack else 60,
                        "Label": label,
                    })
            self.entries.append({
                "scenario_id": scenario, "split": split, "file": filename,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest()
            })
        self.manifest = {"schema": "predict-shield/ctu13-flow-protocol/1",
                         "sample_cap_per_label_per_scenario": 2,
                         "scenarios": self.entries}

    def evaluate(self):
        raw = json.dumps(self.manifest).encode()
        return run(self.manifest, raw, self.root)

    def test_explicit_botnet_normal_and_unknown(self):
        self.assertEqual(classify_label("From-Botnet-V42"), 1)
        self.assertEqual(classify_label("From-Normal-V42"), 0)
        for label in ("Background", "", "From-Botnet-Normal", "C&C"):
            self.assertIsNone(classify_label(label))

    def test_only_predefined_flow_features(self):
        row = {"Dur": "1.25", "TotPkts": "3", "TotBytes": "400",
               "SrcBytes": "120", "Proto": "tcp", "SrcAddr": "192.0.2.10"}
        result = feature(row)
        self.assertEqual(len(result), 7)
        self.assertEqual(result[-3:], [1.0, 0.0, 0.0])

    def test_train_on_different_scenario_and_score(self):
        model, report = self.evaluate()
        self.assertTrue(report["model_is_trained"])
        self.assertFalse(model["production_deployable"])
        self.assertFalse(report["field_effectiveness_established"])
        self.assertFalse(report["sample_precision_is_operational_precision"])
        self.assertEqual(report["test_scenario_ids"], ["scenario-unseen"])
        self.assertEqual(report["evaluated_flows"], 4)
        self.assertEqual(sum(report[k] for k in ("TP", "FP", "FN", "TN")), 4)
        self.assertEqual(report["unknown_background_excluded"], 4)
        self.assertEqual(len(model["features"]), 7)

    def test_wrong_source_sha_is_rejected(self):
        self.entries[-1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.evaluate()

    def test_split_leakage_and_unpinned_inputs_rejected(self):
        self.entries[-1]["scenario_id"] = self.entries[0]["scenario_id"]
        with self.assertRaisesRegex(ValueError, "scenario ID"):
            self.evaluate()
        self.entries[-1]["scenario_id"] = "scenario-unseen"
        self.entries[-1]["sha256"] = ""
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.evaluate()

    def test_unknown_is_not_normal(self):
        _, report = self.evaluate()
        for s in report["scenario_source_stats"]:
            self.assertEqual(s["total_botnet"], 2)
            self.assertEqual(s["total_normal"], 4)
            self.assertEqual(s["excluded_unknown"], 1)
            self.assertEqual(s["sample_normal"], 2)
            self.assertEqual(s["sample_botnet"], 2)

    def test_malformed_labeled_flow_fails(self):
        target = self.root / "scenario-unseen.binetflow"
        data = target.read_text(encoding="utf-8").replace("12000", "-999")
        target.write_text(data, encoding="utf-8")
        self.entries[-1]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "malformed labeled"):
            self.evaluate()


if __name__ == "__main__":
    unittest.main()
