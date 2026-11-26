"""Synthetic engineering tests ONLY, not evidence of real network accuracy."""
import hashlib
import json
import random
import tempfile
import threading
import time
import unittest
from pathlib import Path

import pilot


def make(path, start, n, *, seed=1):
    rng = random.Random(seed)
    with path.open("w", encoding="utf-8") as f:
        for i in range(n):
            rec = {
                "ts": float(start + i * 2), "uid": "synth-" + str(i),
                "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.11",
                "proto": ("tcp" if i % 3 else "udp"), "service": "ssl",
                "duration": round(rng.uniform(0.01, 2.0), 5),
                "orig_bytes": rng.randint(40, 500),
                "resp_bytes": rng.randint(100, 1800),
                "orig_pkts": rng.randint(2, 20),
                "resp_pkts": rng.randint(2, 30),
                "conn_state": "SF"
            }
            f.write(json.dumps(rec) + "\n")
    return path


class ReadOnlyPilotTests(unittest.TestCase):
    def test_parse_zeek_json_without_leaking_identity(self):
        row = json.dumps({"ts": 1.5, "id.orig_h": "private-client",
                          "id.resp_h": "private-server", "proto": "tcp",
                          "duration": None, "orig_bytes": 120, "resp_pkts": 8})
        ts, features = pilot.parse_flow(row.encode())
        self.assertEqual(ts, 1.5)
        self.assertEqual(len(features), len(pilot.FEATURES))
        self.assertTrue(features[pilot.FEATURES.index("missing_duration")])
        self.assertNotIn("private", json.dumps(features))

    def test_fail_closed_on_invalid_flow(self):
        self.assertIsNone(pilot.parse_flow(b'{"ts":3,"proto":"tcp","uid":"id"}'))
        self.assertIsNone(pilot.parse_flow(b'{"ts":null,"proto":"tcp","orig_bytes":4}'))
        self.assertIsNone(pilot.parse_flow(b'{"ts":8,"proto":"tcp","orig_bytes":-3}'))
        self.assertIsNone(pilot.parse_flow(b'{"ts":8,"proto":"tcp","orig_bytes":true}'))
        self.assertIsNone(pilot.parse_flow(b'{"ts":7,"proto":"tcp"'))
        self.assertIsNone(pilot.parse_flow(b"x" * (pilot.MAX_LINE + 1)))

    def test_train_calibrate_evaluate_and_preserve_unknown_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = make(root / "a.json", 10000, 310, seed=10)
            b = make(root / "b.json", 11000, 160, seed=11)
            c = make(root / "c.json", 12000, 200, seed=12)
            modeldir, output = root / "model", root / "result.json"
            frozen = pilot.train(a, b, modeldir, "authorized_lab", True)
            self.assertEqual(frozen["fit_rows"], 310)
            self.assertEqual(frozen["calibration_rows"], 160)
            self.assertEqual(frozen["calibration_target"], 0.005)
            result = pilot.evaluate(c, modeldir, output, "authorized_lab", True)
            self.assertEqual(result["flow_records_scored"], 200)
            self.assertEqual(result["response_actions_attempted"], 0)
            self.assertFalse(result["changes_to_network"])
            self.assertEqual(result["ground_truth"], "UNKNOWN")
            self.assertIsNone(result["false_positive_rate"])
            self.assertIsNone(result["attack_detection_recall"])
            self.assertNotIn("192.0.2.", output.read_text())
            self.assertNotIn("198.51.100.", output.read_text())
            with self.assertRaises(FileExistsError):
                pilot.evaluate(c, modeldir, output, "authorized_lab", True)
            with self.assertRaises(ValueError):
                pilot.evaluate(b, modeldir, root / "bad.json", "authorized_lab", True)
            with self.assertRaises(ValueError):
                pilot.load_frozen(modeldir, "other_site")

    def test_frozen_code_and_model_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            a=make(root/"a",10000,250)
            b=make(root/"b",12000,130)
            md=root/"model"
            pilot.train(a,b,md,"site_x",True)
            frozen, loaded=pilot.load_frozen(md,"site_x")
            self.assertTrue(hasattr(loaded, "score_samples"))
            model_file = md/"model.pkl"
            original = model_file.read_bytes()
            model_file.write_bytes(original + b"tamper")
            with self.assertRaisesRegex(ValueError, "model integrity"):
                pilot.load_frozen(md,"site_x")

    def test_refuse_chronology_and_duplicate_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            a=make(root/"baseline",10000,250)
            b=make(root/"calibration",10020,130)
            with self.assertRaisesRegex(ValueError, "chronologically"):
                pilot.train(a,b,root/"model","site",True)
            with self.assertRaisesRegex(ValueError,"distinct"):
                pilot.train(a,a,root/"model2","site",True)
            with self.assertRaisesRegex(ValueError,"operator-authorized"):
                pilot.train(a,b,root/"model3","site",False)

    def test_watch_is_bounded_and_reads_only_new_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            a=make(root/"baseline",10000,250)
            b=make(root/"calibration",12000,150)
            model=root/"model"
            pilot.train(a,b,model,"site",True)
            current=make(root/"conn.log",15000,4)
            def append():
                time.sleep(0.25)
                with current.open("a") as f:
                    f.write(json.dumps({"ts": 16001.0, "proto": "tcp",
                                        "orig_bytes": 500, "orig_pkts": 4})+"\n")
                    f.flush()
            t=threading.Thread(target=append,daemon=True)
            t.start()
            res=pilot.watch(current,model,root/"watch.json","site",True,2)
            t.join(2)
            self.assertEqual(res["flow_records_scored"],1)
            self.assertEqual(res["response_actions_attempted"],0)
            self.assertEqual(res["ground_truth"],"UNKNOWN")
            self.assertFalse(res["changes_to_network"])


if __name__=="__main__":
    unittest.main()
