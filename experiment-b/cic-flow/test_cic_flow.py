import unittest

import numpy as np
import pandas as pd

import flow_features as ff


class LabelTests(unittest.TestCase):
    def test_benign_and_attempted_are_benign(self):
        for label in ("BENIGN", "benign", "DoS Hulk - Attempted", "Botnet - Attempted", ""):
            self.assertEqual(ff.label_class(label), (False, "benign"), label)

    def test_families(self):
        cases = {"DoS Hulk": "dos-hulk", "DoS Slowloris": "dos-slow", "DoS Slowhttptest": "dos-slow",
                 "DoS GoldenEye": "dos-goldeneye", "DDoS": "ddos", "DDoS-LOIC-HTTP": "ddos", "DDoS-HOIC": "ddos",
                 "FTP-Patator": "brute-force-ftp", "FTP-BruteForce": "brute-force-ftp",
                 "SSH-Patator": "brute-force-ssh", "Web Attack - XSS": "web-attack",
                 "Web Attack - SQL Injection": "web-attack", "Infiltration - Portscan": "infiltration",
                 "Infiltration": "infiltration", "Portscan": "portscan", "Botnet": "botnet",
                 "Botnet Ares": "botnet", "Heartbleed": "heartbleed", "Something New": "unmapped"}
        for label, family in cases.items():
            self.assertEqual(ff.label_class(label), (True, family), label)


class FeatureTests(unittest.TestCase):
    def test_service_bucket(self):
        self.assertEqual(ff.service_bucket(443), "port-443")
        self.assertEqual(ff.service_bucket("8080"), "port-8080")
        self.assertEqual(ff.service_bucket(51000), "ephemeral")
        self.assertEqual(ff.service_bucket(5000), "registered")
        self.assertEqual(ff.service_bucket(7), "other-wellknown")
        self.assertEqual(ff.service_bucket("x"), "unknown")

    def test_signed_log_handles_non_finite(self):
        out = ff.signed_log(np.array([0.0, -1.0, np.inf, np.nan, 9.0]))
        self.assertTrue(np.all(np.isfinite(out)))
        self.assertAlmostEqual(out[1], -np.log(2))
        self.assertEqual(out[2], 0.0)

    def test_timestamp_formats(self):
        a = ff.parse_time("2017-07-03 08:55:58.598621")
        self.assertAlmostEqual(ff.parse_time("2017-07-03 08:55:59.598621") - a, 1.0, places=5)
        self.assertEqual(ff.parse_time("14/02/2018 08:31:01"), ff.parse_time("2018-02-14 08:31:01"))
        with self.assertRaises(ValueError):
            ff.parse_time("yesterday")

    def test_context_is_causal_and_windowed(self):
        c = ff.ContextWindow(window=60)
        self.assertEqual(c.step(0, "a", "x", "80"), (0, 0, 0, 0.0, 0, 0))
        self.assertEqual(c.step(10, "a", "y", "22"), (1, 1, 1, 0.0, 0, 0))
        self.assertEqual(c.step(20, "b", "x", "80"), (0, 0, 0, 0.0, 1, 1))
        out = c.step(30, "a", "x", "80")
        self.assertEqual(out[:4], (2, 2, 2, 0.5))
        self.assertEqual(out[4:], (2, 2))
        out = c.step(100, "a", "z", "80")       # everything before t=40 has left the window
        self.assertEqual(out[:3], (0, 0, 0))

    def test_build_shape_and_no_identifiers(self):
        header = ["id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
                  "Flow Duration", "Flow Bytes/s", "Label", "Attempted Category"]
        frame = pd.DataFrame([[1, "f", "10.0.0.1", 5555, "10.0.0.2", 80, 6, "2017-07-03 08:55:58.0", 100,
                               "Infinity", "BENIGN", -1],
                              [2, "g", "10.0.0.1", 5556, "10.0.0.3", 22, 17, "2017-07-03 08:55:59.0", 50,
                               3.0, "DDoS", -1]], columns=header)
        numeric = ff.numeric_columns(header)
        self.assertEqual(numeric, ["Flow Duration", "Flow Bytes/s"])
        x = ff.build(frame, numeric, ff.ContextWindow())
        self.assertEqual(x.shape, (2, len(ff.feature_names(numeric))))
        self.assertTrue(np.all(np.isfinite(x)))
        names = ff.feature_names(numeric)
        self.assertEqual(x[0, names.index("svc:port-80")], 1.0)
        self.assertEqual(x[1, names.index("proto:17")], 1.0)
        self.assertAlmostEqual(float(x[1, names.index("ctx:src_flows_60s")]), np.log1p(1), places=6)
        self.assertFalse(any("IP" in n or "Timestamp" in n or "Label" in n for n in names))


class ThresholdTests(unittest.TestCase):
    def test_benign_threshold_respects_budget(self):
        scores = np.arange(1000, dtype=float)
        t = ff.benign_threshold(scores, 0.005)
        self.assertLessEqual(np.mean(scores > t), 0.005)
        self.assertGreater(np.mean(scores >= t), 0.005)

    def test_split_is_deterministic_and_spread(self):
        b = [ff.split_bucket("monday.csv", i) for i in range(5000)]
        self.assertEqual(b, [ff.split_bucket("monday.csv", i) for i in range(5000)])
        self.assertEqual(set(b), set(range(10)))

    def test_wilson(self):
        lo, hi = ff.wilson(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.2775, places=3)


if __name__ == "__main__":
    unittest.main()


class EndToEndTests(unittest.TestCase):
    """Synthetic flows only: checks the mechanics (pins, freeze, refusal,
    accounting), not detection performance."""

    def test_develop_freeze_then_score_once(self):
        import hashlib, json, subprocess, sys, tempfile, zipfile
        from pathlib import Path
        rng = np.random.default_rng(0)
        header = ["id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
                  "Flow Duration", "Total Fwd Packet", "Flow Bytes/s", "Label", "Attempted Category"]

        def day(n, attack_label, start):
            rows = []
            for i in range(n):
                attack = i % 5 == 0
                rows.append([i, f"f{i}", "10.0.0.9" if attack else f"10.0.1.{i % 50}", 40000 + i,
                             "10.0.0.1", 80 if attack else 443, 6, f"2017-07-03 09:{start + i // 60:02d}:{i % 60:02d}.0",
                             float(rng.integers(1, 50) if attack else rng.integers(1000, 90000)),
                             float(rng.integers(50, 90) if attack else rng.integers(1, 20)), 1.0,
                             attack_label if attack else "BENIGN", -1])
            return pd.DataFrame(rows, columns=header).to_csv(index=False)

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dev, test = tmp / "dev.zip", tmp / "test.zip"
            with zipfile.ZipFile(dev, "w") as z:
                for k, name in enumerate(("monday.csv", "tuesday.csv", "wednesday.csv", "thursday.csv", "friday.csv")):
                    z.writestr(name, day(1500, "DoS Hulk", k))
            with zipfile.ZipFile(test, "w") as z:
                z.writestr("a.csv", day(500, "DoS-Hulk", 0))
                z.writestr("b.csv", day(500, "Brand New Thing", 10))
            here = Path(__file__).resolve().parent
            protocol = json.loads((here / "protocol.json").read_text())
            protocol["sources"]["development"]["sha256"] = hashlib.sha256(dev.read_bytes()).hexdigest()
            protocol["sources"]["test"]["sha256"] = hashlib.sha256(test.read_bytes()).hexdigest()
            (tmp / "protocol.json").write_text(json.dumps(protocol))
            run = lambda *a: subprocess.run([sys.executable, *a], cwd=here, capture_output=True, text=True)
            r = run("train_dev.py", "--archive", str(dev), "--out-dir", str(tmp / "frozen"),
                    "--protocol", str(tmp / "protocol.json"))
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            freeze = json.loads((tmp / "frozen" / "freeze.json").read_text())
            args = ["score_test.py", "--archive", str(test), "--frozen-dir", str(tmp / "frozen"),
                    "--output", str(tmp / "test.json"), "--protocol", str(tmp / "protocol.json")]
            refused = run(*args, "--expected-freeze-sha256", "0" * 64)
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse((tmp / "test.json").exists())
            r = run(*args, "--expected-freeze-sha256", freeze["freeze_sha256"])
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            out = json.loads((tmp / "test.json").read_text())
            self.assertEqual(out["flows"], 1000)
            self.assertEqual(out["TP"] + out["FN"], 200)
            self.assertEqual(out["unmapped_labels"], ["Brand New Thing"])
            self.assertTrue(out["by_family"]["dos-hulk"]["family_in_development"])
            self.assertFalse(out["by_family"]["unmapped"]["family_in_development"])
            # a changed bundle is refused
            (tmp / "frozen" / "model.pkl").write_bytes(b"x")
            self.assertNotEqual(run(*args, "--expected-freeze-sha256", freeze["freeze_sha256"]).returncode, 0)
