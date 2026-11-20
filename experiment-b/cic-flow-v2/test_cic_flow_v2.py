import unittest

import numpy as np
import pandas as pd

import features_v2 as fv


class ContextTests(unittest.TestCase):
    def test_out_of_order_rows_get_time_ordered_context_and_are_counted(self):
        # the review example: same destination, timestamps 100, 0, 120 in file order
        ctx, ooo = fv.destination_context(np.array([100.0, 0.0, 120.0]), ["s1", "s2", "s3"], ["d", "d", "d"])
        self.assertEqual(ooo, 1)
        self.assertEqual(ctx[1].tolist(), [0, 0])      # t=0 sees nothing earlier
        self.assertEqual(ctx[0].tolist(), [0, 0])      # t=100: the t=0 flow is >60 s older
        self.assertEqual(ctx[2].tolist(), [1, 1])      # t=120 sees only t=100

    def test_distinct_sources_and_window_edge(self):
        ctx, ooo = fv.destination_context(np.array([0.0, 10.0, 20.0, 70.0, 70.0]),
                                          ["a", "a", "b", "c", "c"], ["d", "d", "d", "d", "e"])
        self.assertEqual(ooo, 0)
        self.assertEqual(ctx[2].tolist(), [2, 1])
        self.assertEqual(ctx[3].tolist(), [2, 2])      # t=0 left the window (70-60=10 keeps t=10)
        self.assertEqual(ctx[4].tolist(), [0, 0])      # other destination

    def test_ties_follow_row_order(self):
        ctx, _ = fv.destination_context(np.array([5.0, 5.0]), ["a", "b"], ["d", "d"])
        self.assertEqual(ctx[:, 0].tolist(), [0, 1])


class FeatureTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(fv.label_class("FTP-Patator - Attempted"), (False, "benign"))
        self.assertEqual(fv.label_class("DDoS-HOIC"), (True, "ddos"))
        self.assertEqual(fv.label_class("Infiltration - Dropbox Download"), (True, "infiltration"))
        self.assertEqual(fv.label_class("Web Attack - SQL"), (True, "web-attack"))

    def test_no_per_source_or_identifier_inputs(self):
        names = fv.feature_names(["Flow Duration"])
        self.assertFalse(any(n.startswith("ctx:src") or n.startswith("log:") and ("IP" in n or "Port" in n
                             or "Timestamp" in n) for n in names))
        self.assertEqual([n for n in names if n.startswith("ctx:")],
                         ["ctx:dst_flows_60s", "ctx:dst_distinct_src_ips_60s"])

    def test_parse_times_one_format(self):
        t = fv.parse_times(pd.Series(["2017-07-03 08:55:58.598621", "2017-07-03 08:55:59.598621"]))
        self.assertAlmostEqual(t[1] - t[0], 1.0, places=5)
        t = fv.parse_times(pd.Series(["14/02/2018 08:31:01 PM", "14/02/2018 08:31:03 PM"]))
        self.assertAlmostEqual(t[1] - t[0], 2.0)
        with self.assertRaises(ValueError):
            fv.parse_times(pd.Series(["later", "2017-07-03 08:55:59"]))

    def test_threshold(self):
        s = np.arange(1000, dtype=float)
        t = fv.benign_threshold(s, 0.005)
        self.assertLessEqual(np.mean(s > t), 0.005)


class EndToEndTests(unittest.TestCase):
    """Synthetic flows: mechanics only (pins, code hashes, calibration without
    labels, accounting, refusal), not detection performance."""

    def test_develop_freeze_calibrate_score(self):
        import hashlib, json, shutil, subprocess, sys, tempfile, zipfile
        from pathlib import Path
        rng = np.random.default_rng(0)
        header = ["id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
                  "Flow Duration", "Total Fwd Packet", "Flow Bytes/s", "Label", "Attempted Category"]

        def day(n, attack_label, minute, shuffle=False):
            rows = []
            for i in range(n):
                attack = attack_label is not None and i % 5 == 0
                rows.append([i, f"f{i}", f"10.0.1.{i % 50}", 40000 + i, "10.0.0.1" if attack else f"10.0.2.{i % 7}",
                             80 if attack else 443, 6, f"2017-07-03 09:{minute + i // 60:02d}:{i % 60:02d}.0",
                             float(rng.integers(1, 50) if attack else rng.integers(1000, 90000)),
                             float(rng.integers(50, 90) if attack else rng.integers(1, 20)), 1.0,
                             attack_label if attack else "BENIGN", -1])
            frame = pd.DataFrame(rows, columns=header)
            if shuffle:
                frame = frame.sample(frac=1.0, random_state=1)
            return frame.to_csv(index=False)

        here = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            code = tmp / "code"
            code.mkdir()
            for name in ("features_v2.py", "train_dev_v2.py", "score_test_v2.py"):
                shutil.copy(here / name, code / name)
            dev, test = tmp / "dev.zip", tmp / "test.zip"
            with zipfile.ZipFile(dev, "w") as z:
                z.writestr("monday.csv", day(1500, None, 0))
                for k, name in enumerate(("tuesday.csv", "wednesday.csv", "thursday.csv", "friday.csv")):
                    z.writestr(name, day(1500, "DoS Hulk", k + 1))
            with zipfile.ZipFile(test, "w") as z:
                z.writestr("Wednesday-14-02-2018.csv", day(3000, "SSH-Bruteforce", 0, shuffle=True))
                z.writestr("a.csv", day(500, "DoS-Hulk", 0))
                z.writestr("b.csv", day(500, "Brand New Thing", 10, shuffle=True))
            protocol = json.loads((here / "protocol_v2.json").read_text())
            protocol["sources"]["development"]["sha256"] = hashlib.sha256(dev.read_bytes()).hexdigest()
            protocol["sources"]["test"]["sha256"] = hashlib.sha256(test.read_bytes()).hexdigest()
            (code / "protocol_v2.json").write_text(json.dumps(protocol))
            run = lambda *a: subprocess.run([sys.executable, *a], cwd=code, capture_output=True, text=True)
            r = run("train_dev_v2.py", "--archive", str(dev), "--out-dir", str(tmp / "frozen"))
            self.assertEqual(r.returncode, 0, r.stderr[-3000:])
            freeze = json.loads((tmp / "frozen" / "freeze.json").read_text())
            args = ["score_test_v2.py", "--archive", str(test), "--frozen-dir", str(tmp / "frozen"),
                    "--output", str(tmp / "test.json")]
            r = run(*args, "--expected-freeze-sha256", freeze["freeze_sha256"])
            self.assertEqual(r.returncode, 0, r.stderr[-3000:])
            out = json.loads((tmp / "test.json").read_text())
            self.assertEqual(out["flows"], 1000)                       # calibration day excluded
            self.assertEqual(out["members"], ["a.csv", "b.csv"])
            self.assertEqual(out["TP"] + out["FN"], 200)
            self.assertEqual(out["unmapped_labels"], ["Brand New Thing"])
            self.assertEqual(out["calibration"]["rows"], 3000)
            self.assertGreater(out["calibration"]["out_of_order_rows"], 0)
            self.assertGreater(out["by_member"]["b.csv"]["out_of_order_rows"], 0)
            self.assertIn("passed", out)
            # changing feature code after freeze is refused
            with open(code / "features_v2.py", "a") as f:
                f.write("\n# changed\n")
            (tmp / "test.json").unlink()
            r = run(*args, "--expected-freeze-sha256", freeze["freeze_sha256"])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("code changed", r.stdout + r.stderr)
            self.assertFalse((tmp / "test.json").exists())


if __name__ == "__main__":
    unittest.main()
