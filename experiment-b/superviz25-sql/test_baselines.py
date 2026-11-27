import csv
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
COLS = ["full_query", "label", "user_inputs", "attack_stage", "tamper_method", "attack_status", "statement_type",
        "query_template_id", "attack_id", "attack_technique", "split"]


class BaselineSteps(unittest.TestCase):
    def test_sample_libinj_supervised_report(self):
        rng = random.Random(3)
        words = ["Vieques", "Airport", "Fort", "Cavazos", "MX", "950.0"]
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            data = t / "d.csv"
            with open(data, "w", newline="") as f:
                w = csv.DictWriter(f, COLS)
                w.writeheader()
                for _ in range(3000):
                    w.writerow({**{c: "" for c in COLS}, "label": "0", "split": "test", "query_template_id": "t1",
                                "user_inputs": " ".join(rng.choice(words) for _ in range(2))})
                for i in range(400):
                    w.writerow({**{c: "" for c in COLS}, "label": "1", "split": "test", "query_template_id": "t1",
                                "attack_id": str(i % 20), "attack_technique": "boolean", "attack_stage": "exploit",
                                "user_inputs": "1' OR '1'='1"})
            run = lambda *a: subprocess.run([sys.executable, str(HERE / "baselines.py"), *a], check=True,
                                            capture_output=True, text=True)
            run("sample", "--data", str(data), "--out", str(t / "sample.npz"))
            run("libinj", "--data", str(data), "--out", str(t / "libinj.npz"))
            run("supervised", "--data", str(data), "--sample", str(t / "sample.npz"), "--out", str(t / "sup.npz"))
            out = run("report", "--data", str(data), "--sample", str(t / "sample.npz"), "--inputs",
                      str(t / "libinj.npz"), str(t / "sup.npz"), "--output", str(t / "r.json")).stdout
            self.assertIn("libinj", out)
            self.assertIn("sup AUC", out)
            keep = np.load(t / "sample.npz")["keep"]
            self.assertTrue(0 < keep.sum() < 3400)


if __name__ == "__main__":
    unittest.main()
