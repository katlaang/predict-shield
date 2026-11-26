import csv
import hashlib
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
import model_sql as m  # noqa: E402

COLS = ["full_query", "label", "user_inputs", "attack_stage", "tamper_method", "attack_status", "statement_type",
        "query_template_id", "attack_id", "attack_technique", "split"]


class EvidenceTests(unittest.TestCase):
    def test_per_template_novelty(self):
        prof = m.profiles([("t1", "Vieques Airport"), ("t1", "Fort Cavazos"), ("t2", "MX 950.0")])
        self.assertEqual(m.input_novelty("t1", "Vieques Fort", prof), 0.0)
        self.assertGreaterEqual(m.input_novelty("t1", "x(", prof), 1.0)   # new character class for t1
        self.assertEqual(m.input_novelty("t2", "GB 950.5", prof), 0.0)
        self.assertEqual(m.input_novelty("t9", "a", prof), 10.0)

    def test_vector_length_is_fixed(self):
        self.assertEqual(len(m.vector("t1", "ab c", ["t1", "t2"])), len(m.vector("zz", "", ["t1", "t2"])))


class EndToEnd(unittest.TestCase):
    def test_develop_then_test_once(self):
        rng = random.Random(1)
        words = ["Vieques", "Airport", "Fort", "Cavazos", "Miyakejima", "MX", "GB", "950.0", "2"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "d.csv"
            with open(data, "w", newline="") as f:
                w = csv.DictWriter(f, COLS)
                w.writeheader()
                for split, n in (("train", 1500), ("test", 600)):
                    for _ in range(n):
                        w.writerow({**{c: "" for c in COLS}, "label": "0", "split": split,
                                    "query_template_id": f"t{rng.randint(1, 4)}",
                                    "user_inputs": " ".join(rng.choice(words) for _ in range(rng.randint(1, 3)))})
                for t in m.TECHNIQUES:
                    for _ in range(5):
                        w.writerow({**{c: "" for c in COLS}, "label": "1", "split": "test", "attack_technique": t,
                                    "attack_stage": "exploit", "attack_status": "succeeded", "tamper_method": "none",
                                    "query_template_id": "t1", "user_inputs": "x' AND 1=1-- (" + "z" * 40})
            code = root / "superviz25-sql"
            code.mkdir()
            shutil.copy(HERE / "model_sql.py", code)
            proto = json.loads((HERE / "protocol.json").read_text())
            proto["source"]["sha256"] = hashlib.sha256(data.read_bytes()).hexdigest()
            (code / "protocol.json").write_text(json.dumps(proto))
            v3dir = root / "dvwa-correlation-v3"
            shutil.copytree(HERE.parent / "dvwa-correlation-v3", v3dir, ignore=shutil.ignore_patterns("frozen", "__pycache__"))
            shutil.copytree(HERE.parent / "dvwa-correlation", root / "dvwa-correlation",
                            ignore=shutil.ignore_patterns("frozen", "__pycache__", "reports"))
            frozen = root / "frozen"
            subprocess.run([sys.executable, str(code / "model_sql.py"), "develop", "--data", str(data), "--out-dir",
                            str(frozen)], check=True, capture_output=True)
            h = json.loads((frozen / "freeze.json").read_text())["freeze_sha256"]
            out = root / "r.json"
            subprocess.run([sys.executable, str(code / "model_sql.py"), "test", "--data", str(data), "--frozen-dir",
                            str(frozen), "--expected-freeze-sha256", h, "--output", str(out)], check=True, capture_output=True)
            r = json.loads(out.read_text())
            self.assertEqual(r["results"]["fused"]["attacks"]["of"], 35)
            self.assertEqual(r["results"]["fused"]["benign"]["of"], 600)
            again = subprocess.run([sys.executable, str(code / "model_sql.py"), "test", "--data", str(data), "--frozen-dir",
                                    str(frozen), "--expected-freeze-sha256", h, "--output", str(out)], capture_output=True)
            self.assertNotEqual(again.returncode, 0)


if __name__ == "__main__":
    unittest.main()
