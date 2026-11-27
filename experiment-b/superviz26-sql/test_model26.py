import csv
import hashlib
import io
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
import model26 as m  # noqa: E402

COLS = ["full_query", "label", "user_inputs", "attack_stage", "tamper_method", "attack_status", "statement_type",
        "query_template_id", "attack_id", "attack_technique", "split", "drift_set"]
WORDS = ["Vieques", "Airport", "Fort", "Cavazos", "MX", "GB", "950.0", "2", "Penelope", "Guiness"]


def member_csv(rng: random.Random, domain: str, train_domain: str, drift: bool) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, COLS)
    w.writeheader()
    for split, n in (("train", 1300), ("test", 400)):
        for _ in range(n):
            w.writerow({**{c: "" for c in COLS}, "label": "0", "split": split, "drift_set": "origin" if drift else "",
                        "query_template_id": f"{train_domain if split == 'train' else domain}{rng.randint(1, 3)}",
                        "user_inputs": " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 3)))})
    for t in ("boolean", "union"):
        for _ in range(10):
            w.writerow({**{c: "" for c in COLS}, "label": "1", "split": "test", "attack_technique": t,
                        "attack_stage": "exploit", "attack_status": "succeeded", "tamper_method": "none",
                        "drift_set": "shifted" if drift else "",
                        "query_template_id": f"{domain}1", "user_inputs": "~|~|{}" + "q" * 60})
    return buf.getvalue().encode()


class ArmTests(unittest.TestCase):
    def test_arm_list(self):
        a = m.arms()
        self.assertEqual(len(a), 4 * 3 + 3 * 2)
        self.assertEqual(a["lodo-a"][0], "superviz26-lodo/bcd-a.csv")
        self.assertEqual(a["indomain-c"][0], "superviz26-lodo/c-c.csv")
        self.assertEqual(a["drift-d"][0], "superviz26-cd/d.csv")
        self.assertEqual(a["fewshot-b-500"], ("superviz26-lodo/b-b.csv", 500))
        self.assertNotIn("fewshot-a-500", a)

    def test_checks_ignore_small_techniques(self):
        f = {"benign": {"rate": 0.005}, "attacks": {"rate": 0.95},
             "by_attack_technique": {"big": {"of": 5000, "rate": 0.8}, "tiny": {"of": 10, "rate": 0.0}}}
        self.assertTrue(all(m.checks_for(f).values()))
        f["by_attack_technique"]["big"]["rate"] = 0.7
        self.assertFalse(m.checks_for(f)["each_technique_at_least_75pct"])


class EndToEnd(unittest.TestCase):
    def test_develop_then_test_once(self):
        rng = random.Random(1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zpath = root / "s26.zip"
            members = sorted({mem for mem, _ in m.arms().values()})
            with zipfile.ZipFile(zpath, "w") as z:
                for mem in members:
                    name = mem.rsplit("/", 1)[1][:-4]
                    dom, train_dom = name[-1], name.split("-")[0][0]
                    z.writestr(mem, member_csv(rng, dom, train_dom, "superviz26-cd/" in mem))
            for d in ("superviz26-sql", "superviz25-sql", "dvwa-correlation-v3", "dvwa-correlation"):
                shutil.copytree(HERE.parent / d, root / d,
                                ignore=shutil.ignore_patterns("frozen", "__pycache__", "reports", "models"))
            proto = json.loads((HERE / "protocol.json").read_text())
            proto["source"]["sha256"] = hashlib.sha256(zpath.read_bytes()).hexdigest()
            (root / "superviz26-sql" / "protocol.json").write_text(json.dumps(proto))
            code = root / "superviz26-sql" / "model26.py"
            run = lambda *a: subprocess.run([sys.executable, str(code), *a], capture_output=True, text=True)
            frozen, models = root / "frozen", root / "models"
            p = run("develop", "--zip", str(zpath), "--out-dir", str(frozen), "--models-dir", str(models))
            self.assertEqual(p.returncode, 0, p.stderr)
            freeze = json.loads((frozen / "freeze.json").read_text())
            self.assertEqual(set(freeze["arms"]), set(m.arms()))
            self.assertEqual(freeze["arms"]["fewshot-b-500"]["train_rows"], 500)
            out = frozen / "report.json"
            bad = run("test", "--zip", str(zpath), "--frozen-dir", str(frozen), "--models-dir", str(models),
                      "--expected-freeze-sha256", "0" * 64, "--output", str(out))
            self.assertNotEqual(bad.returncode, 0)
            args = ("test", "--zip", str(zpath), "--frozen-dir", str(frozen), "--models-dir", str(models),
                    "--expected-freeze-sha256", freeze["freeze_sha256"], "--output", str(out))
            p = run(*args)
            self.assertEqual(p.returncode, 0, p.stderr)
            rep = json.loads(out.read_text())
            self.assertEqual(rep["results"]["indomain-b"]["fused"]["attacks"]["rate"], 1.0)
            self.assertGreater(rep["results"]["lodo-b"]["fused"]["benign"]["rate"], 0.9)  # unseen templates
            self.assertIn("shifted", rep["results"]["drift-b"]["fused"]["by_drift_set"])
            self.assertNotEqual(run(*args).returncode, 0)  # the test runs once


if __name__ == "__main__":
    unittest.main()
