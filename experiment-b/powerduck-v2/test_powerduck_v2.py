import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
import hashlib
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "powerduck"))
import history_features as hf  # noqa: E402
from test_powerduck import capture  # noqa: E402


class HistoryTests(unittest.TestCase):
    def test_shapes_and_labels_ignored(self):
        recs = hf.read_ipal(capture(5, 1000.0, "x"))
        x, st = hf.capture_features(recs)
        self.assertEqual(x.shape[0], len(recs))
        flipped = [dict(r, malicious=not hf.is_malicious(r)) for r in recs]
        self.assertTrue(np.array_equal(x, hf.capture_features(flipped)[0]))

    def test_incidents_group_by_gap(self):
        t = np.array([0, 0.5, 1.0, 5.0, 5.5, 20.0])
        a = np.array([1, 1, 0, 1, 1, 1], dtype=bool)
        self.assertEqual(hf.incidents(t, a, 2.0), [(0, 1), (3, 4), (5, 5)])


class EndToEnd(unittest.TestCase):
    def test_develop_and_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "pd.zip"
            with zipfile.ZipFile(archive, "w") as z:
                for i in range(1, 5):
                    z.writestr(f"dataset/ipal/Normal/0{i}-normal-{i}.ipal.gz", capture(60, 1000.0 * i, seed=i))
                for i in range(1, 17):
                    z.writestr(f"dataset/ipal/Attack/{i:02d}-a.ipal.gz", capture(30, 9000.0 + 100 * i, "x", seed=40 + i))
            (root / "powerduck").mkdir()
            shutil.copy(HERE.parent / "powerduck" / "goose_features.py", root / "powerduck")
            code = root / "powerduck-v2"
            code.mkdir()
            for n in ("history_features.py", "detector_v2.py"):
                shutil.copy(HERE / n, code)
            proto = json.loads((HERE / "protocol_v2.json").read_text())
            proto["source"]["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            (code / "protocol_v2.json").write_text(json.dumps(proto))
            frozen = root / "frozen"
            subprocess.run([sys.executable, str(code / "detector_v2.py"), "develop", "--archive", str(archive),
                            "--out-dir", str(frozen)], check=True, capture_output=True, cwd=code)
            h = json.loads((frozen / "freeze.json").read_text())["freeze_sha256"]
            out = root / "r.json"
            subprocess.run([sys.executable, str(code / "detector_v2.py"), "test", "--archive", str(archive),
                            "--frozen-dir", str(frozen), "--expected-freeze-sha256", h, "--output", str(out)],
                           check=True, capture_output=True, cwd=code)
            r = json.loads(out.read_text())
            self.assertEqual(r["scenarios_total"], 16)
            self.assertEqual(r["scenarios_detected"], 16)
            self.assertEqual(sum(s["incidents"] for s in r["scenarios"].values()), r["true_incidents"] + r["false_incidents"])


if __name__ == "__main__":
    unittest.main()
