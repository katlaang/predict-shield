"""Tests on synthetic GOOSE captures only."""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import numpy as np

import goose_features as gf

HERE = Path(__file__).resolve().parent


def capture(n_seconds: int, start: float, attack: str | None = None, seed: int = 0) -> bytes:
    """Three streams publishing every 0.1 s with steady values; an attack
    injects messages with a jumped stNum and distorted values."""
    rng = np.random.default_rng(seed)
    rows, rid = [], 0
    st = {"a": 3, "b": 140, "c": 6}
    sq = {"a": 0, "b": 0, "c": 0}
    t = start
    while t < start + n_seconds:
        for s, dest in (("a", "010ccd010008"), ("b", "010ccd010003"), ("c", "010ccd010000")):
            sq[s] += 1
            rows.append({"id": rid, "timestamp": t + rng.uniform(0, 0.01), "protocol": "goose", "malicious": False,
                         "src": f"src-{s}", "dest": dest, "length": 230,
                         "data": {"Meas-000": 400 + rng.normal(0, 0.5), "Meas-001": "0000000000000",
                                  "stNum": st[s], "sqNum": sq[s]}})
            rid += 1
        if attack and start + n_seconds * 0.5 < t < start + n_seconds * 0.6:
            rows.append({"id": rid, "timestamp": t + 0.05, "protocol": "goose", "malicious": 1,
                         "src": "src-b", "dest": "010ccd010003", "length": 230,
                         "data": {"Meas-000": 9000.0, "Meas-001": "1111111111111", "stNum": st["b"] + 7, "sqNum": 0}})
            rid += 1
        t += 0.1
    return gzip.compress("\n".join(json.dumps(r) for r in rows).encode())


class Features(unittest.TestCase):
    def test_rows_match_messages_and_ignore_labels(self):
        recs = gf.read_ipal(capture(3, 1000.0, "x"))
        x, streams = gf.capture_features(recs)
        self.assertEqual(x.shape, (len(recs), len(gf.BASE_FEATURES)))
        flipped = [dict(r, malicious=not gf.is_malicious(r), id=r["id"] + 5) for r in recs]
        x2, _ = gf.capture_features(flipped)
        self.assertTrue(np.array_equal(x, x2))

    def test_malicious_marks(self):
        self.assertFalse(gf.is_malicious({"malicious": False}))
        self.assertFalse(gf.is_malicious({}))
        self.assertTrue(gf.is_malicious({"malicious": 3}))
        self.assertTrue(gf.is_malicious({"malicious": True}))

    def test_unseen_stream_column(self):
        x = np.zeros((2, 1))
        out = gf.with_streams(x, ["a", "z"], ["a", "b"])
        self.assertEqual(out[:, 1:].tolist(), [[1, 0, 0], [0, 0, 1]])


class EndToEnd(unittest.TestCase):
    def test_develop_freeze_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            archive = tmp / "pd.zip"
            with zipfile.ZipFile(archive, "w") as z:
                for i in range(1, 5):
                    z.writestr(f"dataset/ipal/Normal/0{i}-normal-{i}.ipal.gz", capture(60, 1000.0 * i, seed=i))
                for i in range(1, 17):
                    z.writestr(f"dataset/ipal/Attack/{i:02d}-a.ipal.gz", capture(30, 9000.0 + 100 * i, "x", seed=40 + i))
            import hashlib
            code = tmp / "code"
            code.mkdir()
            proto = json.loads((HERE / "protocol.json").read_text())
            proto["source"]["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            for name in ("goose_features.py", "detector.py"):
                (code / name).write_bytes((HERE / name).read_bytes())
            (code / "protocol.json").write_text(json.dumps(proto))
            frozen = tmp / "frozen"
            subprocess.run([sys.executable, str(code / "detector.py"), "develop", "--archive", str(archive),
                            "--out-dir", str(frozen)], check=True, cwd=code, capture_output=True)
            dev = json.loads((frozen / "development-report.json").read_text())
            self.assertEqual(len(dev["leave_one_capture_out"]), 4)
            h = json.loads((frozen / "freeze.json").read_text())["freeze_sha256"]
            out = tmp / "r.json"
            subprocess.run([sys.executable, str(code / "detector.py"), "test", "--archive", str(archive),
                            "--frozen-dir", str(frozen), "--expected-freeze-sha256", h, "--output", str(out)],
                           check=True, cwd=code, capture_output=True)
            r = json.loads(out.read_text())
            self.assertEqual(r["scenarios_total"], 16)
            self.assertEqual(r["TP"] + r["FP"] + r["FN"] + r["TN"], r["messages"])
            self.assertEqual(r["scenarios_detected"], 16)
            bad = subprocess.run([sys.executable, str(code / "detector.py"), "test", "--archive", str(archive),
                                  "--frozen-dir", str(frozen), "--expected-freeze-sha256", "0" * 64,
                                  "--output", str(out)], cwd=code, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
