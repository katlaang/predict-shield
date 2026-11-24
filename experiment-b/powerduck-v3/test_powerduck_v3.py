import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "powerduck"))
import gated_history as gh  # noqa: E402
from test_powerduck import capture  # noqa: E402


class FastForestTests(unittest.TestCase):
    def test_matches_sklearn(self):
        from sklearn.ensemble import IsolationForest
        rng = np.random.default_rng(3)
        x = rng.normal(size=(3000, 12))
        x[:, 2] = rng.integers(0, 4, 3000)
        m = IsolationForest(n_estimators=50, max_samples=512, random_state=7).fit(x)
        f = gh.FastForest(m)
        y = rng.normal(size=(200, 12)) * 3
        got = np.array([f.score(r) for r in y])
        self.assertLess(float(np.abs(got - m.score_samples(y)).max()), 1e-9)


class GatingTests(unittest.TestCase):
    def test_alerted_messages_do_not_enter_history(self):
        recs = gh.read_ipal(capture(40, 1000.0, seed=1))
        base, st = gh.capture_features(recs)
        known = sorted(set(st))

        class Always:
            def score(self, x):
                return -1.0

        class Never:
            def score(self, x):
                return 0.0

        _, a = gh.gated_scores(Always(), 0.5, base, st, known)
        self.assertTrue(a.all())
        _, b = gh.gated_scores(Never(), 0.5, base, st, known)
        self.assertFalse(b.any())

    def test_history_frozen_when_gated(self):
        h = gh.StreamHistory()
        row = np.zeros(len(gh.gf.BASE_FEATURES))
        before = h.features(row, "s")
        self.assertEqual(before[-1], 0.0)
        row2 = row.copy()
        row2[gh.I_FIRST] = 0.0
        h.admit(row2, "s")
        self.assertEqual(h.features(row2, "s")[-1], 1 / gh.HISTORY)

    def test_labels_ignored(self):
        recs = gh.read_ipal(capture(5, 1000.0, "x"))
        x, _ = gh.capture_features(recs)
        flipped = [dict(r, malicious=not gh.is_malicious(r)) for r in recs]
        self.assertTrue(np.array_equal(x, gh.capture_features(flipped)[0]))

    def test_incidents_group_by_gap(self):
        t = np.array([0, 0.5, 1.0, 5.0, 5.5, 20.0])
        a = np.array([1, 1, 0, 1, 1, 1], dtype=bool)
        self.assertEqual(gh.incidents(t, a, 2.0), [(0, 1), (3, 4), (5, 5)])


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
            code = root / "powerduck-v3"
            code.mkdir()
            for n in ("gated_history.py", "detector_v3.py"):
                shutil.copy(HERE / n, code)
            proto = json.loads((HERE / "protocol_v3.json").read_text())
            proto["source"]["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            (code / "protocol_v3.json").write_text(json.dumps(proto))
            frozen = root / "frozen"
            subprocess.run([sys.executable, str(code / "detector_v3.py"), "develop", "--archive", str(archive),
                            "--out-dir", str(frozen)], check=True, capture_output=True, cwd=code)
            h = json.loads((frozen / "freeze.json").read_text())["freeze_sha256"]
            out = root / "r.json"
            subprocess.run([sys.executable, str(code / "detector_v3.py"), "test", "--archive", str(archive),
                            "--frozen-dir", str(frozen), "--expected-freeze-sha256", h, "--output", str(out)],
                           check=True, capture_output=True, cwd=code)
            r = json.loads(out.read_text())
            self.assertEqual(r["scenarios_total"], 16)
            self.assertEqual(set(r["checks"]), {"non_malicious_alert_rate_at_most_1pct", "at_least_12_of_16_scenarios",
                                                "attack_captures_false_incidents_per_hour_at_most_2",
                                                "held_out_normal_false_incidents_per_hour_at_most_2"})
            self.assertEqual(sum(s["incidents"] for s in r["scenarios"].values()),
                             r["true_incidents"] + r["false_incidents"])
            bad = subprocess.run([sys.executable, str(code / "detector_v3.py"), "test", "--archive", str(archive),
                                  "--frozen-dir", str(frozen), "--expected-freeze-sha256", "0" * 64,
                                  "--output", str(out)], capture_output=True, cwd=code)
            self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
