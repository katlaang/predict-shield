import random
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_calib as c  # noqa: E402

WORDS = ["kafsh", "mobile", "laptop", "12", "3", "sale", "new"]


def write_log(path: Path, days: int = 5, per_day: int = 2500) -> None:
    rng = random.Random(5)
    start = datetime(2019, 1, 22)
    with open(path, "w") as f:
        for d in range(days):
            for i in range(per_day):
                t = start + timedelta(days=d, seconds=i * 30)
                page = rng.randint(1, 4 + d)  # new pages appear over time
                f.write(f'1.2.3.4 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0330] "GET /p/{page}/x?q={rng.choice(WORDS)}'
                        f'&n={rng.randint(1, 50)} HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n')


class Calib(unittest.TestCase):
    def test_periods_and_splits(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "access.log"
            write_log(log)
            p = c.periods(c.rows(log))
            self.assertEqual(len(p["dev_days"]), 3)
            self.assertEqual(len(p["test_days"]), 2)
            self.assertLess(p["sel_fit"][-1][0], p["sel"][0][0])
            a, b, t = c.split("C1-temporal", p["dev"])
            self.assertEqual(len(a) + len(b) + len(t), len(p["dev"]))

    def test_choose_breaks_ties_by_abstention_then_order(self):
        res = {"C0-random": {"selection_score": 0.004, "abstain_share": 0.0},
               "C1-temporal": {"selection_score": 0.0005, "abstain_share": 0.0},
               "C2-temporal-strata": {"selection_score": 0.0009, "abstain_share": 0.0},
               "C3-temporal-abstain": {"selection_score": None, "abstain_share": 0.2}}
        self.assertEqual(c.choose(res), "C1-temporal")

    def test_select_then_test_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "access.log"
            write_log(log)
            c.select(log, root / "frozen", pinned=False)
            import json
            fr = json.loads((root / "frozen" / "freeze.json").read_text())
            self.assertIn(fr["winner"], c.CANDIDATES)
            out = root / "frozen" / "test-report.json"
            c.test(log, root / "frozen", fr["freeze_sha256"], out, pinned=False)
            rep = json.loads(out.read_text())
            self.assertEqual(set(rep["results"]), set(c.CANDIDATES))
            with self.assertRaises(SystemExit):
                c.test(log, root / "frozen", fr["freeze_sha256"], out, pinned=False)


if __name__ == "__main__":
    unittest.main()
