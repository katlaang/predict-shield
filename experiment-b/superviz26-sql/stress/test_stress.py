import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stress as s  # noqa: E402

POOL = ["Seán O'Brien", "547, avenue de Rossi", "ulica Morska 69/53"]


class StressTests(unittest.TestCase):
    def test_replaces_first_letter_run_only(self):
        rng = random.Random(0)
        out = s.perturb("Mike Hillyer 463 Jon 2", rng, POOL)
        self.assertTrue(out.endswith(" 463 Jon 2"))
        self.assertIn(out[: -len(" 463 Jon 2")], POOL)

    def test_numeric_rows_are_not_eligible(self):
        self.assertIsNone(s.perturb("11729 2.99", random.Random(0), POOL))

    def test_noisy_train_is_deterministic_and_near_rate(self):
        pairs = [("t", "Vieques Airport")] * 10000
        a, ka = s.noisy_train(pairs, 0.05, POOL)
        b, kb = s.noisy_train(pairs, 0.05, POOL)
        self.assertEqual(a, b)
        self.assertTrue(400 < ka < 600)

    def test_pool_is_deterministic(self):
        self.assertEqual(s.pool_sha(s.pool(7)), s.pool_sha(s.pool(7)))
        self.assertEqual(len(s.pool(7)), len(s.LOCALES) * len(s.KINDS) * s.PER)


if __name__ == "__main__":
    unittest.main()
