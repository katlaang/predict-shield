import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_v32 as v  # noqa: E402

PROF = {"s|GET|/a": {"chars": ["alpha"], "min": 2, "max": 5}, "s|GET|/b": {"chars": ["digit"], "min": 1, "max": 9}}


class V32(unittest.TestCase):
    def test_pooled_profile_is_the_union_per_site_and_method(self):
        self.assertEqual(v.pooled(PROF), {"s|GET": {"chars": ["alpha", "digit"], "min": 1, "max": 9}})

    def test_only_unseen_templates_change(self):
        st = {"profiles": PROF, "pooled": v.pooled(PROF)}
        self.assertEqual(v.novelty("v3", "s|GET|/new", "ab12", st), 10.0)
        self.assertEqual(v.novelty("v32", "s|GET|/new", "ab12", st), 0.0)
        self.assertEqual(v.novelty("v32", "t|GET|/x", "ab", st), 10.0)
        self.assertEqual(v.novelty("v32", "s|GET|/a", "ab1", st), v.novelty("v3", "s|GET|/a", "ab1", st))

    def test_new_windows_never_overlap_the_original_test_period(self):
        for org, (lo, split, hi) in v.WINDOWS["early"].items():
            self.assertLessEqual(hi, v.m.SPLIT[org])
            self.assertLess(split, hi)


if __name__ == "__main__":
    unittest.main()
