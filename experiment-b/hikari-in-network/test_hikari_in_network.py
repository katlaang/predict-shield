import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cic-flow-v3"))
import features_v3 as fv  # noqa: E402
import run  # noqa: E402
from test_cic_flow_v3 import hikari_frame  # noqa: E402


class InNetworkTests(unittest.TestCase):
    def test_split_is_stable_and_nested(self):
        u1 = run.uniform("s", ["a", "b", "c"])
        self.assertTrue(np.array_equal(u1, run.uniform("s", ["a", "b", "c"])))
        u = run.uniform("hikari-in-network", [f"C{i}" for i in range(4000)])
        sets = [set(np.where(u < f / 2)[0]) for f in run.FRACTIONS]
        self.assertTrue(all(a <= b for a, b in zip(sets, sets[1:])))
        self.assertFalse(sets[-1] & set(np.where(u >= 0.5)[0]))

    def test_train_and_test_on_synthetic_flows(self):
        frame = hikari_frame(6000, np.random.default_rng(3))
        x = fv.build(frame, fv.resolve_hikari(list(frame.columns)), fv.HIKARI_PORT, hikari=True, feature_set="flow+service")
        cats = frame[fv.HIKARI_CATEGORY].astype(str).to_numpy()
        attack = np.array([fv.hikari_class(c, l)[0] for c, l in zip(cats, frame[fv.HIKARI_LABEL])])
        u = run.uniform("hikari-in-network", frame["uid"])
        v = run.uniform("hikari-in-network-fit", frame["uid"])
        res = run.train_and_test(x, attack, cats, u < 0.25, u >= 0.5, v)
        self.assertEqual(res["TP"] + res["FP"] + res["FN"] + res["TN"], int((u >= 0.5).sum()))
        self.assertGreater(res["detection"], 0.9)
        self.assertIn("Background", res["by_category"])


if __name__ == "__main__":
    unittest.main()
