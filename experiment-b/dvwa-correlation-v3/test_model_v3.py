import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dvwa-correlation"))
import lab  # noqa: E402
import model_v3 as m  # noqa: E402


def ex(path, **params):
    return lab.Exchange("benign", "x", "GET", path, params, body="<pre>a</pre>", status=200)


class RequestProfileTests(unittest.TestCase):
    def setUp(self):
        self.prof = m.request_profiles([ex("/a", id=str(i)) for i in range(1, 40)] +
                                       [ex("/b", name="O'Brien"), ex("/b", name="Ann")])

    def test_known_values_score_zero(self):
        self.assertEqual(m.request_novelty(ex("/a", id="7"), self.prof), 0.0)

    def test_character_novelty_is_per_field(self):
        # An apostrophe is normal in /b name, but new in /a id.
        self.assertEqual(m.request_novelty(ex("/b", name="D'Arcy"), self.prof), 0.0)
        self.assertGreaterEqual(m.request_novelty(ex("/a", id="7'"), self.prof), 1.0)

    def test_unseen_parameter_and_page(self):
        self.assertEqual(m.request_novelty(ex("/a", id="1", extra="1"), self.prof), 3.0)
        self.assertEqual(m.request_novelty(ex("/new"), self.prof), 10.0)

    def test_overlong_value(self):
        self.assertGreater(m.request_novelty(ex("/a", id="1" * 30), self.prof), 0.0)


class FusionTests(unittest.TestCase):
    def test_tail_probability(self):
        ref = np.array([0.0, 0.0, 1.0, 2.0])
        p = m.tail_p(np.array([0.0, 1.5, 9.0]), ref)
        self.assertTrue(np.allclose(p, [5 / 5, 2 / 5, 1 / 5]))

    def test_one_rare_component_raises_fisher(self):
        cal = np.zeros((99, 4))
        cal[:, 3] = np.linspace(0, 1, 99)
        common = np.array([[0.0, 0.0, 0.0, 0.5]])
        rare = np.array([[2.0, 0.0, 0.0, 0.5]])
        self.assertGreater(m.fused(rare, cal)[0], m.fused(common, cal)[0] + 8.0)


class ResponseTests(unittest.TestCase):
    def test_more_rows_shift_response(self):
        base = [lab.Exchange("benign", "x", "GET", "/s", {}, body="<pre>r</pre>" + " w" * (i % 3), status=200)
                for i in range(30)]
        prof = m.response_profiles(base)
        many = lab.Exchange("x", "x", "GET", "/s", {}, body="<pre>r</pre>" * 5, status=200)
        self.assertLess(m.response_shift(base[0], prof), 2.0)
        self.assertGreater(m.response_shift(many, prof), 5.0)


if __name__ == "__main__":
    unittest.main()
