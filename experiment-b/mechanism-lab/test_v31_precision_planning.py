import unittest

from v31_precision_planning import wilson, minimum_successes_to_clear, report


class PrecisionPlanningTests(unittest.TestCase):
    def test_prior_five_group_result_does_not_confidently_clear_threshold(self):
        low, high = wilson(2, 5)
        self.assertAlmostEqual(low, .11762077423264794, places=10)
        self.assertAlmostEqual(high, .769275718723987, places=10)
        self.assertLess(low, .30)
        self.assertGreater(high, .30)

    def test_wilson_18_group_feasibility_is_not_automatic(self):
        self.assertEqual(minimum_successes_to_clear(18), 10)
        self.assertEqual(minimum_successes_to_clear(5), 4)
        self.assertLess(wilson(9, 18)[0], .30)
        self.assertGreater(wilson(10, 18)[0], .30)

    def test_no_ai_power_claim(self):
        obj=report()
        self.assertTrue(obj["no_power_claim_for_ai_model_improvement"])
        self.assertTrue(obj["feasibility_sample_size_not_approved"])
        self.assertEqual(obj["unit_of_analysis"], "independent_configuration_group")

    def test_input_contract(self):
        for count, total in [(-1, 5), (6, 5), (0, 0), (1.0, 5)]:
            with self.assertRaises(ValueError):
                wilson(count, total)
        with self.assertRaises(ValueError):
            report((5, 5))


if __name__ == "__main__":
    unittest.main()
