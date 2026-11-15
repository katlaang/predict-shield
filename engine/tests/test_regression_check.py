import subprocess
import unittest
from datetime import datetime, timezone

from predict_shield.assessment import Outcome, assess
from predict_shield.regression_check import RegressionSuite, check

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


class FakeCompleted:
    def __init__(self, returncode):
        self.returncode = returncode


def fake_runner(returncode):
    def runner(command, *, cwd, capture_output, text, timeout):
        return FakeCompleted(returncode)
    return runner


def raising_runner(exc):
    def runner(command, *, cwd, capture_output, text, timeout):
        raise exc
    return runner


SUITE = RegressionSuite(project="widget-api", command=("pytest", "-q"), cwd="/repo/widget-api")


class RegressionCheckTests(unittest.TestCase):
    def test_passing_suite_is_no_regression(self):
        evidence = check(SUITE, runner=fake_runner(0), now=NOW)
        self.assertTrue(evidence.observed_pass)
        self.assertTrue(evidence.independent)
        self.assertEqual(evidence.asset, "widget-api")
        self.assertEqual(evidence.assertion, "no_regression:widget-api")

    def test_failing_suite_is_a_regression(self):
        evidence = check(SUITE, runner=fake_runner(1), now=NOW)
        self.assertFalse(evidence.observed_pass)
        self.assertTrue(evidence.integrity_ok)

    def test_timeout_is_indeterminate_not_a_clean_bill(self):
        evidence = check(SUITE, runner=raising_runner(
            subprocess.TimeoutExpired(cmd="pytest", timeout=600.0)), now=NOW)
        self.assertFalse(evidence.integrity_ok)
        self.assertIsNone(evidence.observed_pass)
        result = assess("widget-api", "no_regression:widget-api", [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)

    def test_missing_test_runner_is_indeterminate_not_a_clean_bill(self):
        evidence = check(SUITE, runner=raising_runner(OSError("no such file")), now=NOW)
        self.assertFalse(evidence.integrity_ok)
        result = assess("widget-api", "no_regression:widget-api", [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)

    def test_a_real_regression_still_wins_over_a_stale_pass(self):
        from predict_shield.assessment import Evidence
        stale_pass = Evidence(asset="widget-api", assertion="no_regression:widget-api",
                              observed_pass=True, observed_at=NOW, source="regression-check",
                              independent=True)
        failing = check(SUITE, runner=fake_runner(1), now=NOW)
        result = assess("widget-api", "no_regression:widget-api", [stale_pass, failing], now=NOW)
        self.assertEqual(result.outcome, Outcome.NOT_VERIFIED)


if __name__=="__main__": unittest.main()
