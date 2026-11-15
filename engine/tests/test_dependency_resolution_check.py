import subprocess
import unittest
from datetime import datetime, timezone

from predict_shield.assessment import Outcome, assess
from predict_shield.dependency_resolution_check import ResolutionCheck, check

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


RESOLUTION = ResolutionCheck(project="widget-api", command=("npm", "install", "--dry-run"),
                             cwd="/repo/widget-api")


class DependencyResolutionCheckTests(unittest.TestCase):
    def test_clean_resolve_is_a_pass(self):
        evidence = check(RESOLUTION, runner=fake_runner(0), now=NOW)
        self.assertTrue(evidence.observed_pass)
        self.assertTrue(evidence.independent)
        self.assertEqual(evidence.asset, "widget-api")
        self.assertEqual(evidence.assertion, "dependency_resolution_ok:widget-api")

    def test_conflicting_resolve_is_a_failure(self):
        evidence = check(RESOLUTION, runner=fake_runner(1), now=NOW)
        self.assertFalse(evidence.observed_pass)
        self.assertTrue(evidence.integrity_ok)

    def test_timeout_is_indeterminate_not_a_clean_bill(self):
        evidence = check(RESOLUTION, runner=raising_runner(
            subprocess.TimeoutExpired(cmd="npm", timeout=120.0)), now=NOW)
        self.assertFalse(evidence.integrity_ok)
        self.assertIsNone(evidence.observed_pass)
        result = assess("widget-api", "dependency_resolution_ok:widget-api", [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)

    def test_missing_executable_is_indeterminate_not_a_clean_bill(self):
        evidence = check(RESOLUTION, runner=raising_runner(OSError("no such file")), now=NOW)
        self.assertFalse(evidence.integrity_ok)
        result = assess("widget-api", "dependency_resolution_ok:widget-api", [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)

    def test_clean_resolve_reaches_verified_through_assess(self):
        evidence = check(RESOLUTION, runner=fake_runner(0), now=NOW)
        result = assess("widget-api", "dependency_resolution_ok:widget-api", [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.VERIFIED)


if __name__=="__main__": unittest.main()
