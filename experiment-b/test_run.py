"""Deterministic tests without running Java or Docker."""
import unittest
from run import run, classify, Observation, fetch_status

class FakeTransport:
    def __init__(self, stale=True, refuse=False, offline=False):
        self.stale = stale
        self.refuse = refuse
        self.offline = offline
        self.calls = []
    def __call__(self, url, token=None, method="GET"):
        self.calls.append((url, method))
        if self.offline and "18082" in url:
            raise TimeoutError("unavailable")
        if method == "POST":
            if self.refuse or token != "disposable-token":
                return 403
            self.stale = False
            return 200
        if "18082" in url and self.stale:
            return 200
        return 403

class ExperimentBTests(unittest.TestCase):
    def test_readonly_flags_stale_policy(self):
        transport = FakeTransport()
        result = run(transport=transport)
        self.assertEqual(result["final_outcome"], "NOT VERIFIED")
        self.assertEqual(result["actions"], [])
        self.assertTrue(all(method == "GET" for _, method in transport.calls))

    def test_authorized_correction_is_independently_rechecked(self):
        transport = FakeTransport()
        result = run(True, "disposable-token", transport)
        self.assertEqual(result["started_outcome"], "NOT VERIFIED")
        self.assertEqual(result["final_outcome"], "VERIFIED")
        self.assertEqual(len(result["actions"]), 1)
        self.assertEqual(transport.calls[-1][1], "GET")

    def test_rejected_correction_never_claims_success(self):
        result = run(True, "invalid-token", FakeTransport(refuse=True))
        self.assertEqual(result["final_outcome"], "NOT VERIFIED")
        self.assertFalse(result["actions"][0]["acknowledged"])

    def test_missing_token_fails_closed(self):
        with self.assertRaises(ValueError):
            run(True, "", FakeTransport())

    def test_offline_service_abstains_without_actions(self):
        result = run(True, "disposable-token", FakeTransport(offline=True))
        self.assertEqual(result["final_outcome"], "INDETERMINATE")
        self.assertEqual(result["actions"][0]["action"], "abstain")

    def test_clean_state_verified(self):
        self.assertEqual(run(transport=FakeTransport(stale=False))["final_outcome"], "VERIFIED")

    def test_unknown_status_indeterminate(self):
        observations = [Observation("service-a",403,"now"),Observation("service-b",500,"now")]
        self.assertEqual(classify(observations)[0], "INDETERMINATE")

    def test_unexpected_url_rejected(self):
        with self.assertRaises(ValueError):
            fetch_status("http://example.com/api/protected")

if __name__ == "__main__":
    unittest.main()
