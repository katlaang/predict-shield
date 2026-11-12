"""No-network tests for independent inventory and lab-only SLO constraints."""
import unittest

from scope import declared_service_budget, verify_reconciled_scope


def probes(*names: str) -> list[dict]:
    """Build test-only forwarded-denial records with exact process identity."""
    return [
        {"http_status": 403,
         "result": {"gateway_upstream": f"http://{name}:8080", "decision": "DENY"}}
        for name in names
    ]


class InventoryVerificationTests(unittest.TestCase):
    """Prevent gateway responses from certifying unobserved enforcement state."""

    def test_fully_reconciled_scope_can_verify(self):
        """Two separate inventory sources and every direct route allow VERIFIED."""
        names = {"enforcer-a", "enforcer-b", "enforcer-hidden"}
        upstreams = [f"http://{name}:8080" for name in sorted(names)]
        result = verify_reconciled_scope(names, upstreams, probes(*sorted(names)))
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["inventory_reconciled"])

    def test_omitted_hidden_instance_is_indeterminate(self):
        """Even clean gateway denies cannot certify an omitted process."""
        expected = {"enforcer-a", "enforcer-b", "enforcer-hidden"}
        routed = ["http://enforcer-a:8080", "http://enforcer-b:8080"]
        result = verify_reconciled_scope(expected, routed,
                                         probes("enforcer-a", "enforcer-b"))
        self.assertEqual(result["status"], "INDETERMINATE")

    def test_gateway_generated_denial_cannot_verify(self):
        """A 403 generated without forwarding is not proof of target enforcement."""
        expected = {"enforcer-a"}
        result = verify_reconciled_scope(
            expected, ["http://enforcer-a:8080"],
            [{"http_status": 403, "result": {"source": "gateway"}}]
        )
        self.assertEqual(result["status"], "INDETERMINATE")

    def test_observed_allow_refutes_before_scope_completion(self):
        """An actual HTTP 200 disproves the no-unauthorized-access claim."""
        result = verify_reconciled_scope(
            {"enforcer-a", "enforcer-hidden"}, ["http://enforcer-a:8080"],
            [{"http_status": 200,
              "result": {"gateway_upstream": "http://enforcer-a:8080"}}]
        )
        self.assertEqual(result["status"], "NOT VERIFIED")

    def test_declared_budget_is_not_remaining_budget(self):
        """An assumed 1 percent lab SLO cannot authorize automatic execution."""
        budget = declared_service_budget(50, 10)
        self.assertEqual(budget["maximum_failed_requests"], 5)
        self.assertFalse(budget["remaining_budget_verified"])
        self.assertTrue(budget["requires_measured_consumption"])
        with self.assertRaises(ValueError):
            declared_service_budget(0, 10)


if __name__ == "__main__":
    unittest.main()
