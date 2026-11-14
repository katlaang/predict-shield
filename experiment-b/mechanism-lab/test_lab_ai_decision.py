"""Contract tests for trained-model adapter and evidence-gated laboratory runner."""
import unittest
from datetime import datetime, timezone

from lab_ai_decision import select_lab_defense
from test_model_adapter import ModelDecisionIntegrationTests
from predict_shield.lab_scope_evidence import evaluate_lab_scope

NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)


def lab_report():
    return {"schema": "predict-shield/physical-lab-discovery/1",
            "sha256": "synthetic-report", "gateway_source": "live-lab-gateway-config",
            "reconciliation_status": "RECONCILED_SOURCES",
            "running_enforcer_services": ["enforcer-a", "enforcer-b"],
            "gateway_routed_services": ["enforcer-a", "enforcer-b"],
            "ambiguous_scaled_services": []}


def probes():
    return [{"http_status": 200, "gateway_upstream": "http://enforcer-a:8080"},
            {"http_status": 403, "gateway_upstream": "http://enforcer-b:8080"}]


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = ModelDecisionIntegrationTests()
        self.fixtures.setUp()

    def test_model_selects_with_supported_lab_evidence(self):
        snapshot, scope = evaluate_lab_scope(lab_report(), probes(),
                                             case_id="run-test", captured_at=NOW)
        self.assertTrue(snapshot.trusted)
        result = select_lab_defense(self.fixtures.bundle, self.fixtures.pre,
                                    snapshot, remaining_budget=50,
                                    restart_permitted=True)
        self.assertFalse(result["abstained"])
        self.assertIsNotNone(result["selected_action"])
        self.assertFalse(result["action_executed"])
        self.assertFalse(result["independently_verified_post_action"])

    def test_hidden_node_blocks_model_recommendation(self):
        r=lab_report()
        r["gateway_routed_services"]=["enforcer-a"]
        r["reconciliation_status"]="DRIFT_DETECTED"
        snapshot, _ = evaluate_lab_scope(r,probes(),case_id="run-test", captured_at=NOW)
        result = select_lab_defense(self.fixtures.bundle,self.fixtures.pre,snapshot,
                                     remaining_budget=50,restart_permitted=True)
        self.assertTrue(result["abstained"])
        self.assertIsNone(result["selected_action"])

    def test_restart_without_permission_is_prohibited(self):
        snapshot, _ = evaluate_lab_scope(lab_report(),probes(),case_id="run-test",captured_at=NOW)
        result=select_lab_defense(self.fixtures.bundle,self.fixtures.pre,snapshot,
                                   remaining_budget=50,restart_permitted=False)
        self.assertEqual(result["screened"]["restart_enforcer"]["decision"],"REJECT")

    def test_invalid_budget_rejected(self):
        snapshot, _ = evaluate_lab_scope(lab_report(),probes(),case_id="run-test",captured_at=NOW)
        with self.assertRaises(ValueError):
            select_lab_defense(self.fixtures.bundle,self.fixtures.pre,snapshot,
                               remaining_budget=0,restart_permitted=True)


if __name__=="__main__":
    unittest.main()
