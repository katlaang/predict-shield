"""Fail-closed invariants for the prospective read-only audit."""
import copy
import unittest
from prospective_defense_audit import audit, ACTIONS

H = "a" * 64

def fixture():
    rows = []
    for action in ACTIONS:
        rows.append({
            "configuration_id":"fresh-group-1", "repeat":0, "action":action,
            "partition":"test", "restart_permitted":False,
            "absolute_error_budget_requests":25,
            "label_security_exposure":0 if action == "resync_policy" else 1,
            "label_absolute_failed_requests":0, "pre_action_hash":H,
            "oracle_verified":True,
        })
    decisions = [
        {"configuration_id":"fresh-group-1","repeat":0,"policy":"ai",
         "selected_action":"resync_policy","evidence_hash":H},
        {"configuration_id":"fresh-group-1","repeat":0,"policy":"expert",
         "selected_action":"monitor_only","evidence_hash":H},
    ]
    return rows, decisions

class AuditTests(unittest.TestCase):
    def test_descriptive_never_claims_superiority(self):
        rows, decisions = fixture()
        result = audit(rows, decisions)
        self.assertFalse(result["superiority_established"])
        self.assertEqual(result["policies"]["ai"]["resolved_episodes"], 1)
        self.assertEqual(result["policies"]["expert"]["resolved_episodes"], 0)

    def test_missing_physical_arm_fails(self):
        rows, decisions = fixture()
        with self.assertRaises(ValueError):
            audit(rows[:-1], decisions)

    def test_oracle_missing_fails(self):
        rows, decisions = fixture()
        rows[0]["oracle_verified"] = False
        with self.assertRaises(ValueError):
            audit(rows, decisions)

    def test_restart_not_permitted_fails(self):
        rows, decisions = fixture()
        decisions[0]["selected_action"] = "restart_enforcer"
        with self.assertRaises(ValueError):
            audit(rows, decisions)

    def test_inconsistent_pre_action_fails(self):
        rows, decisions = fixture()
        rows[0]["pre_action_hash"] = "b" * 64
        with self.assertRaises(ValueError):
            audit(rows, decisions)

    def test_duplicate_policy_decision_fails(self):
        rows, decisions = fixture()
        with self.assertRaises(ValueError):
            audit(rows, decisions + [copy.deepcopy(decisions[0])])

    def test_excess_budget_recorded_not_hidden(self):
        rows, decisions = fixture()
        rows[1]["label_absolute_failed_requests"] = 30
        result = audit(rows, decisions)
        self.assertEqual(result["policies"]["ai"]["observed_budget_breaches"], 1)

if __name__ == "__main__":
    unittest.main()
