"""Grid action-to-OVS authorization tests. No live grid or switches are touched."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))
from gated_ovs_response import make_plan, verify_plan, ALLOWED_ACTION
from predict_shield.grid_cyber_physical_lab import load_registration


class GatedOVSTests(unittest.TestCase):
    def setUp(self):
        self.reg = load_registration(HERE / "registration.json")
        self.plan = make_plan(self.reg, ALLOWED_ACTION, trustworthy_observations=True)

    def test_proposed_action_never_self_approves(self):
        self.assertEqual(self.plan["preapproval_gate"], "PROPOSE_FOR_APPROVAL")
        self.assertFalse(self.plan["production_authorized"])
        self.assertFalse(self.plan["lab_execution_authorized"])

    def test_lab_approval_is_separate_and_narrow(self):
        command = verify_plan(self.reg, self.plan, operator_approved=True,
                              trustworthy_observations=True)
        self.assertEqual(command["action_id"], ALLOWED_ACTION)
        self.assertTrue(command["lab_approved_only"])
        self.assertFalse(command["production_authorized"])
        self.assertFalse(command["grid_power_flow_coupled"])
        self.assertEqual(command["flow_add"],
                         "priority=250,ip,nw_src=10.89.34.10,nw_dst=10.89.34.30,actions=drop")

    def test_absent_authorization_and_untrusted_scope_fail(self):
        for approved, trusted in ((False, True), (True, False), (False, False)):
            with self.subTest(approved=approved, trusted=trusted):
                with self.assertRaises(PermissionError):
                    verify_plan(self.reg, self.plan,
                                operator_approved=approved,
                                trustworthy_observations=trusted)

    def test_reject_unsafe_and_unregistered_actions(self):
        for action in ("disconnect_substation_a", "monitor_only", "drop_everything", ""):
            with self.subTest(action=action):
                plan = make_plan(self.reg, action, trustworthy_observations=True)
                with self.assertRaises(PermissionError):
                    verify_plan(self.reg, plan, operator_approved=True,
                                trustworthy_observations=True)

    def test_modified_plan_and_registered_mapping_rejected(self):
        for field, value in (
            ("lab_execution_authorized", True),
            ("action_id", "disconnect_substation_a"),
            ("registration_sha256", "0" * 64),
            ("trusted_observations_declared", False),
            ("source", "real-AI"),
            ("production_authorized", True),
        ):
            with self.subTest(field=field):
                altered = copy.deepcopy(self.plan)
                altered[field] = value
                with self.assertRaises(PermissionError):
                    verify_plan(self.reg, altered, operator_approved=True,
                                trustworthy_observations=True)
        new_reg = copy.deepcopy(self.reg)
        new_reg["actions"][0]["remove_links"] = [["remote-access-gateway", "engineering-station"]]
        # Even a registered alternative link is not implicitly mapped to a switch rule.
        with self.assertRaises(PermissionError):
            verify_plan(new_reg, make_plan(new_reg, ALLOWED_ACTION,
                                          trustworthy_observations=True),
                        operator_approved=True, trustworthy_observations=True)

    def test_extra_plan_fields_rejected(self):
        modified = dict(self.plan, new_flow="actions=drop")
        with self.assertRaises(PermissionError):
            verify_plan(self.reg, modified, operator_approved=True,
                        trustworthy_observations=True)


if __name__ == "__main__":
    unittest.main()
