"""Synthetic action-runner fixtures. Never represent these as real pilot runs."""
import unittest
from lab_autonomous_execution import execute_lab_recommendation


def recommendation(action="resync_policy", eligible=True):
    return {"research_lab_only":True, "abstained":False, "action_executed":False,
            "selected_action":action,
            "screened":{action:{"decision":"ELIGIBLE_AUTOMATIC" if eligible else "REJECT"}}}

SCOPE={"status":"LAB_SCOPE_SUPPORTED","production_scope_attested":False}


class ActionTests(unittest.TestCase):
    def test_model_recommendation_calls_action_and_independent_oracle(self):
        events=[]
        def runner(a,t): events.append(("action",a))
        def oracle(t):
            events.append(("oracle",t))
            return {"inventory_complete":True,"direct_target_observations_complete":True,
                    "all_revoked_access_denied":True}
        def gateway():
            events.append(("gateway",))
            return [{"http_status":403},{"http_status":200}]
        r=execute_lab_recommendation(recommendation(),scope_assessment=SCOPE,
                control_token="control",oracle_token="oracle",
                action_runner=runner,oracle_reader=oracle,gateway_reader=gateway)
        self.assertEqual(r["oracle_verdict"],"VERIFIED_LAB_ONLY")
        self.assertEqual(events[0],("action","resync_policy"))
        self.assertEqual(events[1],("oracle","oracle"))
        self.assertEqual(r["gateway_probe_total"],2)

    def test_noneligible_action_rejected(self):
        with self.assertRaisesRegex(ValueError,"Policy gate"):
            execute_lab_recommendation(recommendation(eligible=False),scope_assessment=SCOPE,
                    control_token="control",oracle_token="oracle",
                    action_runner=lambda *x:None,oracle_reader=lambda *x:None,gateway_reader=lambda:[])

    def test_restart_requires_approval_not_dispatch(self):
        events=[]
        r=execute_lab_recommendation(recommendation("restart_enforcer"),
            scope_assessment=SCOPE,control_token="control",oracle_token="oracle",
            action_runner=lambda *args:events.append(args),
            oracle_reader=lambda *args:events.append("oracle"),
            gateway_reader=lambda:[])
        self.assertEqual(r["status"],"AWAITING_LAB_APPROVAL")
        self.assertEqual(events,[])

    def test_incomplete_oracle_is_indeterminate(self):
        r=execute_lab_recommendation(recommendation(),scope_assessment=SCOPE,
            control_token="control",oracle_token="oracle",
            action_runner=lambda *x:None,
            oracle_reader=lambda t:{"inventory_complete":False,"all_revoked_access_denied":True},
            gateway_reader=lambda:[])
        self.assertEqual(r["oracle_verdict"],"INDETERMINATE")
        self.assertFalse(r["independent_postcondition_verified"])

    def test_negative_oracle_is_preserved(self):
        r=execute_lab_recommendation(recommendation(),scope_assessment=SCOPE,
            control_token="control",oracle_token="oracle",
            action_runner=lambda *x:None,
            oracle_reader=lambda t:{"inventory_complete":True,"direct_target_observations_complete":True,
                                    "all_revoked_access_denied":False},
            gateway_reader=lambda:[{"http_status":200}])
        self.assertEqual(r["oracle_verdict"],"NOT_VERIFIED_LAB_ONLY")

    def test_scope_and_replay_rejected(self):
        with self.assertRaises(ValueError):
            execute_lab_recommendation(recommendation(),scope_assessment={"status":"DRIFT_DETECTED"},
                control_token="control",oracle_token="oracle")
        again=recommendation()
        again["action_executed"]=True
        with self.assertRaises(ValueError):
            execute_lab_recommendation(again,scope_assessment=SCOPE,
                control_token="control",oracle_token="oracle")


if __name__=="__main__":
    unittest.main()
