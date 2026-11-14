"""Synthetic test scaffolding; real pilot evidence comes only from CI physical lab."""
import unittest
from datetime import datetime,timezone
from predict_shield.ai_contracts import EvidenceSnapshot,ActionPrediction,Interval
from lab_exploration import choose_lab_exploration, run_isolated_exploration

NOW=datetime(2026,11,14,tzinfo=timezone.utc)
SNAP=EvidenceSnapshot("lab","case",NOW,("docker","gateway","probe"),True,True)
SCOPE={"status":"LAB_SCOPE_SUPPORTED","production_scope_attested":False}

def model_prediction(action,risk,impact):
    return ActionPrediction(action_id=action,snapshot_id="lab",
        model_name="synthetic-mock",model_version="fixture",predicted_at=NOW,
        residual_risk=Interval(max(0,risk-.5),risk,min(1,risk+.5)),
        additional_errors={"authorization":Interval(0,impact,impact+30)},
        calibration_supported=True,training_fingerprint="synthetic")

def strict():
    return {"abstained":True,"research_lab_only":True,
            "screened":{"resync_policy":{"decision":"ESCALATE_FOR_EVIDENCE",
                "reason":"Unacceptable residual-risk uncertainty"}}}

class ExplorationTests(unittest.TestCase):
    def test_registered_lab_exploration_preserves_strict_refusal(self):
        p=(model_prediction("resync_policy",.2,2),
           model_prediction("gateway_restrict",.1,15))
        result=choose_lab_exploration(p,SNAP,strict(),
                        experimental_budget=50,protocol="physical-ai-exploration-v1")
        self.assertEqual(result["selected_action"],"resync_policy")
        self.assertFalse(result["production_authorization"])
        self.assertTrue(result["high_uncertainty_accepted_for_disposable_lab_measurement_only"])
    def test_no_restart_or_untrusted_scope(self):
        p=(model_prediction("restart_enforcer",0,0),)
        r=choose_lab_exploration(p,SNAP,strict(),experimental_budget=50,
                                 protocol="physical-ai-exploration-v1")
        self.assertTrue(r["abstained"])
        incomplete=EvidenceSnapshot("lab","case",NOW,("docker",),False,False)
        with self.assertRaises(ValueError):
            choose_lab_exploration(p,incomplete,strict(),experimental_budget=50,
                                   protocol="physical-ai-exploration-v1")
    def test_physical_executor_retains_negative_oracle(self):
        p=(model_prediction("gateway_restrict",.1,1),)
        choice=choose_lab_exploration(p,SNAP,strict(),experimental_budget=50,
                                     protocol="physical-ai-exploration-v1")
        actions=[]
        r=run_isolated_exploration(choice,scope=SCOPE,control_token="control",
                   oracle_token="oracle",action_runner=lambda a,t:actions.append(a),
                   oracle_reader=lambda t:{"inventory_complete":True,
                       "direct_target_observations_complete":True,
                       "all_revoked_access_denied":False},
                   gateway_reader=lambda:[{"http_status":200},{"http_status":403}])
        self.assertEqual(actions,["gateway_restrict"])
        self.assertEqual(r["oracle_verdict"],"NOT_VERIFIED_LAB_ONLY")
        self.assertFalse(r["scientific_superiority_established"])
    def test_unregistered_protocol_rejected(self):
        with self.assertRaises(ValueError):
            choose_lab_exploration((),SNAP,strict(),experimental_budget=50,
                                   protocol="unregistered")
if __name__=="__main__":
    unittest.main()
