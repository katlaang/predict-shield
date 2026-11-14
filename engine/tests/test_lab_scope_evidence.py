"""Lab-only contracts including positive and negative policy gate integration."""
import unittest
from datetime import datetime, timezone, timedelta
from predict_shield.lab_scope_evidence import evaluate_lab_scope
from predict_shield.ai_contracts import EvidenceSnapshot, CandidateAction, ActionTier, ActionPrediction, Interval
from predict_shield.selector import select_action
from predict_shield.action_gate import GateDecision

NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)

def report(*, drift=False):
    return {"schema":"predict-shield/physical-lab-discovery/1",
            "reconciliation_status":"DRIFT_DETECTED" if drift else "RECONCILED_SOURCES",
            "gateway_source":"live-lab-gateway-config",
            "sha256":"synthetic-only",
            "running_enforcer_services":["enforcer-a","enforcer-b"],
            "gateway_routed_services":["enforcer-a"] if drift else ["enforcer-a","enforcer-b"],
            "ambiguous_scaled_services":[]}

def observations(*names):
    return [{"http_status":200, "gateway_upstream":"http://"+name+":8080"} for name in names]

class LabEvidenceTests(unittest.TestCase):
    def test_positive_lab_scope_can_reach_policy_selector(self):
        snap, result = evaluate_lab_scope(report(), observations("enforcer-a","enforcer-b"),
                                           case_id="lab-run", captured_at=NOW)
        self.assertTrue(snap.trusted)
        self.assertTrue(snap.scope_complete)
        self.assertEqual(result["status"],"LAB_SCOPE_SUPPORTED")
        a=CandidateAction("resync_policy",ActionTier.AUTOMATIC,("authorization",),"deny")
        p=ActionPrediction(action_id=a.action_id,snapshot_id=snap.snapshot_id,
            model_name="synthetic-only",model_version="fixture",predicted_at=NOW+timedelta(seconds=1),
            residual_risk=Interval(.05,.10,.15),
            additional_errors={"authorization":Interval(1,2,3)},calibration_supported=True)
        selection=select_action(snap,(a,),(p,),{"authorization":10})
        self.assertFalse(selection.abstained)
        self.assertEqual(selection.selected.action_id,"resync_policy")
        self.assertFalse(result["production_scope_attested"])
    def test_hidden_enforcer_blocks_selection(self):
        snap, result=evaluate_lab_scope(report(drift=True), observations("enforcer-a"),
                                         case_id="lab-run", captured_at=NOW)
        self.assertFalse(snap.scope_complete)
        self.assertIn("INVENTORY_NOT_RECONCILED",result["reasons"])
    def test_missing_forwarded_target_blocks(self):
        snap, result=evaluate_lab_scope(report(),observations("enforcer-a"),
                                         case_id="lab-run",captured_at=NOW)
        self.assertFalse(snap.trusted)
        self.assertIn("INCOMPLETE_FORWARDED_PROBES",result["reasons"])
    def test_gateway_generated_denial_not_forwarded(self):
        snap, result=evaluate_lab_scope(report(),
            [{"http_status":403,"gateway_upstream":None}],
            case_id="lab-run",captured_at=NOW)
        self.assertFalse(snap.trusted)
    def test_no_targets_does_not_become_verified(self):
        r=report(); r["running_enforcer_services"]=[];r["gateway_routed_services"]=[]
        snap,_=evaluate_lab_scope(r,[],case_id="lab-run",captured_at=NOW)
        self.assertFalse(snap.trusted)

if __name__=="__main__": unittest.main()
