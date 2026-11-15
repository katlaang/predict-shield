"""Synthetic contract tests; never mistake mocks for real lab effectiveness."""
import copy
import unittest
from datetime import datetime, timezone

from predict_shield.ai_contracts import EvidenceSnapshot
from predict_shield.assessment import Evidence
from unified_lab_case_adapter import execute_bound_lab_case

NOW=datetime(2026,11,14,22,0,tzinfo=timezone.utc)
ASSET="docker:"+"b"*64
CVE="CVE-2026-12345"
PURL="pkg:maven/org.example/core@1.0"
CONTROL="control-"+"x"*32
ORACLE="oracle-"+"y"*32


def plan():
    return {
        "schema":"predict-shield/unified-ai-case-plan/1",
        "case_id":"test-case",
        "created_at":NOW.isoformat(),
        "selection_status":"ELIGIBLE_RESEARCH_LAB_PLAN",
        "selected_action":"resync_policy",
        "scope_snapshot_id":"lab-scope:lab-sha",
        "selected_action_model_fingerprint":"trained-bundle-fingerprint",
        "discovery_sha256":"discovery-fixture",
        "applicability":"VERIFIED",
        "applicability_evidence_sources":["independent-advisory-check"],
        "dispatch_authorized":False,
        "independent_verification":"NOT_EVALUATED",
        "ai_proposals":[{"asset_id":ASSET,"cve":CVE,"purl":PURL,
                         "action_id":"resync_policy","status":"MODEL_PROPOSAL_UNVERIFIED",
                         "execution_authorized":False}],
    }


def evidence():
    return Evidence(asset=ASSET,assertion="cve-applicable:"+CVE+":"+PURL,
                    observed_pass=True,observed_at=NOW,
                    source="independent-advisory-check",independent=True)


def responses(verdict=True, action="resync_policy", trusted=True, scope=True,
              model="trained-bundle-fingerprint"):
    snapshot=EvidenceSnapshot("lab-scope:lab-sha","test-case",NOW,
                               ("lab-gateway","docker"),trusted,scope)
    def collector(**kwargs):
        return snapshot,{"status":"LAB_SCOPE_SUPPORTED",
                         "production_scope_attested":False},{"sha256":"lab-sha"}
    def selector(bundle,pre_action,snapshot,**kwargs):
        return {"research_lab_only":True,"action_executed":False,
                "abstained":False,"selected_action":action,
                "case_id":"test-case","snapshot_id":snapshot.snapshot_id,
                "model_fingerprint":model,
                "screened":{action:{"decision":"ELIGIBLE_AUTOMATIC"}}}
    calls=[]
    def executor(rec,**kwargs):
        calls.append(rec["selected_action"])
        return {"schema":"predict-shield/lab-execution-record/1",
                "selected_action":rec["selected_action"],
                "lab_only":True,"action_executed":True,
                "oracle_verdict":"VERIFIED_LAB_ONLY"}
    def oracle_reader(token):
        return {"inventory_complete":True,
                "direct_target_observations_complete":True,
                "all_revoked_access_denied":verdict}
    def gateway_reader():
        return [{"http_status":403 if verdict else 200} for _ in range(6)]
    return {"scope_collector":collector,"lab_selector":selector,
            "lab_executor":executor,"post_oracle_reader":oracle_reader,
            "post_gateway_reader":gateway_reader}, calls


def run(p=None, callbacks=None, observations=None, **kw):
    c,_=responses()
    if callbacks is not None:
        c=callbacks
    return execute_bound_lab_case(
        p or plan(),project="psunified",
        model_bundle={"training_fingerprint":"trained-bundle-fingerprint"},
        pre_action={"run_id":"test-case","oracle_features_excluded":True,
                    "experiment_type":"real_kafka_multijvm_lab"},
        control_token=CONTROL,oracle_token=ORACLE,remaining_lab_budget=30,
        applicability_observations=(evidence(),) if observations is None else observations,
        now=NOW,**c,**kw)


class UnifiedBridgeTests(unittest.TestCase):
    def test_policy_eligible_case_rechecks_oracle_but_not_cve(self):
        callback,calls=responses()
        outcome=run(callbacks=callback)
        self.assertEqual(calls,["resync_policy"])
        self.assertEqual(outcome["authorization_control_outcome"],"VERIFIED_LAB_ONLY")
        self.assertEqual(outcome["vulnerability_remediation_outcome"],"INDETERMINATE")
        self.assertFalse(outcome["vulnerability_remediation_verified"])
        self.assertEqual(outcome["unmeasured_service_continuity"],"UNKNOWN")

    def test_executor_ack_does_not_override_negative_oracle(self):
        callback,calls=responses(verdict=False)
        result=run(callbacks=callback)
        self.assertEqual(calls,["resync_policy"])
        self.assertEqual(result["authorization_control_outcome"],"NOT_VERIFIED_LAB_ONLY")
        self.assertFalse(result["vulnerability_remediation_verified"])

    def test_no_current_applicability_no_dispatch(self):
        callback,calls=responses()
        with self.assertRaisesRegex(ValueError,"applicability"):
            run(callbacks=callback,observations=())
        self.assertEqual(calls,[])

    def test_stale_case_no_dispatch(self):
        callback,calls=responses()
        p=plan();p["created_at"]="2026-11-14T20:00:00+00:00"
        with self.assertRaisesRegex(ValueError,"Stale"):
            run(p,callback)
        self.assertEqual(calls,[])

    def test_wrong_actual_model_fingerprint_no_dispatch(self):
        callback,calls=responses(model="other-model")
        with self.assertRaisesRegex(ValueError,"selection"):
            run(callbacks=callback)
        self.assertEqual(calls,[])

    def test_incomplete_live_scope_no_dispatch(self):
        callback,calls=responses(scope=False)
        with self.assertRaisesRegex(ValueError,"scope"):
            run(callbacks=callback)
        self.assertEqual(calls,[])

    def test_policy_selection_recomputed_not_trusted_from_plan(self):
        callback,calls=responses(action="gateway_restrict")
        with self.assertRaisesRegex(ValueError,"selection"):
            run(callbacks=callback)
        self.assertEqual(calls,[])

    def test_unapproved_action_never_reaches_executor(self):
        callback,calls=responses()
        p=plan();p["selected_action"]="restart_enforcer"
        with self.assertRaisesRegex(ValueError,"limited lab"):
            run(p,callback)
        self.assertEqual(calls,[])

    def test_plan_cannot_be_self_authorizing(self):
        callback,calls=responses()
        p=plan();p["dispatch_authorized"]=True
        with self.assertRaisesRegex(ValueError,"unexecuted"):
            run(p,callback)
        self.assertEqual(calls,[])

    def test_laboratory_projects_only(self):
        callback,calls=responses()
        with self.assertRaisesRegex(ValueError,"disposable"):
            run(callbacks=callback,project="production-isp")
        self.assertEqual(calls,[])

    def test_distinct_disposable_credentials_required(self):
        callback,calls=responses()
        with self.assertRaisesRegex(ValueError,"tokens"):
            run(callbacks=callback,oracle_token=CONTROL)
        self.assertEqual(calls,[])

    def test_replay_of_other_scope_is_blocked(self):
        callback,calls=responses()
        p=plan();p["scope_snapshot_id"]="lab-scope:other"
        with self.assertRaisesRegex(ValueError,"scope"):
            run(p,callback)
        self.assertEqual(calls,[])


if __name__=="__main__":
    unittest.main()
