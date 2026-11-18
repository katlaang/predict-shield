"""Synthetic contracts for the unified read-only AI vulnerability case lifecycle."""
import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.ai_contracts import (
    ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval
)
from predict_shield.assessment import Evidence
from predict_shield.dependency_graph import build_dependency_graph, reachable_service_dependents
from predict_shield.local_ai import prepare_request, validate_proposals
from predict_shield.pipeline import plan_case, record_independent_outcome
from predict_shield.risk_evidence import canonical_digest

NOW=datetime(2026,11,14,22,0,tzinfo=timezone.utc)
IMAGE="sha256:"+"a"*64
CONTAINER="b"*64
ASSET="docker:"+CONTAINER
CVE="CVE-2026-12345"
PURL="pkg:maven/org.example/core@1.0"
ACTION=CandidateAction("resync_policy",ActionTier.AUTOMATIC,
        ("authorization",),"Revoked operation denied",reversible=True)


def discovery():
    doc={"schema":"predict-shield/asset-discovery-report/1",
         "collected_at":NOW.isoformat(),
         "assets":[{"asset_id":ASSET,"container_id":CONTAINER,"image_id":IMAGE,
                   "service":"authorization","owner":"lab","criticality":"high"}],
         "reconciliation":{"matched":[CONTAINER],"scope_status":"RECONCILED_SOURCES"},
         "sbom":{IMAGE:{"status":"SCANNED","sbom":{"image_id":IMAGE,
                   "components":[{"purl":PURL,"name":"core"}]}}}}
    doc["sha256"]=canonical_digest(doc)
    return doc


def advisories():
    return [{"cve":CVE,"purl":PURL,"source":"synthetic-advisory",
             "text":"An example vulnerable component; not a real advisory."}]


class FakeAdvisor:
    model_id="recorded-synthetic-test"
    model_fingerprint="synthetic-fixture-1"
    def __init__(self, *, action="resync_policy"):
        self.action=action
        self.request=None
    def __call__(self, request):
        self.request=request
        return {"schema":"predict-shield/llm-advisory-proposals/1",
                "proposals":[{"asset_id":ASSET,"cve":CVE,"purl":PURL,
                              "action_id":self.action,
                              "verification_check_ids":["independent-deny"],
                              "rationale":"Candidate needs external validation"}]}


def snap(d):
    return EvidenceSnapshot(snapshot_id="lab-scope:test",case_id="test-case",
        captured_at=NOW,source_ids=("docker","gateway","discovery:"+d["sha256"]),
        trusted=True,scope_complete=True)


def applicable(positive=True, independent=True):
    return Evidence(asset=ASSET,assertion="cve-applicable:"+CVE+":"+PURL,
       observed_pass=positive,observed_at=NOW,source="separate-observer",
       independent=independent,integrity_ok=True)


def predicted(snapshot):
    return ActionPrediction(action_id=ACTION.action_id,
        snapshot_id=snapshot.snapshot_id,model_name="synthetic-outcome-model",
        model_version="fixture",predicted_at=NOW+timedelta(seconds=1),
        residual_risk=Interval(.1,.2,.3),
        additional_errors={"authorization":Interval(1,2,3)},
        calibration_supported=True,training_fingerprint="synthetic")


def run(d=None,model=None,**kwargs):
    d=d or discovery()
    return plan_case(case_id="test-case",discovery=d,advisories=advisories(),
            local_model=model or FakeAdvisor(),actions=(ACTION,),
            verification_check_ids=("independent-deny",),now=NOW,**kwargs)


class PipelineTests(unittest.TestCase):
    def test_ai_analysis_without_independent_scope_stays_unverified(self):
        model=FakeAdvisor()
        result=run(model=model)
        self.assertEqual(result["selection_status"],"ESCALATE_FOR_EVIDENCE")
        self.assertIsNone(result["selected_action"])
        self.assertFalse(result["dispatch_authorized"])
        self.assertFalse(result["ai_proposals"][0]["vulnerability_confirmed"])
        self.assertEqual(model.request["candidate_findings"][0]["cve"],CVE)

    def test_complete_synthetic_fixture_reaches_existing_policy_gate(self):
        d=discovery()
        snapshot=snap(d)
        result=run(d,scope_snapshot=snapshot,
                   finding_evidence=(applicable(),),
                   predictions=(predicted(snapshot),),
                   remaining_error_budgets={"authorization":10})
        self.assertEqual(result["selection_status"],"ELIGIBLE_LAB_PLAN")
        self.assertEqual(result["selected_action"],"resync_policy")
        self.assertEqual(result["applicability"],"VERIFIED")
        self.assertEqual(result["policy_screened"]["resync_policy"]["decision"],
                         "ELIGIBLE_AUTOMATIC")
        self.assertFalse(result["dispatch_authorized"])

    def test_optimistic_llm_without_independent_applicability_cannot_select(self):
        d=discovery();snapshot=snap(d)
        result=run(d,scope_snapshot=snapshot,
                   predictions=(predicted(snapshot),),
                   remaining_error_budgets={"authorization":10})
        self.assertIsNone(result["selected_action"])

    def test_incorrect_context_binding_fails(self):
        d=discovery()
        false_snapshot=EvidenceSnapshot("wrong","test-case",NOW,
            ("discovery:incorrect",),True,True)
        result=run(d,scope_snapshot=false_snapshot,
                   finding_evidence=(applicable(),),predictions=(predicted(false_snapshot),),
                   remaining_error_budgets={"authorization":10})
        self.assertIsNone(result["selected_action"])
        self.assertIn("not bound",result["reason"])

    def test_independent_refutation_blocks_approval(self):
        d=discovery();snapshot=snap(d)
        result=run(d,scope_snapshot=snapshot,
                   finding_evidence=(applicable(False),),
                   predictions=(predicted(snapshot),),
                   remaining_error_budgets={"authorization":10})
        self.assertEqual(result["applicability"],"NOT VERIFIED")
        self.assertIsNone(result["selected_action"])

    def test_no_calibrated_prediction_abstains(self):
        d=discovery();snapshot=snap(d)
        result=run(d,scope_snapshot=snapshot,
                   finding_evidence=(applicable(),),
                   remaining_error_budgets={"authorization":10})
        self.assertIsNone(result["selected_action"])
        self.assertEqual(result["policy_screened"]["resync_policy"]["decision"],
                         "ESCALATE_FOR_EVIDENCE")

    def test_unsafe_budget_blocks_action(self):
        d=discovery();snapshot=snap(d)
        result=run(d,scope_snapshot=snapshot,finding_evidence=(applicable(),),
                   predictions=(predicted(snapshot),),
                   remaining_error_budgets={"authorization":1})
        self.assertIsNone(result["selected_action"])
        self.assertEqual(result["policy_screened"]["resync_policy"]["decision"],"ESCALATE_FOR_EVIDENCE")

    def test_proposal_cannot_escape_allowed_action_catalog(self):
        with self.assertRaisesRegex(ValueError,"unauthorized action"):
            run(model=FakeAdvisor(action="shutdown_all_routers"))

    def test_tampered_discovery_fails_before_llm(self):
        d=discovery();d["assets"][0]["criticality"]="attacker-changed"
        model=FakeAdvisor()
        with self.assertRaisesRegex(ValueError,"altered"):
            run(d,model=model)
        self.assertIsNone(model.request)

    def test_reported_verified_outcome_requires_independent_postcheck(self):
        d=discovery();snapshot=snap(d)
        plan=run(d,scope_snapshot=snapshot,finding_evidence=(applicable(),),
                 predictions=(predicted(snapshot),),
                 remaining_error_budgets={"authorization":10})
        receipt={"lab_only":True,"selected_action":"resync_policy","action_executed":True,
                 "oracle_verdict":"VERIFIED_LAB_ONLY"}
        missing=record_independent_outcome(plan,receipt,(),now=NOW)
        self.assertEqual(missing["verification_status"],"INDETERMINATE")
        self_report=(Evidence(ASSET,"mitigated:"+CVE+":"+PURL,
                     True,NOW,"executor",False),)
        result=record_independent_outcome(plan,receipt,self_report,now=NOW)
        self.assertEqual(result["verification_status"],"INDETERMINATE")
        negative=(Evidence(ASSET,"mitigated:"+CVE+":"+PURL,
                   False,NOW,"external-probe",True),)
        result=record_independent_outcome(plan,receipt,negative,now=NOW)
        self.assertEqual(result["verification_status"],"NOT VERIFIED")
        confirmed=(Evidence(ASSET,"mitigated:"+CVE+":"+PURL,
                    True,NOW,"external-probe",True),)
        result=record_independent_outcome(plan,receipt,confirmed,now=NOW)
        self.assertEqual(result["verification_status"],"VERIFIED")
        self.assertEqual(result["service_continuity_status"],"UNKNOWN")

    def test_graph_declared_dependency_without_invented_links(self):
        d=discovery()
        graph=build_dependency_graph(d)
        self.assertEqual(graph["reconciliation_status"],"RECONCILED_SOURCES")
        self.assertEqual(sum(edge["relation"]=="RUNS" for edge in graph["edges"]),1)
        self.assertFalse(graph["complete_scope_verified"])
        result=reachable_service_dependents(graph,"authorization")
        self.assertEqual(result["declared_service_dependents"],[])
        self.assertFalse(result["impact_scope_complete"])

    def test_llm_cannot_author_unapproved_checks(self):
        from predict_shield.asset_risk_context import contextualize
        req=prepare_request(contextualize(discovery(),advisories()),advisories(),
                            action_ids=("resync_policy",),verification_check_ids=("independent-deny",))
        output=FakeAdvisor()(req)
        output["proposals"][0]["verification_check_ids"]=["run shell script"]
        with self.assertRaisesRegex(ValueError,"Unregistered"):
            validate_proposals(output,req)


if __name__=="__main__":
    unittest.main()
