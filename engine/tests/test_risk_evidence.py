"""Synthetic discovery-to-policy integration contracts."""
import unittest
from datetime import datetime, timezone, timedelta

from predict_shield.asset_risk_context import contextualize
from predict_shield.risk_evidence import assess_risk_evidence, canonical_digest
from predict_shield.ai_contracts import (
    ActionPrediction, ActionTier, CandidateAction, Interval,
)
from predict_shield.action_gate import GateDecision
from predict_shield.selector import select_action

IMAGE = "sha256:" + "a" * 64
NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)


def context():
    d = {"schema": "predict-shield/asset-discovery-report/1",
         "sha256": "synthetic-discovery",
         "assets": [{"asset_id": "docker:a", "image_id": IMAGE, "service": "enforcer-a"}],
         "sbom": {IMAGE: {"status": "SCANNED", "sbom": {"image_id": IMAGE,
             "components": [{"purl": "pkg:maven/lab@1", "name": "lab"}]}}}}
    return contextualize(d, [{"purl": "pkg:maven/lab@1",
                              "cve": "CVE-2026-12345", "source": "synthetic"}])


class RiskEvidenceIntegrationTests(unittest.TestCase):
    def test_advisory_candidate_is_not_trusted_scope(self):
        r = assess_risk_evidence(context(), case_id="case-a", timestamp=NOW)
        self.assertFalse(r.snapshot.trusted)
        self.assertFalse(r.snapshot.scope_complete)
        self.assertEqual(r.candidate_cve_count, 1)
        self.assertIn("UNVALIDATED_ADVISORY_APPLICABILITY", r.reason_codes)

    def test_candidate_cannot_trigger_ai_action_even_with_optimistic_model(self):
        r = assess_risk_evidence(context(), case_id="case-a", timestamp=NOW)
        action = CandidateAction("resync", ActionTier.AUTOMATIC, ("enforcer-a",), "safe")
        prediction = ActionPrediction(
            action_id="resync", snapshot_id=r.snapshot.snapshot_id,
            model_name="synthetic-model", model_version="fixture",
            predicted_at=NOW+timedelta(seconds=1),
            residual_risk=Interval(0, 0.01, 0.02),
            additional_errors={"enforcer-a": Interval(0, 0, 0)},
            calibration_supported=True)
        output = select_action(r.snapshot, (action,), (prediction,),
                               {"enforcer-a": 100})
        self.assertTrue(output.abstained)
        self.assertIsNone(output.selected)
        self.assertEqual(output.screened["resync"].decision,
                         GateDecision.ESCALATE_FOR_EVIDENCE)

    def test_digest_tamper_remains_untrusted(self):
        c = context()
        c["rows"][0]["service"] = "attacker-edited"
        r = assess_risk_evidence(c, case_id="case-a", timestamp=NOW)
        self.assertIn("UNTRUSTED_CONTEXT_INTEGRITY", r.reason_codes)

    def test_absent_sbom_is_not_clean(self):
        c = context()
        c["rows"][0]["sbom_status"] = "UNAVAILABLE"
        c["sha256"] = canonical_digest({k: v for k, v in c.items() if k != "sha256"})
        r = assess_risk_evidence(c, case_id="case-a", timestamp=NOW)
        self.assertIn("MISSING_SBOM_EVIDENCE", r.reason_codes)

    def test_duplicate_asset_refused(self):
        c = context()
        c["rows"].append(dict(c["rows"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            assess_risk_evidence(c, case_id="case-a", timestamp=NOW)

    def test_no_assets_does_not_equal_no_risk(self):
        c = context()
        c["rows"] = []
        r = assess_risk_evidence(c, case_id="case-a", timestamp=NOW)
        self.assertIn("NO_ASSET_SCOPE_EVIDENCE", r.reason_codes)


if __name__ == "__main__":
    unittest.main()
