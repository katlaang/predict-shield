"""Synthetic documentation fixtures, not any actual operator or pilot results."""
import copy
import unittest
from external_pilot_evidence_audit import assess, SCHEMA


def fixture():
    measurement = {
        "revoked_access_exposure_seconds": 10.0,
        "authorized_request_failures": 4,
        "authorized_request_total": 100,
        "independent_false_assurance_events": 1,
        "independent_verification_events": 20,
        "critical_service_downtime_seconds": 3.0,
    }
    return {
        "schema": SCHEMA, "country": "US", "environment": "isolated_staging",
        "sector": "illustrative synthetic sector",
        "critical_service": "illustrative protected service",
        "operator_pseudonym": "test-operator-FAKE",
        "independent_assessor_pseudonym": "test-assessor-FAKE",
        "real_operator_consent_documented": True,
        "human_safety_approval_documented": True,
        "study_registration_id": "synthetic-do-not-publish",
        "source_commit_sha": "a"*40,
        "protocol_document_sha256": "b"*64,
        "operator_consent_sha256": "c"*64,
        "independent_assessment_sha256": "d"*64,
        "measurement_artifact_sha256": "e"*64,
        "conditions": [
            {"condition_id": f"mock-{i}",
             "independent_verification_scope_complete": True,
             "framework": copy.deepcopy(measurement)} for i in range(2)
        ],
    }


class ExternalValidationEvidenceTests(unittest.TestCase):
    def test_arithmetic_never_implies_independently_proven_effectiveness(self):
        report=assess(fixture())
        self.assertEqual(report["documentation_status"],
                         "STRUCTURALLY_COMPLETE_UNAUTHENTICATED")
        self.assertFalse(report["critical_infrastructure_effectiveness_established"])
        self.assertFalse(report["external_independence_cryptographically_verified"])
        self.assertFalse(report["actual_operator_permission_authenticated"])
        self.assertEqual(report["condition_records"], 2)
        first = report["descriptive_measurements"][0]
        self.assertEqual(first["revoked_access_exposure_seconds"], 10)
        self.assertAlmostEqual(first["authorized_failure_fraction"], 0.04)
        self.assertAlmostEqual(first["false_assurance_fraction"], 0.05)

    def test_without_real_documented_operator_consent_fail_closed(self):
        f=fixture()
        f["real_operator_consent_documented"]=False
        with self.assertRaisesRegex(ValueError, "operator approval"):
            assess(f)

    def test_assessor_same_as_operator_is_not_independent(self):
        f=fixture()
        f["independent_assessor_pseudonym"]=f["operator_pseudonym"]
        with self.assertRaisesRegex(ValueError, "self-identical"):
            assess(f)

    def test_rejects_missing_or_mismatched_denominators(self):
        f=fixture()
        f["conditions"][0]["framework"]["authorized_request_failures"]=101
        with self.assertRaisesRegex(ValueError, "denominator"):
            assess(f)
        f=fixture()
        f["conditions"][0]["framework"]["independent_verification_events"]=0
        with self.assertRaisesRegex(ValueError, "denominator"):
            assess(f)

    def test_missing_signed_artifact_digest_rejected(self):
        f=fixture()
        f["measurement_artifact_sha256"]="not-a-hash"
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            assess(f)

    def test_no_field_results_from_single_condition(self):
        f=fixture()
        f["conditions"].pop()
        with self.assertRaisesRegex(ValueError, "Two or more"):
            assess(f)

    def test_cloned_conditions_not_distinct(self):
        f=fixture()
        f["conditions"][1]["condition_id"]="mock-0"
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            assess(f)

    def test_unknown_production_environment_rejected(self):
        f=fixture()
        f["environment"]="unapproved_live_network"
        with self.assertRaisesRegex(ValueError, "Environment"):
            assess(f)


if __name__ == "__main__":
    unittest.main()
