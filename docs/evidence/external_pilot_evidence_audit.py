"""Fail-closed external pilot DOCUMENTATION audit, not evidence authentication.

The audit can check manifest structure and arithmetic, but cannot confirm
that a named operator/assessor is real, authorized, or independent. It never
converts an uploaded JSON record into an independent impact claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "predict-shield/external-critical-service-pilot/1"
REQUIRED_RESULTS = (
    "revoked_access_exposure_seconds",
    "authorized_request_failures",
    "authorized_request_total",
    "independent_false_assurance_events",
    "independent_verification_events",
    "critical_service_downtime_seconds",
)
SHA = set("0123456789abcdef")


def _sha256(value: object, field: str) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in SHA for c in value)):
        raise ValueError(field + " must be a SHA-256 hex digest")
    return value


def _number(value: object, field: str) -> float:
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < 0):
        raise ValueError("Missing/nonfinite/negative physical " + field)
    return float(value)


def _measure(record: dict, name: str) -> dict:
    if not isinstance(record, dict):
        raise ValueError("Missing actual " + name + " measurements")
    if set(record) != set(REQUIRED_RESULTS):
        raise ValueError("Incomplete external field measurement categories")
    result = {field: _number(record[field], field) for field in REQUIRED_RESULTS}
    for total, failures in (
        ("authorized_request_total", "authorized_request_failures"),
        ("independent_verification_events", "independent_false_assurance_events"),
    ):
        if (int(result[total]) != result[total] or
                int(result[failures]) != result[failures] or
                result[total] <= 0 or result[failures] > result[total]):
            raise ValueError("Invalid independent observation denominator")
    return result


def assess(manifest: dict) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("Wrong external pilot evidence schema")
    if manifest.get("country") != "US":
        raise ValueError("US critical infrastructure relevance is not established")
    if manifest.get("environment") not in (
            "operator_lab", "isolated_staging", "authorized_production"):
        raise ValueError("Environment and operational boundary must be identified")
    if manifest.get("real_operator_consent_documented") is not True:
        raise ValueError("No documented operator approval")
    if manifest.get("human_safety_approval_documented") is not True:
        raise ValueError("No documented authorized safety control")
    for field in ("sector", "critical_service", "operator_pseudonym",
                  "independent_assessor_pseudonym", "study_registration_id"):
        if not isinstance(manifest.get(field), str) or not manifest[field].strip():
            raise ValueError("Missing independent context: " + field)
    if (manifest["operator_pseudonym"] ==
            manifest["independent_assessor_pseudonym"]):
        raise ValueError("Operator and assessor cannot be self-identical")
    source = manifest.get("source_commit_sha")
    if (not isinstance(source, str) or len(source) not in (40, 64)
            or any(c not in SHA for c in source)):
        raise ValueError("Missing valid Git source commit hash")
    for field in ("protocol_document_sha256", "operator_consent_sha256",
                  "independent_assessment_sha256", "measurement_artifact_sha256"):
        _sha256(manifest.get(field), field)
    conditions = manifest.get("conditions")
    if not isinstance(conditions, list) or len(conditions) < 2:
        raise ValueError("Two or more actual condition records required")
    seen = set()
    measured = []
    for condition in conditions:
        if not isinstance(condition, dict):
            raise ValueError("Invalid physical condition record")
        ident = condition.get("condition_id")
        if not isinstance(ident, str) or not ident or ident in seen:
            raise ValueError("Duplicate or missing condition identity")
        seen.add(ident)
        if condition.get("independent_verification_scope_complete") is not True:
            raise ValueError("No independently verified scope")
        framework = _measure(condition.get("framework"), "framework")
        measured.append({
            "condition_id": ident,
            "revoked_access_exposure_seconds":
                framework["revoked_access_exposure_seconds"],
            "authorized_failure_fraction":
                framework["authorized_request_failures"] /
                framework["authorized_request_total"],
            "critical_service_downtime_seconds":
                framework["critical_service_downtime_seconds"],
            "false_assurance_fraction":
                framework["independent_false_assurance_events"] /
                framework["independent_verification_events"],
            "causal_effect_estimated": False,
        })
    return {
        "schema": "predict-shield/external-pilot-documentation-audit/2",
        "condition_records": len(measured),
        "descriptive_measurements": measured,
        "documentation_status": "STRUCTURALLY_COMPLETE_UNAUTHENTICATED",
        "external_independence_cryptographically_verified": False,
        "actual_operator_permission_authenticated": False,
        "critical_infrastructure_effectiveness_established": False,
        "national_generalization_established": False,
        "required_human_followup": [
            "Authenticate the actual US operator, approval scope and dates",
            "Authenticate the independent assessor and direct observations",
            "Check hashes against original securely retained artifacts",
            "Independently reproduce the load, measurements and inference",
            "Assess selection effects, site variation and plausible harms",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    report = assess(manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"documentation_status": report["documentation_status"],
                      "infrastructure_effectiveness_proven": False}))


if __name__ == "__main__":
    main()
