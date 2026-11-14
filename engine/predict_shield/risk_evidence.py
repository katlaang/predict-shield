"""Bridge discovered asset risk context into fail-closed AI decision evidence.

Unvalidated advisory candidates never become trusted or complete snapshots.
This module does not authenticate source identities or authorize any action.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .ai_contracts import EvidenceSnapshot


def canonical_digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_digest(value: dict) -> bool:
    expected = value.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    without = {key: item for key, item in value.items() if key != "sha256"}
    return canonical_digest(without) == expected


@dataclass(frozen=True)
class RiskEvidence:
    snapshot: EvidenceSnapshot
    status: str
    reason_codes: tuple[str, ...]
    candidate_cve_count: int
    matched_asset_count: int
    provenance: Mapping[str, str]


def assess_risk_evidence(
    context: dict,
    *,
    case_id: str,
    timestamp: datetime | None = None,
) -> RiskEvidence:
    """Convert contextual candidate findings to conservative typed evidence.

    Even a syntactically complete asset + SBOM mapping cannot establish
    authenticated source independence, complete scope or verified CVE applicability.
    """
    if not isinstance(context, dict) or context.get("schema") != "predict-shield/asset-risk-context/1":
        raise ValueError("Unsupported asset risk context")
    if not case_id:
        raise ValueError("case_id is required")
    rows = context.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Context rows must be a list")
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("Evidence timestamps require UTC offset")
    reasons = set()
    digest_valid = verify_digest(context)
    if not digest_valid:
        reasons.add("UNTRUSTED_CONTEXT_INTEGRITY")
    if not context.get("discovery_digest"):
        reasons.add("MISSING_DISCOVERY_PROVENANCE")
    if context.get("discovery_scope_verified") is not False:
        # Current schema explicitly cannot claim complete discovery.
        reasons.add("UNSUPPORTED_SCOPE_ASSERTION")
    candidates = 0
    matched = 0
    identities = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("asset_id"), str) or not row["asset_id"]:
            raise ValueError("Malformed contextual asset")
        if row["asset_id"] in identities:
            raise ValueError("Duplicate contextual asset identity")
        identities.add(row["asset_id"])
        scan_status = row.get("sbom_status")
        if scan_status != "SCANNED":
            reasons.add("MISSING_SBOM_EVIDENCE")
        records = row.get("advisory_candidates")
        if not isinstance(records, list):
            raise ValueError("Missing advisory candidate records")
        if records:
            matched += 1
            reasons.add("UNVALIDATED_ADVISORY_APPLICABILITY")
        candidates += len(records)
        for candidate in records:
            if not isinstance(candidate, dict) or candidate.get("status") != "REQUIRES_APPLICABILITY_VALIDATION":
                raise ValueError("Unrecognized advisory status")
            if not candidate.get("cve") or not candidate.get("purl") or not candidate.get("source"):
                raise ValueError("Missing advisory provenance")
        if row.get("confirmed_vulnerability") is not False:
            reasons.add("UNSUPPORTED_VULNERABILITY_CONFIRMATION")
    if not rows:
        reasons.add("NO_ASSET_SCOPE_EVIDENCE")
    # No cryptographic attestation of live discovery or independently established
    # enterprise inventory exists in this schema. Even with no advisory candidates,
    # the case must abstain until independent scope and source verification exists.
    reasons.add("UNAUTHENTICATED_INDEPENDENT_SCOPE")
    snapshot = EvidenceSnapshot(
        snapshot_id="risk-context:" + (context["sha256"] if digest_valid else canonical_digest(context)),
        case_id=case_id,
        captured_at=timestamp,
        source_ids=(str(context.get("discovery_digest") or "missing-discovery"),),
        trusted=False,
        scope_complete=False,
    )
    return RiskEvidence(
        snapshot=snapshot,
        status="ESCALATE_FOR_EVIDENCE",
        reason_codes=tuple(sorted(reasons)),
        candidate_cve_count=candidates,
        matched_asset_count=matched,
        provenance={"context_sha256": str(context.get("sha256") or ""),
                    "discovery_digest": str(context.get("discovery_digest") or "")},
    )
