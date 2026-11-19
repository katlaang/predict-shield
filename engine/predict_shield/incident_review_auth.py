"""Verify incident-review authorizations before using labels to train AI.

A signature authenticates *which registered reviewer signed a claim*, NOT
whether an ATTACK/BENIGN verdict is factually correct. Key registration and
reviewer independence must be established by the operator out of band.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .incident_feedback import validated_feedback

_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{128}$")
_ENVELOPE_FIELDS = frozenset(("review", "signature"))
_REVIEW_FIELDS = frozenset((
    "schema", "incident_id", "asset_group", "split", "detected_at",
    "signal_source_id", "alert_evidence_sha256", "pre_action_features",
    "independent_review",
))
_LABEL_FIELDS = frozenset((
    "verdict", "reviewer_id", "reviewed_at", "independent_evidence_sha256",
))


@dataclass(frozen=True)
class RegisteredReviewer:
    reviewer_id: str
    public_key_ed25519_hex: str
    permitted_asset_groups: frozenset[str]
    independent_of_sources: frozenset[str]

    def validate(self) -> None:
        if not isinstance(self.reviewer_id, str) or not self.reviewer_id:
            raise ValueError("reviewer ID required")
        if not isinstance(self.public_key_ed25519_hex, str) or not _HEX32.fullmatch(self.public_key_ed25519_hex):
            raise ValueError("reviewer key must be 32-byte lowercase hex")
        if not isinstance(self.permitted_asset_groups, frozenset) or not self.permitted_asset_groups:
            raise ValueError("reviewer must have registered asset scope")
        if not isinstance(self.independent_of_sources, frozenset) or not self.independent_of_sources:
            raise ValueError("independent alert-source scope required")


def review_message(record: dict) -> bytes:
    """Signed canonical record, binding verdict to source, original digest and features."""
    if not isinstance(record, dict) or set(record) != _REVIEW_FIELDS:
        raise ValueError("signed review needs exactly the registered fields")
    label = record.get("independent_review")
    if not isinstance(label, dict) or set(label) != _LABEL_FIELDS:
        raise ValueError("signed review must contain exact label fields")
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def verify_reviews(envelopes: list[dict], registry: dict[str, RegisteredReviewer]) -> dict:
    """Verify signatures and return a *structurally validated* learning dataset.

    Rejects missing, unregistered, rotated, out-of-scope, reused or forged
    reviewer identities; a signature cannot establish correctness of the
    underlying verdict or the archived evidence digest.
    """
    if not isinstance(envelopes, list) or not envelopes:
        raise ValueError("at least one signed review required")
    if not isinstance(registry, dict) or not registry:
        raise ValueError("trusted reviewer registry required")
    keys: set[str] = set()
    for name, reviewer in registry.items():
        if not isinstance(reviewer, RegisteredReviewer) or name != reviewer.reviewer_id:
            raise ValueError("invalid registered reviewer")
        reviewer.validate()
        if reviewer.public_key_ed25519_hex in keys:
            raise ValueError("one key cannot masquerade as multiple independent reviewers")
        keys.add(reviewer.public_key_ed25519_hex)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    records: list[dict] = []
    seen: set[str] = set()
    for envelope in envelopes:
        if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
            raise ValueError("review envelope must have record and signature")
        record, signature = envelope["review"], envelope["signature"]
        message = review_message(record)
        if not isinstance(signature, str) or not _HEX64.fullmatch(signature):
            raise ValueError("invalid Ed25519 review signature")
        label = record["independent_review"]
        reviewer = registry.get(label["reviewer_id"])
        if reviewer is None:
            raise ValueError("unregistered reviewer")
        if record["asset_group"] not in reviewer.permitted_asset_groups:
            raise ValueError("reviewer not authorized for asset group")
        if record["signal_source_id"] not in reviewer.independent_of_sources:
            raise ValueError("reviewer independence not registered for alert source")
        if record["incident_id"] in seen:
            raise ValueError("repeated incident review")
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(reviewer.public_key_ed25519_hex))
            key.verify(bytes.fromhex(signature), message)
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("incident review signature invalid") from exc
        seen.add(record["incident_id"])
        records.append(record)

    prepared = validated_feedback(records)
    prepared["authentication"] = {
        "method": "ed25519",
        "review_signatures_verified": len(records),
        "reviewer_identities_independently_vetted": False,
        "review_evidence_content_checked": False,
        "ground_truth_confirmed": False,
        "signatures_sha256": hashlib.sha256(
            json.dumps(
                [x["signature"] for x in envelopes],
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    return prepared


def train_on_authenticated_reviews(envelopes: list[dict], registry: dict[str, RegisteredReviewer]) -> tuple[dict, dict]:
    """Run the existing learned baseline only after reviewer signature checks.

    Signature verification is *not* a replacement for independent label
    adjudication. Model remains uncalibrated and forbidden from action control.
    """
    prepared = verify_reviews(envelopes, registry)
    from .incident_detection_model import train_and_evaluate

    model, report = train_and_evaluate([e["review"] for e in envelopes])
    model["provenance_authentication"] = "REGISTERED_ED25519_REVIEW_SIGNATURES"
    model["registered_reviewer_signatures_sha256"] = prepared["authentication"]["signatures_sha256"]
    model["label_ground_truth_confirmed"] = False
    report["review_authentication"] = prepared["authentication"]
    report["field_accuracy_established"] = False
    return model, report
