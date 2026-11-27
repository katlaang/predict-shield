"""Privileged pre-outage policy witness and bounded offline target observations.

This cannot certify VERIFIED while the policy authority is unavailable.
It does not supply an AI selector with private policy truth or manufacture
the policy's post-outage state. It is an experimental observation precursor,
NOT a v3.1 four-action cost scorer.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class PolicyWitness:
    trial_id: str
    revision: int
    desired_revoked: bool
    observed_at: str
    commitment_sha256: str
    expected_inventory: int
    expected_nodes: tuple[str, ...]


def capture_witness(snapshot: dict, *, observed_at: datetime) -> PolicyWitness:
    """Capture policy while the authority is actually responding.

    Requires an oracle with four separately listed targets. Their cache
    convergence is NOT required, since a physical fault may already exist.
    """
    policy = snapshot.get("authority")
    if (snapshot.get("authority_http") != 200 or
            snapshot.get("authority_truth_available") is not True or
            not isinstance(policy, dict)):
        raise ValueError("No live authoritative policy to witness")
    trial_id = policy.get("trialId")
    revision = policy.get("revision")
    if (not isinstance(trial_id, str) or not trial_id or len(trial_id) > 256
            or type(revision) is not int or revision <= 0
            or policy.get("revoked") is not True):
        raise ValueError("Expected a committed revoked policy revision")
    targets = snapshot.get("targets")
    inventory = snapshot.get("expected_inventory_count")
    if (type(inventory) is not int or inventory != 4 or
            not isinstance(targets, list) or len(targets) != inventory or
            any(not isinstance(row, dict) or not isinstance(row.get("node"), str)
                or not row["node"] for row in targets)):
        raise ValueError("Witness requires the full declared four-node inventory")
    nodes = tuple(sorted(row["node"] for row in targets))
    if len(set(nodes)) != inventory:
        raise ValueError("Witness requires distinct physical target identities")
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("Observation timestamp must be timezone-aware")
    timestamp = observed_at.astimezone(timezone.utc).isoformat()
    payload = {"trial_id": trial_id, "revision": revision,
               "revoked": True, "observed_at": timestamp,
               "inventory": inventory, "nodes": list(nodes)}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return PolicyWitness(trial_id, revision, True, timestamp,
                         hashlib.sha256(canonical).hexdigest(), inventory, nodes)


def observe_offline(snapshot: dict, witness: PolicyWitness) -> dict:
    """Derive observed-denial exposure bounds, never a full policy verdict.

    All direct HTTP 200 decisions count as observed allow/exposure against
    the *historical witnessed* revoked rule. A 403 with a matching local
    trial ID is a denial observation, not proof of current authority truth.
    Missing, invalid and stale-trial observations remain UNKNOWN.
    """
    if not isinstance(witness, PolicyWitness) or witness.desired_revoked is not True:
        raise ValueError("Invalid pre-outage policy witness")
    if (witness.expected_inventory != 4 or len(witness.expected_nodes) != 4 or
            len(set(witness.expected_nodes)) != 4 or
            any(not isinstance(node, str) or not node for node in witness.expected_nodes)):
        raise ValueError("Invalid witness inventory identities")
    witness_payload = {
        "trial_id": witness.trial_id, "revision": witness.revision,
        "revoked": True, "observed_at": witness.observed_at,
        "inventory": witness.expected_inventory, "nodes": list(witness.expected_nodes),
    }
    commitment = hashlib.sha256(json.dumps(
        witness_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if commitment != witness.commitment_sha256:
        raise ValueError("Pre-outage witness commitment differs from recorded policy and scope")
    if (snapshot.get("authority_http") is not None or
            snapshot.get("authority_truth_available") is not False or
            snapshot.get("inventory_complete") is not False or
            snapshot.get("all_revoked_access_denied") is not None):
        raise ValueError("Offline comparison requires authoritative truth UNKNOWN")
    targets = snapshot.get("targets")
    if (not isinstance(targets, list) or len(targets) != witness.expected_inventory or
            any(not isinstance(t, dict) or not isinstance(t.get("node"), str)
                for t in targets) or
            tuple(sorted(t["node"] for t in targets)) != witness.expected_nodes):
        raise ValueError("Offline target identities differ from frozen pre-outage witness")
    observed_allow = 0
    observed_deny = 0
    unknown = 0
    for t in targets:
        status = t.get("direct_probe_http")
        admin = t.get("admin") or {}
        valid = (t.get("admin_http") == 200 and
                 isinstance(admin, dict) and
                 admin.get("trial_id") == witness.trial_id and
                 type(admin.get("revoked")) is bool)
        if status == 200 and valid:
            observed_allow += 1
        elif status == 403 and valid and admin["revoked"] is True:
            # A denial response from a node that itself reports an allowed
            # policy is not evidence that the revoked rule was enforced.
            observed_deny += 1
        else:
            unknown += 1
    n = witness.expected_inventory
    return {
        "schema": "predict-shield/authority-outage-observation/2",
        "witness_inventory_identical_to_pre_outage": True,
        "pre_outage_witness_sha256": witness.commitment_sha256,
        "witness_timestamp_utc": witness.observed_at,
        "historical_policy_revoked": True,
        "authority_truth_status": "UNKNOWN",
        "verification_status": "INDETERMINATE",
        "observed_allow_count": observed_allow,
        "observed_deny_count": observed_deny,
        "unknown_target_count": unknown,
        "declared_target_count": n,
        "observed_allow_fraction_lower_bound": observed_allow / n,
        "observed_allow_fraction_upper_bound": (observed_allow + unknown) / n,
        "not_live_authoritative_policy_verification": True,
        "not_full_v31_utility": True,
    }
