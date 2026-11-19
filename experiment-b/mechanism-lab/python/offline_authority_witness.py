"""Conservative offline authority witness and independent HTTP observation bounds.

A pre-outage witness is evidence that a runner captured a policy snapshot.
Its digest does not authenticate the runner or prove policy freshness.
Offline observations NEVER establish full live-authority verification.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

SCHEMA = "predict-shield/offline-authority-witness/1"
MEASUREMENT = "predict-shield/offline-authority-probe-bounds/1"


def _canonical(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()


def _time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timezone-aware observation time required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError("invalid ISO time") from e
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result.astimezone(timezone.utc)


def freeze_witness(policy: dict, *, authority_http: int | None, inventory: list[str],
                   captured_at: str) -> dict:
    """Capture a policy before the outage, not an after-the-fact assertion."""
    if authority_http != 200 or not isinstance(policy, dict):
        raise ValueError("witness requires a live HTTP 200 authority reading")
    if type(policy.get("revoked")) is not bool or policy["revoked"] is not True:
        raise ValueError("witness must explicitly record a previously committed revocation")
    if not isinstance(policy.get("trialId"), str) or not policy["trialId"]:
        raise ValueError("authority trial identity required")
    if not isinstance(inventory, list) or len(inventory) != 4 or len(set(inventory)) != 4:
        raise ValueError("exactly four distinct declared enforcement nodes required")
    if any(not isinstance(n, str) or not n for n in inventory):
        raise ValueError("invalid node identity")
    when = _time(captured_at).isoformat()
    fields = {
        "schema": SCHEMA, "policy": policy, "authority_http": authority_http,
        "expected_nodes": sorted(inventory), "captured_at": when,
        "source_policy_sha256": hashlib.sha256(_canonical(policy)).hexdigest(),
        "claim": "Runner-supplied pre-outage policy evidence, not authenticated policy truth",
    }
    return dict(fields, witness_sha256=hashlib.sha256(_canonical(fields)).hexdigest())


def validate_witness(witness: dict) -> None:
    if not isinstance(witness, dict) or set(witness) != {
        "schema", "policy", "authority_http", "expected_nodes", "captured_at",
        "source_policy_sha256", "claim", "witness_sha256",
    }:
        raise ValueError("invalid witness schema")
    expected = freeze_witness(
        witness["policy"], authority_http=witness["authority_http"],
        inventory=witness["expected_nodes"], captured_at=witness["captured_at"],
    )
    if expected != witness:
        raise ValueError("pre-outage witness missing, changed, or inconsistent")


def offline_bounds(witness: dict, *, authority_http: int | None,
                   observed_at: str, nodes: list[dict]) -> dict:
    """Use independent direct probes; unknown is bounded, never success."""
    validate_witness(witness)
    if authority_http == 200:
        raise ValueError("live authority returned; use full oracle reconciliation")
    if authority_http is not None:
        raise ValueError("outage only supported for a physically unreachable authority")
    if _time(observed_at) <= _time(witness["captured_at"]):
        raise ValueError("offline observation must postdate pre-outage witness")
    if not isinstance(nodes, list) or len(nodes) != 4:
        raise ValueError("complete declared four-node observation inventory required")
    identities = [n.get("node") for n in nodes if isinstance(n, dict)]
    if sorted(identities) != witness["expected_nodes"]:
        raise ValueError("missing, extra, or duplicate enforcement node")
    denied, allowed, unknown_deny, unknown_allow = 0, 0, 0, 0
    for n in nodes:
        if set(n) != {"node", "revoked_probe_http", "legitimate_probe_http"}:
            raise ValueError("exact direct-probe observation schema required")
        for key in ("revoked_probe_http", "legitimate_probe_http"):
            status = n[key]
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("invalid observed HTTP status")
        denied += n["revoked_probe_http"] == 403
        allowed += n["legitimate_probe_http"] == 200
        unknown_deny += n["revoked_probe_http"] is None
        unknown_allow += n["legitimate_probe_http"] is None
    # A status other than expected is a measured failure, not unknown.
    return {
        "schema": MEASUREMENT, "witness_sha256": witness["witness_sha256"],
        "authority_http": None, "observed_at": _time(observed_at).isoformat(),
        "raw_nodes": nodes, "revoked_denial_fraction_bounds": [
            denied / 4, (denied + unknown_deny) / 4,
        ], "legitimate_access_fraction_bounds": [
            allowed / 4, (allowed + unknown_allow) / 4,
        ],
        "revoked_observed_denied": denied, "legitimate_observed_allowed": allowed,
        "revoked_unknown": unknown_deny, "legitimate_unknown": unknown_allow,
        "authority_truth_current": None, "full_reconciliation": False,
        "verification_outcome": "INDETERMINATE",
        "field_resilience_established": False,
        "offline_utility_is_not_v3_oracle_truth": True,
        "interpretation": "Four independent synthetic-lab direct probes relative to pre-outage witness; full current-policy truth unavailable",
    }
