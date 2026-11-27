"""Strict read-only control-plane revision metadata, NOT the private oracle.

Only a separate LAB_OBSERVER_TOKEN is permitted to query the isolated
authority endpoint. Desired revision is a source-defined expectation, not
independent proof that any enforcer has applied a revocation.
"""
from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request

URL = "http://127.0.0.1:18281/operator/desired-revision"


def collect_desired_revision(observer_token: str) -> dict:
    if not isinstance(observer_token, str) or len(observer_token) < 24:
        raise ValueError("Dedicated read-only authority observer credential required")
    request = urllib.request.Request(
        URL, headers={"X-Lab-Observer": observer_token}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status != 200:
                raise ValueError("Independent observer denied")
            payload = json.loads(response.read(8192))
    except (OSError, urllib.error.URLError, ValueError):
        return {"status": "UNKNOWN", "reason": "AUTHORITY_REVISION_NOT_AVAILABLE"}
    if not isinstance(payload, dict):
        return {"status": "UNKNOWN", "reason": "INVALID_AUTHORITY_RESPONSE"}
    allowed = {"observation_type", "desired_revision",
               "observed_at_epoch_ms", "security_outcome_verified"}
    if set(payload) != allowed:
        return {"status": "UNKNOWN", "reason": "PRIVATE_OR_UNEXPECTED_FIELD"}
    if (payload["observation_type"] != "authority_operator_revision_v1"
            or payload["security_outcome_verified"] is not False
            or type(payload["desired_revision"]) is not int
            or payload["desired_revision"] < 0
            or type(payload["observed_at_epoch_ms"]) is not int
            or payload["observed_at_epoch_ms"] <= 0):
        return {"status": "UNKNOWN", "reason": "INVALID_AUTHORITY_REVISION"}
    return {"status": "OBSERVED_OPERATOR_METADATA",
            "revision": payload["desired_revision"],
            "source_time_epoch_ms": payload["observed_at_epoch_ms"],
            "observed_at_monotonic": time.monotonic(),
            "revocation_state_disclosed": False,
            "oracle_accessed": False,
            "post_action_outcome_proven": False}


def authority_revision_gap(revision: dict, operator_rows: list[dict],
                           *, now_monotonic: float | None = None) -> dict:
    now = time.monotonic() if now_monotonic is None else now_monotonic
    if (not isinstance(revision, dict)
            or revision.get("status") != "OBSERVED_OPERATOR_METADATA"
            or revision.get("revocation_state_disclosed") is not False
            or revision.get("oracle_accessed") is not False
            or type(revision.get("revision")) is not int
            or type(revision.get("observed_at_monotonic")) not in (float, int)
            or not math.isfinite(revision["observed_at_monotonic"])
            or revision["observed_at_monotonic"] > now
            or now - revision["observed_at_monotonic"] > 5
            or not isinstance(operator_rows, list) or len(operator_rows) != 4):
        return {"status": "UNKNOWN", "reason": "MISSING_OR_STALE_OPERATOR_EXPECTATION"}
    expected = revision["revision"]
    gaps = {}
    seen = set()
    for row in operator_rows:
        if (not isinstance(row, dict) or row.get("observed") is not True
                or row.get("node") not in ("enforcer-a", "enforcer-b",
                                            "enforcer-c", "enforcer-hidden")
                or row["node"] in seen or type(row.get("applied_revision")) is not int
                or row["applied_revision"] < 0
                or row["applied_revision"] > expected):
            return {"status": "UNKNOWN", "reason": "UNTRUSTED_ENFORCER_REVISION"}
        seen.add(row["node"])
        gaps[row["node"]] = expected - row["applied_revision"]
    return {"status": "OBSERVED_OPERATOR_REVISION_GAP",
            "expected_revision": expected,
            "per_node_gap": gaps,
            "any_revision_gap": any(x > 0 for x in gaps.values()),
            "verified_policy_outcome": False,
            "known_injected_fault_label": False}
