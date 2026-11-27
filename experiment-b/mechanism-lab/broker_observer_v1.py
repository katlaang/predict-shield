"""Read-only broker-group offset observer for the isolated Kafka lab.

Distinct LAB_OBSERVER_TOKEN (not lab control/oracle tokens) is sent only
to localhost:18287. Never joins Kafka groups, consumes messages, or
converts missing commits into zero lag. An observed backlog cannot prove
a security remediation succeeded.
"""
from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request

BROKER_ENDPOINT = "http://127.0.0.1:18287/operator/broker-offsets"
GROUPS = ("enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden")


def read_broker_offsets(observer_token: str) -> dict:
    if not isinstance(observer_token, str) or len(observer_token) < 24:
        raise ValueError("Dedicated broker observer credential required")
    begin = time.monotonic()
    request = urllib.request.Request(
        BROKER_ENDPOINT, headers={"X-Lab-Observer": observer_token},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise ValueError("Broker offset observer not ready")
            payload = json.loads(response.read(128_000))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {
            "schema": "predict-shield/broker-offset-witness/1",
            "status": "UNKNOWN",
            "reason": "AUTHENTICATED_BROKER_OBSERVATION_UNAVAILABLE",
            "observed_at_monotonic": time.monotonic(),
        }
    observed = time.monotonic()
    if not isinstance(payload, dict):
        raise ValueError("Broker observation must be a JSON object")
    # Attach local receipt metadata to otherwise untrusted remote JSON.
    result = dict(payload)
    result["observed_at_monotonic"] = observed
    result["request_elapsed_seconds"] = observed - begin
    return result


def verify_broker_evidence(observation: dict | None, *,
                           now_monotonic: float | None = None,
                           max_age_seconds: float = 10.0) -> dict:
    """Fail closed on absent, stale, incomplete or inconsistent group offsets.

    End offsets are read before sequential per-group commits, so this is
    **not atomic**. A positive backlog at this moment is not an exact
    measurement of processing lag or a guaranteed failed consumer.
    """
    now = time.monotonic() if now_monotonic is None else now_monotonic
    if type(now) not in (int, float) or not math.isfinite(now):
        raise ValueError("Invalid monotonic decision clock")
    reasons = []
    if not isinstance(observation, dict):
        return {"status": "UNKNOWN", "reasons": ["NO_INDEPENDENT_BROKER_EVIDENCE"],
                "backlog": {}, "source_type": "NONE"}
    if observation.get("schema") != "predict-shield/broker-offset-witness/1":
        reasons.append("UNVERIFIED_BROKER_SCHEMA")
    if (observation.get("status") != "MEASURED"
            or observation.get("observation_type") != "kafka_admin_readonly"
            or observation.get("topic") != "lab-policy"):
        reasons.append("BROKER_OFFSETS_NOT_MEASURED")
    if (observation.get("atomic_snapshot") is not False
            or observation.get("payload_contents_read") is not False
            or observation.get("security_outcome_verified") is not False
            or observation.get("group_membership_observed") is not False):
        reasons.append("INCONSISTENT_BROKER_SCOPE_CLAIMS")
    stamped = observation.get("observed_at_monotonic")
    elapsed = observation.get("request_elapsed_seconds")
    if (type(stamped) not in (float, int) or not math.isfinite(stamped)
            or stamped > now or now - stamped > max_age_seconds
            or type(elapsed) not in (float, int) or not math.isfinite(elapsed)
            or not 0 <= elapsed <= max_age_seconds):
        reasons.append("STALE_OR_INVALID_BROKER_TIMESTAMP")
    groups = observation.get("groups")
    if not isinstance(groups, dict) or set(groups) != set(GROUPS):
        reasons.append("INCOMPLETE_BROKER_CONSUMER_GROUPS")
        return {"status": "UNKNOWN", "reasons": sorted(set(reasons)),
                "backlog": {}, "source_type": "KAFKA_ADMIN_READONLY"}
    backlog = {}
    for name in GROUPS:
        item = groups[name]
        if not isinstance(item, dict) or item.get("status") != "MEASURED":
            reasons.append("MISSING_GROUP_MEASUREMENT")
            continue
        if item.get("consumer_group") != name:
            reasons.append("CONSUMER_GROUP_IDENTITY_MISMATCH")
        count = item.get("total_committed_backlog")
        partitions = item.get("partitions")
        if type(count) is not int or count < 0 or not isinstance(partitions, list) or not partitions:
            reasons.append("INVALID_BROKER_BACKLOG")
            continue
        seen_partitions = set()
        recomputed = 0
        for partition in partitions:
            if not isinstance(partition, dict):
                reasons.append("INVALID_BROKER_PARTITION")
                continue
            ident = partition.get("partition")
            committed = partition.get("committed_offset")
            end = partition.get("log_end_offset")
            behind = partition.get("committed_backlog")
            if (type(ident) is not int or ident < 0 or ident in seen_partitions
                    or any(type(v) is not int or v < 0 for v in
                           (committed, end, behind))
                    or committed > end or end - committed != behind):
                reasons.append("INCONSISTENT_PARTITION_OFFSETS")
                continue
            seen_partitions.add(ident)
            recomputed += behind
        if recomputed != count:
            reasons.append("BROKER_BACKLOG_TOTAL_MISMATCH")
        backlog[name] = count
    return {
        "status": "MEASURED" if not reasons else "UNKNOWN",
        "reasons": sorted(set(reasons)),
        "backlog": backlog,
        "source_type": "KAFKA_ADMIN_READONLY",
        "not_atomic_across_groups": True,
        "evidence_of_security_resolution": False,
        "consumer_processing_correctness_verified": False,
    }
