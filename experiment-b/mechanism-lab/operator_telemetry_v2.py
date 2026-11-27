"""Operator-only v2 collector that does not modify the LOCKED v3.1 pilot.py.

This queries /operator/telemetry on each enforcer with the existing scoped
LAB control credential. Do not treat the credential as least-privilege
production access. No oracle, injected-fault metadata, or future labels.
"""
from __future__ import annotations

import time
from pilot import ENFORCERS, request


def operator_telemetry_v2(control_token: str) -> list[dict]:
    if not isinstance(control_token, str) or len(control_token) < 24:
        raise ValueError("Disposable authenticated operator control credential required")
    rows = []
    for node in ENFORCERS:
        status, payload, latency = request(
            node, "/operator/telemetry", token=control_token, timeout=1.5
        )
        if (status != 200 or not isinstance(payload, dict)
                or payload.get("instance") != node
                or payload.get("observation_type") != "operator_pre_action_v2"):
            rows.append({"node": node, "observed": False,
                         "consumer_state_observed": False,
                         "latency_ms": latency})
            continue
        rows.append({
            "node": node, "observed": True,
            "observed_at_monotonic": time.monotonic(),
            "observed_at_epoch_ms": payload.get("observed_at_epoch_ms"),
            "applied_revision": payload["applied_revision"],
            "cache_age_ms": payload["cache_age_ms"],
            "cache_ttl_ms": payload["cache_ttl_ms"],
            "legitimate_service_latency_ms": payload["legitimate_service_latency_ms"],
            "handled_events": payload["handled_events"],
            "refresh_failed": payload["refresh_failed"],
            "scheduled_callbacks_pending": payload["scheduled_callbacks_pending"],
            "consumer_state_observed": payload["consumer_state_observed"],
            "consumer_running": payload["consumer_running"],
            "consumer_paused": payload["consumer_paused"],
            "consumer_pause_requested": payload["consumer_pause_requested"],
            "broker_consumer_lag_measured": False,
            "latency_ms": latency,
        })
    return rows
