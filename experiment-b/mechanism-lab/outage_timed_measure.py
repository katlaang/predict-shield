"""Bounded, timed physical gateway observations during an outage action.

The action executes concurrently with real revoked and legitimate HTTP probes.
No authoritative verdict or synthetic remediation utility is inferred.
"""
from __future__ import annotations

import concurrent.futures
import math
import time
from collections import Counter

from pilot import integrate_gateway_exposure, request

WINDOW_SECONDS = 6.0
ACTION_START_SECONDS = 1.0
PROBE_PERIOD_SECONDS = 0.2


def _status_key(status: int | None) -> str:
    return str(status) if status is not None else "unreachable"


def summarize_samples(samples: list[dict], *, window_seconds: float) -> dict:
    """Retain unknown durations and measured legitimate-user failures."""
    if not 0 < window_seconds <= 30 or not samples:
        raise ValueError("Timed observations required")
    revoked = [row for row in samples if row["principal"] == "revoked"]
    authorized = [row for row in samples if row["principal"] == "authorized"]
    legitimate = [row for row in samples if row["principal"] == "legitimate"]
    if not revoked or not authorized or not legitimate:
        raise ValueError("All three observer categories required")
    if any(row["principal"] not in ("revoked", "authorized", "legitimate")
           or type(row["seconds_after_start"]) not in (int, float)
           or not math.isfinite(row["seconds_after_start"])
           or not 0 <= row["seconds_after_start"] <= window_seconds
           for row in samples):
        raise ValueError("Invalid observed probe timestamp/principal")
    # Existing monotonic HTTP integration deliberately treats anything
    # other than protected 200 or 403 as unknown, not denied.
    exposure = integrate_gateway_exposure(
        [{"seconds_after_start": row["seconds_after_start"],
          "http_status": row["http_status"]}
         for row in revoked], window_seconds=window_seconds)
    def report(rows: list[dict]) -> dict:
        counts = Counter(_status_key(row["http_status"]) for row in rows)
        return {"requests": len(rows), "http_status_counts": dict(counts),
                "non_200_requests": sum(row["http_status"] != 200 for row in rows)}
    return {
        "schema": "predict-shield/outage-timed-observations/1",
        "registered_window_seconds": window_seconds,
        "revoked_gateway_exposure": {
            key: exposure[key] for key in (
                "method", "window_seconds", "probe_count", "valid_probe_count",
                "exposure_seconds_lower_bound", "exposure_seconds_upper_bound",
                "unknown_seconds", "exposure_fraction_lower_bound",
                "exposure_fraction_upper_bound")},
        "authorized_protected": report(authorized),
        "legitimate_endpoint": report(legitimate),
        "failure_count_has_measured_denominator": True,
        "sampled_observation_not_continuous_network_truth": True,
        "policy_verification_from_this_measurement": "NOT_EVALUATED",
    }


def observe_during_action(action: str, control: str, compose_dir,
                          action_function, *, window_seconds: float = WINDOW_SECONDS) -> dict:
    """Run intervention inside a fixed monotonic sampling window.

    An action failure is an explicit observed arm result; it never silently
    converts an unavailable authority into a successful resync.
    """
    if not 3 <= window_seconds <= 30:
        raise ValueError("Invalid bounded sampling window")
    start = time.perf_counter()
    observations = []
    action_future = None
    late = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        tick = 0
        while True:
            elapsed = time.perf_counter() - start
            if elapsed >= window_seconds:
                break
            if action_future is None and elapsed >= ACTION_START_SECONDS:
                action_future = pool.submit(action_function, action, control, compose_dir)
            deadline = start + tick * PROBE_PERIOD_SECONDS
            if deadline > time.perf_counter():
                time.sleep(deadline - time.perf_counter())
            if time.perf_counter() - start >= window_seconds:
                break
            principal, route, authorized = (
                ("revoked", "/protected", False),
                ("authorized", "/protected", True),
                ("legitimate", "/legitimate", False),
            )[tick % 3]
            status, _, latency_ms = request("gateway", route,
                                           authorized_lab_user=authorized, timeout=1.0)
            measured_at = time.perf_counter() - start
            if measured_at <= window_seconds:
                observations.append({
                    "principal": principal, "seconds_after_start": measured_at,
                    "http_status": status, "latency_ms": latency_ms,
                })
            else:
                late += 1
            tick += 1
        if action_future is None:
            raise RuntimeError("Registered physical action was never launched")
        # This raises on a failed Docker restart or rejected gateway restriction.
        action_result = action_future.result(timeout=125)
    summary = summarize_samples(observations, window_seconds=window_seconds)
    summary["registered_action_start_seconds"] = ACTION_START_SECONDS
    summary["actual_late_probe_count"] = late
    summary["action_observation"] = action_result
    return summary
