"""Candidate v4 evidence fusion; NOT a trained detector or a scored attack result.

Strong independently calibrated evidence can alert without being suppressed by
a saturated response-score component. Each gate receives a share of the
benign calibration alert budget (union-bound allocation). Must be evaluated
on entirely new frozen held-out sessions before any efficacy claim.
"""
from __future__ import annotations

import math
from typing import Sequence

SIGNALS = ("request_novelty", "host_novelty", "response_shift",
           "learned_anomaly", "fused_statistic")


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def calibrate_gates(benign_calibration: Sequence[dict], *,
                    alert_budget: float = 0.005) -> dict:
    """Fit only on bona fide benign calibration evidence, never final test.

    The allocation bounds *empirical calibration alerts*, not future FPR.
    Caller must validate provenance and grouped splits separately.
    """
    if not _number(alert_budget) or not 0 < alert_budget < 1:
        raise ValueError("alert budget must be between zero and one")
    if len(benign_calibration) < 1000:
        raise ValueError("need at least 1000 benign calibration observations")
    if any(row.get("role") != "calibration" or row.get("label") != "benign" or
           row.get("truth_basis") != "independently_reviewed_event"
           for row in benign_calibration):
        raise ValueError("calibration requires independently reviewed benign-only rows")
    share = alert_budget / len(SIGNALS)
    if len(benign_calibration) * share < 1:
        raise ValueError("insufficient calibration size for five component gates")
    gates = {}
    for feature in SIGNALS:
        values = [row.get(feature) for row in benign_calibration]
        if any(not _number(x) for x in values):
            raise ValueError("non-finite or missing calibration evidence: " + feature)
        ordered = sorted(values)
        allowance = math.floor(len(values) * share)
        threshold = ordered[len(values) - allowance - 1]
        gates[feature] = threshold

    decisions = [evaluate_gates(r, {"thresholds": gates})["alert"]
                 for r in benign_calibration]
    rate = sum(decisions) / len(decisions)
    if rate > alert_budget:
        raise AssertionError("observed calibration alerts exceed allocated budget")
    return {"schema": "predict-shield/candidate-v4-gates/1",
            "thresholds": gates, "component_budget": share,
            "combined_alert_budget": alert_budget,
            "calibration_benign": len(benign_calibration),
            "calibration_alerts": sum(decisions),
            "calibration_alert_rate": rate,
            "limitations": "No attack-detection or unseen-domain claim; calibrate and freeze before untouched testing."}


def evaluate_gates(observation: dict, config: dict) -> dict:
    gates = config["thresholds"]
    if set(gates) != set(SIGNALS) or any(not _number(gates[k]) for k in SIGNALS):
        raise ValueError("invalid gate configuration")
    missing = [k for k in SIGNALS if not _number(observation.get(k))]
    if missing:
        return {"alert": False, "status": "INDETERMINATE",
                "evidence": [], "missing": missing}
    fired = [k for k in SIGNALS if observation[k] > gates[k]]
    return {"alert": bool(fired), "status": "ALERT" if fired else "NO_ALERT",
            "evidence": fired, "missing": []}
