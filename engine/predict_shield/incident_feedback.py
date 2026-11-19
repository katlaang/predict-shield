"""Fail-closed preparation of independently reviewed incident labels for AI detection.

This is a DATA CONTRACT, not a deployed attack detector or continuous learner.
Review attribution and SHA-256 syntax are structural checks, not identity
authentication. A trained model may only use pre-detection evidence features.
Do not convert unreviewed alerts or remediation success into attack labels.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime

SCHEMA = "predict-shield/incident-feedback/1"
FEATURES = ("network_alert", "endpoint_alert", "known_vulnerability",
            "observed_remote_access", "critical_service_count", "independent_source_count")
BOOLEANS = frozenset(FEATURES[:4])
COUNTS = frozenset(FEATURES[4:])
SPLITS = frozenset(("train", "calibration", "test"))
VERDICTS = frozenset(("ATTACK", "BENIGN", "UNKNOWN"))
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be ISO 8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone-aware timestamps required")
    return parsed


def _sha(value: str) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _require_id(value, field: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError("invalid " + field)


def validated_feedback(items: list[dict]) -> dict:
    """Return independently reviewed, correctly partitioned pre-action rows.

    Records marked UNKNOWN are retained in provenance counts but are never
    silently converted into BENIGN or placed into supervised training.
    """
    if not isinstance(items, list) or not items:
        raise ValueError("at least one incident record required")
    ids: set[str] = set()
    assets: dict[str, str] = {}
    rows: list[dict] = []
    excluded: Counter = Counter()
    for item in items:
        if not isinstance(item, dict) or item.get("schema") != SCHEMA:
            raise ValueError("unsupported incident evidence schema")
        ident, asset, split = item.get("incident_id"), item.get("asset_group"), item.get("split")
        _require_id(ident, "incident_id")
        _require_id(asset, "asset_group")
        if ident in ids or split not in SPLITS:
            raise ValueError("duplicate incident or invalid split")
        ids.add(ident)
        if asset in assets and assets[asset] != split:
            raise ValueError("asset-group leakage across dataset splits")
        assets[asset] = split
        detected = _timestamp(item.get("detected_at"))
        if not _sha(item.get("alert_evidence_sha256")):
            raise ValueError("missing alert evidence digest")
        signal_source = item.get("signal_source_id")
        _require_id(signal_source, "signal_source_id")
        label = item.get("independent_review")
        if not isinstance(label, dict) or label.get("verdict") not in VERDICTS:
            raise ValueError("independent review record required, including UNKNOWN")
        reviewer = label.get("reviewer_id")
        _require_id(reviewer, "reviewer_id")
        if reviewer == signal_source:
            raise ValueError("alert source cannot label its own incident")
        if _timestamp(label.get("reviewed_at")) < detected:
            raise ValueError("review cannot predate detection")
        if not _sha(label.get("independent_evidence_sha256")):
            raise ValueError("independent review evidence digest required")
        if label["independent_evidence_sha256"] == item["alert_evidence_sha256"]:
            raise ValueError("independent review requires a separate evidence digest")
        raw = item.get("pre_action_features")
        if not isinstance(raw, dict) or set(raw) != set(FEATURES):
            raise ValueError("exact pre-action feature schema required")
        for key in BOOLEANS:
            if type(raw[key]) is not bool:
                raise ValueError("non-Boolean pre-action feature: " + key)
        for key in COUNTS:
            if type(raw[key]) is not int or not 0 <= raw[key] <= 100000:
                raise ValueError("invalid pre-action count: " + key)
        if label["verdict"] == "UNKNOWN":
            excluded["UNKNOWN"] += 1
            continue
        rows.append({"incident_id": ident, "asset_group": asset, "split": split,
                     "features": {key: int(raw[key]) for key in FEATURES},
                     "label_attack": int(label["verdict"] == "ATTACK"),
                     "reviewer_id": reviewer,
                     "review_evidence_sha256": label["independent_evidence_sha256"]})
    frozen = json.dumps(rows, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {"schema": "predict-shield/incident-learning-dataset/1",
            "feature_names": list(FEATURES), "rows": rows,
            "included": len(rows), "excluded_unknown": excluded["UNKNOWN"],
            "sha256": hashlib.sha256(frozen.encode()).hexdigest(),
            "claim": "structural provenance only; independently identified reviewers not authenticated by this module"}


def score_detection(predictions: list[dict], prepared: dict) -> dict:
    """Evaluate frozen prediction decisions against known reviewed labels.

    This cannot validate the truth of reviewer-provided labels or estimate
    real-world false-positive rates without representative independently
    labeled benign traffic. No unknown-label records are scored.
    """
    truth = {r["incident_id"]: r for r in prepared["rows"] if r["split"] == "test"}
    if not truth:
        raise ValueError("no independently reviewed test cases")
    if not isinstance(predictions, list) or len(predictions) != len(truth):
        raise ValueError("prediction count does not match the exact test population")
    observed: set[str] = set()
    counts = Counter()
    for prediction in predictions:
        if not isinstance(prediction, dict):
            raise ValueError("prediction record required")
        ident, value = prediction.get("incident_id"), prediction.get("predict_attack")
        if ident not in truth or ident in observed or type(value) is not bool:
            raise ValueError("unexpected, duplicate or invalid prediction")
        observed.add(ident)
        actual = bool(truth[ident]["label_attack"])
        counts["TP" if value and actual else "FP" if value else "FN" if actual else "TN"] += 1
    def fraction(n, d):
        return n / d if d else None
    tp, fp, fn, tn = (counts[k] for k in ("TP", "FP", "FN", "TN"))
    return {"test_cases": len(truth), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "recall": fraction(tp, tp + fn), "precision": fraction(tp, tp + fp),
            "false_positive_rate": fraction(fp, fp + tn),
            "label_ground_truth_independently_authenticated": False,
            "field_detection_accuracy_established": False}
