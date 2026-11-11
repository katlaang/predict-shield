"""Use a locally trained mechanism model behind the typed safety-gate interface.

This adapter performs *prediction only*. It does not run a security action,
claim independent verification, invent a remaining error budget, or assert
that model uncertainty is safe for production. Every prediction is tied to
the same pre-action snapshot, and the independent policy gate must still
authorize its use. Oracle and post-action data are forbidden as inputs.
"""
from __future__ import annotations

from datetime import datetime, timezone

from train import ACTIONS, to_features

from predict_shield.ai_contracts import (
    ActionPrediction, CandidateAction, EvidenceSnapshot, Interval,
)


def predictions_from_bundle(
    bundle: dict, pre_action: dict,
    snapshot: EvidenceSnapshot,
    candidates: tuple[CandidateAction, ...],
) -> tuple[ActionPrediction, ...]:
    """Turn trained estimates into typed, provenance-tagged candidate predictions.

    Expects a bundle trained exclusively on the 60 registered training groups
    and calibrated on 20 disjoint groups. Residual risk is the predicted
    probability-like fraction of post-action oracle-exposed cases. The impact
    quantity uses the predicted *total* failed HTTP request fraction times
    scheduled request attempts. As no background subtraction is implemented,
    the total is conservatively treated as a bound on additional disruption.
    This is not a calibrated real-service error-budget predictor.

    A nonempty verified inventory snapshot and explicit service budgets must
    be established by other components; the adapter cannot create those.
    """
    if (bundle.get("schema") != "predict-shield/mechanism-model-bundle/1"
            or list(bundle.get("features", [])) != list(__import__("train").FEATURES)):
        raise ValueError("Wrong or untrusted model feature schema")
    if pre_action.get("oracle_features_excluded") is not True:
        raise ValueError("Prediction input must be explicit pre-action record")
    if pre_action.get("experiment_type") != "real_kafka_multijvm_lab":
        raise ValueError("Unsupported model input environment")
    if pre_action.get("run_id") is None or not snapshot.snapshot_id:
        raise ValueError("Missing prediction provenance")
    if set(pre_action) & {"oracle", "actual_revoked_access_denied", "post_action"}:
        raise ValueError("Oracle or future outcomes cannot be passed into predictor")
    if snapshot.case_id != pre_action["run_id"]:
        raise ValueError("Evidence snapshot must match the experiment case")
    now = datetime.now(timezone.utc)
    if now < snapshot.captured_at:
        raise ValueError("Evidence timestamp is in the future")
    features = pre_action["features"]
    if (features["fault_mode"] not in __import__("train").FAULTS
            or features["fault_target"] not in __import__("train").TARGETS):
        raise ValueError("Unrecognized fault or target")
    probes = pre_action["external_deny_observations"]
    if not probes or any(p.get("http_status") not in (200, 403) for p in probes):
        raise ValueError("Missing pre-action gateway observations")
    allowed = sum(p["http_status"] == 200 for p in probes) / len(probes)
    risk_model = bundle["models"]["label_security_exposure"]
    impact_model = bundle["models"]["label_service_failure_fraction"]
    risk_radius = bundle["radii"]["label_security_exposure"]
    impact_radius = bundle["radii"]["label_service_failure_fraction"]
    count = float(features["requested_rps"]) * float(features["measurement_seconds"])
    if count <= 0 or count > 3000:
        raise ValueError("Unbounded action-specific scheduled request count")
    bounds = bundle.get("numeric_feature_bounds", {})
    numeric = {
        "cache_ttl_ms": features["cache_ttl_ms"],
        "event_delay_ms": features["event_delay_ms"],
        "requested_rps": features["requested_rps"],
        "initial_gateway_allowed_fraction": allowed,
    }
    out_of_distribution = any(
        name not in bounds or float(value) < bounds[name][0]
        or float(value) > bounds[name][1]
        for name, value in numeric.items()
    )
    if len({c.action_id for c in candidates}) != len(candidates):
        raise ValueError("Candidate IDs must be unique")
    result = []
    for candidate in candidates:
        if candidate.action_id not in ACTIONS or candidate.affected_services != ("authorization",):
            raise ValueError("Unknown action or missing affected service closure")
        example = {
            "action": candidate.action_id,
            "fault": features["fault_mode"],
            "target": features["fault_target"],
            "pre_action": numeric,
        }
        vector = [to_features(example)]
        r = max(0.0, min(1.0, float(risk_model.predict(vector)[0])))
        d = max(0.0, min(1.0, float(impact_model.predict(vector)[0])))
        r_interval = Interval(max(0, r-risk_radius), r, min(1, r+risk_radius))
        d_interval = Interval(max(0, d-impact_radius) * count,
                              d * count,
                              min(1, d+impact_radius) * count)
        result.append(ActionPrediction(
            action_id=candidate.action_id,
            snapshot_id=snapshot.snapshot_id,
            model_name="experiment-b-random-forest",
            model_version=bundle["schema"],
            predicted_at=now,
            residual_risk=r_interval,
            additional_errors={"authorization": d_interval},
            out_of_distribution=out_of_distribution,
            calibration_supported=(
                bundle.get("calibration_group_count", 0) >= 20
                and not out_of_distribution
            ),
            training_fingerprint=bundle["training_fingerprint"],
        ))
    return tuple(result)


def load_local_bundle(path, *, trusted_sha256: str) -> dict:
    """Load only a locally approved model artifact after exact digest validation.

    Scikit-learn/joblib bundles are pickle-based and may execute arbitrary code
    when loaded. The expected SHA-256 must come from independently trusted
    provenance, never from metadata inside the untrusted artifact itself.
    This method must never load user-uploaded or network-fetched model files.
    """
    import hashlib
    import joblib
    from pathlib import Path
    source = Path(path)
    if not source.is_file() or source.is_symlink() or not trusted_sha256:
        raise ValueError("Missing trusted regular local model file or digest")
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    if checksum != trusted_sha256:
        raise ValueError("Model artifact hash does not match trusted fingerprint")
    result = joblib.load(source)
    if not isinstance(result, dict) or result.get("schema") != "predict-shield/mechanism-model-bundle/1":
        raise ValueError("Unexpected model bundle schema")
    return result
