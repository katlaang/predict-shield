"""Normal-only learned inter-stream physical consistency.

No handwritten attack signatures. A mapping requires physical justification
from topology; a high sample correlation alone does not certify causality.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class PairSpec:
    primary_stream: str
    primary_field: str
    reference_stream: str
    reference_field: str
    max_lag_s: float = 0.25

    def check(self):
        if self.primary_stream == self.reference_stream:
            raise ValueError("a physical relationship needs distinct sensor streams")
        if not self.primary_field or not self.reference_field:
            raise ValueError("explicit measured fields required")
        if not 0 < self.max_lag_s <= 30:
            raise ValueError("invalid physical alignment window")


def channel(record: dict) -> str:
    return f"{record.get('src')}>{record.get('dest')}"


def numeric(record: dict, field: str):
    val = (record.get("data") or {}).get(field)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    num = float(val)
    return num if np.isfinite(num) else None


def aligned(records: list[dict], spec: PairSpec) -> list[dict]:
    """Causal join: only a past or simultaneous reference observation may be used."""
    spec.check()
    ordered = sorted(records, key=lambda row: float(row["timestamp"]))
    ref = []
    for r in ordered:
        if channel(r) == spec.reference_stream:
            val = numeric(r, spec.reference_field)
            if val is not None:
                ref.append((float(r["timestamp"]), val, r.get("malicious") not in (None, False)))
    times = [r[0] for r in ref]
    rows = []
    for r in ordered:
        if channel(r) != spec.primary_stream:
            continue
        val = numeric(r, spec.primary_field)
        if val is None:
            continue
        t = float(r["timestamp"])
        index = bisect.bisect_right(times, t) - 1
        if index < 0 or t - times[index] > spec.max_lag_s:
            rows.append({"timestamp": t, "observed": val, "prediction": None,
                         "reference": None, "truth": "INDETERMINATE"})
            continue
        rt, reference, ref_malicious = ref[index]
        label = r.get("malicious") not in (None, False)
        rows.append({"timestamp": t, "observed": val, "prediction": None,
                     "reference": reference,
                     "truth": "ATTACK_LABELED_PRIMARY" if label else
                              "REFERENCE_ATTACK_CONTEXT" if ref_malicious else "UNLABELED",
                     "lag_s": round(t - rt, 8)})
    return rows


def quantile_threshold(values, false_rate: float) -> float:
    sample = np.sort(np.asarray(values, dtype=float))
    if len(sample) == 0:
        raise ValueError("cannot calibrate on empty normals")
    allowed = int(np.floor(false_rate * len(sample)))
    return float(sample[len(sample) - 1 - allowed])


def train(records: list[dict], spec: PairSpec) -> tuple[dict, dict]:
    pairs = [r for r in aligned(records, spec) if r["reference"] is not None]
    if len(pairs) < 50:
        raise ValueError("insufficient paired normal behavior, abstaining")
    if any(r["truth"] != "UNLABELED" for r in pairs):
        raise ValueError("development cannot contain attack labels")
    cut = int(len(pairs) * 0.7)
    ref = np.asarray([r["reference"] for r in pairs], dtype=float)
    observed = np.asarray([r["observed"] for r in pairs], dtype=float)
    x = ref[:cut]
    y = observed[:cut]
    if np.std(x) < 1e-6 or np.std(y) < 1e-6:
        raise ValueError("insufficient normal-state variation for a learned relationship")
    correlation = float(np.corrcoef(x, y)[0, 1])
    if abs(correlation) < 0.65:
        raise ValueError("no well-supported linear inter-stream relation")
    slope = float(np.cov(x, y, bias=True)[0, 1] / np.var(x))
    intercept = float(y.mean() - slope * x.mean())
    residuals = np.abs(observed[cut:] - (slope * ref[cut:] + intercept))
    threshold = quantile_threshold(residuals, 0.01)
    model = {"schema": "predict-shield/learned-stream-relationship/1",
             "spec": asdict(spec), "slope": slope, "intercept": intercept,
             "threshold": threshold, "normal_training_pairs": cut,
             "normal_calibration_pairs": len(pairs) - cut,
             "training_correlation": correlation,
             "calibration_alerts": int((residuals > threshold).sum())}
    model["model_sha256"] = hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest()
    diagnostics = {"paired_rows": len(pairs),
                   "unpaired_rows": sum(r["reference"] is None for r in aligned(records, spec)),
                   "normal_calibration_alert_rate": float((residuals > threshold).mean())}
    return model, diagnostics


def score(records: list[dict], frozen: dict) -> dict:
    model = dict(frozen)
    claimed = model.pop("model_sha256")
    if hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest() != claimed:
        raise ValueError("frozen relationship is tampered with")
    spec = PairSpec(**model["spec"])
    pairs = aligned(records, spec)
    outcomes = []
    for row in pairs:
        if row["reference"] is None:
            outcomes.append({**row, "outcome": "INDETERMINATE"})
            continue
        expected = model["slope"] * row["reference"] + model["intercept"]
        residual = abs(row["observed"] - expected)
        outcomes.append({**row, "prediction": round(expected, 8),
                         "residual": round(residual, 8),
                         "outcome": "ANOMALY" if residual > model["threshold"] else "NO_ALERT"})
    eligible = [r for r in outcomes if r["outcome"] != "INDETERMINATE"]
    labeled = [r for r in eligible if r["truth"] == "ATTACK_LABELED_PRIMARY"]
    other = [r for r in eligible if r["truth"] != "ATTACK_LABELED_PRIMARY"]
    return {"schema": "predict-shield/cross-stream-test/1", "model_sha256": claimed,
            "total_primary_messages": len(outcomes), "scorable_pairs": len(eligible),
            "indeterminate": len(outcomes) - len(eligible),
            "primary_attack_labeled": len(labeled),
            "primary_attack_alerts": sum(r["outcome"] == "ANOMALY" for r in labeled),
            "non_primary_labeled_alerts": sum(r["outcome"] == "ANOMALY" for r in other),
            "normal_false_positive_rate": None, "cross_network_generalization": None,
            "warning": "Reference-context anomalies cannot be counted as true-positive detections of unlabeled primary records.",
            "events": outcomes}


def main():
    from gzip import open as gzip_open
    p = argparse.ArgumentParser()
    p.add_argument("--normal", type=Path, required=True)
    p.add_argument("--attack", type=Path)
    p.add_argument("--primary-stream", required=True)
    p.add_argument("--primary-field", required=True)
    p.add_argument("--reference-stream", required=True)
    p.add_argument("--reference-field", required=True)
    p.add_argument("--max-lag-s", type=float, default=0.25)
    p.add_argument("--output-dir", type=Path, required=True)
    a = p.parse_args()
    def read(path):
        opener = gzip_open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    if a.output_dir.exists():
        raise ValueError("output directory must be new; do not overwrite frozen measurements")
    a.output_dir.mkdir(parents=True)
    spec = PairSpec(a.primary_stream, a.primary_field,
                    a.reference_stream, a.reference_field, a.max_lag_s)
    model, diagnostics = train(read(a.normal), spec)
    (a.output_dir / "freeze.json").write_text(json.dumps(model, indent=2, sort_keys=True) + "\n")
    (a.output_dir / "development-report.json").write_text(json.dumps(diagnostics, indent=2) + "\n")
    if a.attack:
        report = score(read(a.attack), model)
        (a.output_dir / "test-report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "events"}, indent=2))
    else:
        print(json.dumps(diagnostics))


if __name__ == "__main__":
    main()
