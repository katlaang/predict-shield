"""Exploratory chronological learned *KEV-addition proxy* ranking.

This is not a confirmatory holdout evaluation, calibrated exploitation
probability, production asset risk model, or evidence of autonomous defense.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import tempfile
from datetime import date, timedelta
from pathlib import Path

from .archive_acquire import _download, source_url
from .threat_intel import read_epss, read_kev

NEGATIVE_SAMPLE_MODULUS = 100
NEGATIVE_SAMPLE_THRESHOLD = 3
TRAIN_SPLIT = "train"


def load_window(window: dict, future: dict, fetcher=_download) -> dict:
    """Load point-in-time features and a separate future KEV catalog label."""
    cutoff = date.fromisoformat(window["as_of"])
    horizon = cutoff + timedelta(days=window["horizon_days"])
    if date.fromisoformat(future["snapshot_date"]) < horizon:
        raise ValueError("Future catalog does not cover label horizon")
    with tempfile.TemporaryDirectory(prefix="ps-intel-") as folder:
        paths = {}
        hashes = {}
        for key, source in (("epss", window["epss"]),
                            ("kev_before", window["kev_before"]),
                            ("kev_after", future)):
            observed = date.fromisoformat(source["snapshot_date"])
            if key != "kev_after" and (
                    observed > cutoff or date.fromisoformat(source["commit_observed_date"]) > cutoff):
                raise ValueError("Feature source exists after cutoff")
            raw = fetcher(source_url(source))
            if not isinstance(raw, bytes) or not raw:
                raise ValueError("Missing official archive bytes")
            path = Path(folder) / ("epss.csv.gz" if key == "epss" else key + ".json")
            path.write_bytes(raw)
            paths[key] = path
            hashes[key] = hashlib.sha256(raw).hexdigest()
        epss, _ = read_epss(paths["epss"], window["epss"]["snapshot_date"], window["as_of"])
        before, _ = read_kev(paths["kev_before"], window["kev_before"]["snapshot_date"], window["as_of"])
        future_kev, _ = read_kev(paths["kev_after"], future["snapshot_date"], future["snapshot_date"])
        raw = paths["epss"].read_bytes()
        decoded = gzip.decompress(raw).decode("utf-8-sig") if raw.startswith(b"\x1f\x8b") else raw.decode("utf-8-sig")
        source = csv.DictReader(io.StringIO("\n".join(
            line for line in decoded.splitlines() if line.strip() and not line.startswith("#"))))
        if not {"cve","epss","percentile"}.issubset(source.fieldnames or []):
            raise ValueError("EPSS archive missing core features")
        rows = []
        known = set(before)
        new_kev = {cve for cve, added in future_kev.items()
                   if cutoff < date.fromisoformat(added) <= horizon and cve not in known}
        for row in source:
            cve = row["cve"].strip().upper()
            if cve in known:
                continue
            probability = epss[cve]
            percentile = float(row["percentile"])
            if not math.isfinite(percentile) or not 0 <= percentile <= 1:
                raise ValueError("Invalid historical EPSS percentile")
            year = int(cve.split("-")[1])
            age = max(0, cutoff.year - year)
            # No target labels, future dates or post-action measurements in features.
            features = [math.log((probability + 1e-6)/(1.000001 - probability)),
                        percentile, min(age, 30)]
            label = int(cve in new_kev)
            rows.append((cve, features, probability, label))
        if not rows:
            raise ValueError("No historical eligible CVEs")
        return {"partition": window["partition"], "as_of": window["as_of"],
                "horizon_end": horizon.isoformat(), "records": rows,
                "covered_additions": sum(row[3] for row in rows),
                "all_additions": len(new_kev), "source_hashes": hashes}


def sample_training(rows: list[dict]) -> tuple[list[list[float]], list[int]]:
    features, labels = [], []
    for window in rows:
        if window["partition"] != TRAIN_SPLIT:
            raise ValueError("Only predeclared training windows permitted in model fit")
        for cve, vector, _, label in window["records"]:
            select = int(hashlib.sha256((cve+"|"+window["as_of"]).encode()).hexdigest()[:8],16) % NEGATIVE_SAMPLE_MODULUS
            if label or select < NEGATIVE_SAMPLE_THRESHOLD:
                features.append(vector)
                labels.append(label)
    if 0 not in labels or 1 not in labels:
        raise ValueError("Insufficient positive and negative labels for trained study")
    return features, labels


def rank_metrics(rows: list[tuple], learned_scores: list[float]) -> dict:
    from sklearn.metrics import average_precision_score
    if len(rows) != len(learned_scores):
        raise ValueError("Score count mismatch")
    labels = [r[3] for r in rows]
    epss = [r[2] for r in rows]
    outputs = {}
    for key, scores in (("epss_only", epss),("learned_reranker", learned_scores)):
        order = sorted(range(len(scores)), key=lambda i: (-scores[i], rows[i][0]))
        outputs[key] = {
            "average_precision": float(average_precision_score(labels, scores)) if any(labels) else None,
            "precision_at_100": sum(labels[i] for i in order[:100])/min(100,len(order)),
            "precision_at_1000": sum(labels[i] for i in order[:1000])/min(1000,len(order)),
        }
    return outputs


def evaluate_manifest(manifest: dict, fetcher=_download) -> dict:
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    if manifest.get("schema") != "predict-shield/exploratory-chronological-model/1":
        raise ValueError("Wrong study manifest schema")
    windows = [load_window(w, manifest["source_outcome"], fetcher=fetcher)
               for w in manifest["windows"]]
    if [w["partition"] for w in windows] != [
            "train","train","train","diagnostic","previously_inspected_exploratory"]:
        raise ValueError("Unexpected temporal split order")
    if [w["as_of"] for w in windows] != sorted(w["as_of"] for w in windows):
        raise ValueError("Chronological windows out of order")
    X, y = sample_training(windows[:3])
    model = make_pipeline(StandardScaler(),
                          LogisticRegression(max_iter=400, class_weight="balanced",
                                             random_state=20261112))
    model.fit(X, y)
    reports = []
    for window in windows[3:]:
        values = model.decision_function([r[1] for r in window["records"]])
        reports.append({"as_of": window["as_of"], "partition": window["partition"],
                        "eligible_cves": len(window["records"]),
                        "catalog_additions_in_horizon": window["all_additions"],
                        "additions_with_prior_epss": window["covered_additions"],
                        "rank_metrics": rank_metrics(window["records"], list(values)),
                        "source_hashes": window["source_hashes"]})
    return {"schema": "predict-shield/exploratory-chronological-model-results/1",
            "train_windows": [w["as_of"] for w in windows[:3]],
            "sampled_training_rows": len(y),
            "sampled_training_positives": sum(y),
            "feature_names": ["historical_epss_logit","historical_epss_percentile","cve_year_age"],
            "trained_model": "standard_scaler_logistic_regression_fixed_parameters",
            "no_calibrated_probabilities": True,
            "future_kev_catalog_addition_is_only_proxy": True,
            "october_previously_inspected_not_confirmatory": True,
            "diagnostic_and_exploratory_windows": reports,
            "no_model_superiority_claim": True}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--manifest",required=True)
    p.add_argument("--output",required=True)
    a = p.parse_args()
    result = evaluate_manifest(json.loads(Path(a.manifest).read_text()))
    out = Path(a.output)
    with out.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"trained": True, "sampled_training_rows": result["sampled_training_rows"],
                      "sampled_training_positives": result["sampled_training_positives"],
                      "windows": result["diagnostic_and_exploratory_windows"]},indent=2))


if __name__ == "__main__":
    main()
