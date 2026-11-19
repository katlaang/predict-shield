"""Grouped, SHA-pinned CTU-13 *flow* detection evaluation.

Records with Botnet labels are positives, Normal labels are negatives,
Background and all ambiguous labels are UNKNOWN and never training negatives.
Each scenario belongs to only one split. Sampling is class-stratified,
so reported precision is sample precision, NOT operational precision.
No downloads, network access, production actuation, or deployment.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import random

SCHEMA = "predict-shield/ctu13-flow-protocol/2"
CANDIDATE_THRESHOLDS = (0.10, 0.20, 0.35, 0.50, 0.65, 0.80, 0.90, 0.95, 1.00)
SPLITS = ("train", "calibration", "test")
FIELDS = ("StartTime", "Dur", "Proto", "SrcAddr", "Sport", "Dir", "DstAddr",
          "Dport", "State", "sTos", "dTos", "TotPkts", "TotBytes", "SrcBytes", "Label")
NUMERIC = ("Dur", "TotPkts", "TotBytes", "SrcBytes")
PROTOCOLS = ("tcp", "udp", "icmp")
MAX_SOURCE_BYTES = 2_000_000_000


def classify_label(raw: str) -> int | None:
    """CTU-13 publisher labels; unknown is not equivalent to Normal."""
    if not isinstance(raw, str):
        return None
    label = raw.strip().lower()
    # The original CTU-13 publisher explicitly warns that To-Botnet and
    # To-Normal flows originate from unknown hosts. Only From- labels
    # identify flows originating from the known botnet/normal machines.
    if "botnet" in label and "normal" in label:
        return None
    if label.startswith("from-botnet"):
        return 1
    if label.startswith("from-normal"):
        return 0
    return None


def feature(row: dict) -> list[float]:
    """Exclude IPs, capture time and scenario identifiers to reduce leakage."""
    out = []
    for field in NUMERIC:
        try:
            n = float(row[field])
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("missing numeric flow field " + field) from exc
        if not math.isfinite(n) or n < 0 or n > 1e15:
            raise ValueError("non-finite/invalid flow measure " + field)
        out.append(math.log1p(n))
    protocol = str(row.get("Proto", "")).strip().lower()
    out.extend(float(protocol == p) for p in PROTOCOLS)
    return out


def _validate_manifest(manifest: dict, root: Path) -> list[dict]:
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported registered protocol")
    cap = manifest.get("sample_cap_per_label_per_scenario")
    max_fpr = manifest.get("max_calibration_sample_false_positive_rate")
    if type(max_fpr) not in (float, int) or isinstance(max_fpr, bool) or not (
            math.isfinite(max_fpr) and 0.0 <= max_fpr <= 0.25):
        raise ValueError("pre-registered calibration sample FPR cap must be in [0, 0.25]")
    if type(cap) is not int or not 1 <= cap <= 50000:
        raise ValueError("pre-registered class-stratified cap required")
    sources = manifest.get("scenarios")
    if not isinstance(sources, list) or len(sources) < 3:
        raise ValueError("separate training, calibration and test scenarios required")
    names, paths = set(), set()
    splits = Counter()
    for entry in sources:
        if not isinstance(entry, dict) or set(entry) != {"scenario_id", "split", "file", "sha256"}:
            raise ValueError("each scenario needs exactly id, split, file and SHA-256")
        sid, split, source, digest = (entry[k] for k in ("scenario_id", "split", "file", "sha256"))
        if not isinstance(sid, str) or not sid or sid in names:
            raise ValueError("unique scenario ID required")
        if split not in SPLITS:
            raise ValueError("unrecognized split")
        if not isinstance(source, str) or not source or Path(source).is_absolute() or ".." in Path(source).parts:
            raise ValueError("source path must remain inside the approved data directory")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("exact source file SHA-256 required")
        location = (root / source).resolve()
        if not location.is_relative_to(root.resolve()) or source in paths:
            raise ValueError("duplicate or escaping source path")
        paths.add(source)
        names.add(sid)
        splits[split] += 1
    if any(splits[s] == 0 for s in SPLITS):
        raise ValueError("at least one scenario per split required")
    return sources


def _read_one(entry: dict, root: Path, cap: int) -> tuple[list[tuple[list[float], int]], dict]:
    path = (root / entry["file"]).resolve()
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("source file missing or too large: " + entry["file"])
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != entry["sha256"]:
        raise ValueError("file SHA-256 mismatch: " + entry["file"])
    counts = Counter()
    samples: dict[int, list] = {0: [], 1: []}
    seed = int.from_bytes(hashlib.sha256(entry["scenario_id"].encode()).digest()[:8], "big")
    rng = random.Random(seed)
    with path.open(encoding="utf-8-sig", errors="strict", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or not set(FIELDS).issubset(set(reader.fieldnames)):
            raise ValueError("CTU-13 binetflow header missing expected columns: " + entry["file"])
        for row in reader:
            label = classify_label(row.get("Label"))
            if label is None:
                counts["unknown"] += 1
                continue
            counts["botnet" if label else "normal"] += 1
            try:
                vec = feature(row)
            except ValueError:
                counts["malformed_labeled"] += 1
                continue
            bucket = samples[label]
            seen = counts["botnet" if label else "normal"]
            if len(bucket) < cap:
                bucket.append((vec, label))
            else:
                idx = rng.randrange(seen)
                if idx < cap:
                    bucket[idx] = (vec, label)
    if counts["malformed_labeled"]:
        raise ValueError("malformed labeled flows cannot silently disappear")
    return samples[0] + samples[1], {
        "scenario_id": entry["scenario_id"], "split": entry["split"],
        "source_sha256": digest.hexdigest(),
        "total_botnet": counts["botnet"], "total_normal": counts["normal"],
        "excluded_unknown": counts["unknown"],
        "sample_botnet": len(samples[1]), "sample_normal": len(samples[0]),
        "sample_cap_per_class": cap,
    }


def run(manifest: dict, manifest_bytes: bytes, root: Path) -> tuple[dict, dict]:
    sources = _validate_manifest(manifest, root)
    rows = {s: [] for s in SPLITS}
    stats = []
    for entry in sources:
        sample, record = _read_one(entry, root, manifest["sample_cap_per_label_per_scenario"])
        rows[entry["split"]].extend(sample)
        stats.append(record)
    if any(not rows[s] for s in SPLITS) or any(
            set(y for _, y in rows[split]) != {0, 1}
            for split in ("train", "calibration", "test")):
        raise ValueError("every partition must contain both Botnet and Normal labels; never silently drop missing classes")
    from sklearn.linear_model import LogisticRegression
    model = LogisticRegression(max_iter=1000, solver="liblinear", random_state=20261118, class_weight="balanced")
    model.fit([x for x, _ in rows["train"]], [y for _, y in rows["train"]])
    # Threshold is chosen exclusively from a pre-registered candidate grid
    # using CALIBRATION samples, never inspection of held-out test labels.
    calibration_x = [x for x, y in rows["calibration"]]
    calibration_y = [y for x, y in rows["calibration"]]
    calibration_prob = model.predict_proba(calibration_x)[:, 1].tolist()
    calibration_normal_count = calibration_y.count(0)
    max_fpr = manifest["max_calibration_sample_false_positive_rate"]
    evaluations = []
    for threshold_candidate in CANDIDATE_THRESHOLDS:
        false_positives = sum(p >= threshold_candidate
                              for p, label in zip(calibration_prob, calibration_y)
                              if label == 0)
        true_positives = sum(p >= threshold_candidate
                             for p, label in zip(calibration_prob, calibration_y)
                             if label == 1)
        evaluations.append({
            "threshold": threshold_candidate,
            "calibration_false_positives": false_positives,
            "calibration_normals": calibration_normal_count,
            "calibration_true_positives": true_positives,
            "calibration_attacks": calibration_y.count(1),
            "calibration_sample_false_positive_rate": false_positives / calibration_normal_count,
        })
    eligible = [entry for entry in evaluations
                if entry["calibration_sample_false_positive_rate"] <= max_fpr]
    if not eligible:
        raise ValueError("no preregistered threshold satisfies calibration false-positive cap")
    # From eligible thresholds, choose lowest to favor calibration recall.
    # This is a fixed rule, not cherry-picking on held-out outcomes.
    chosen = eligible[0]
    threshold = chosen["threshold"]
    test_x = [x for x, y in rows["test"]]
    test_y = [y for x, y in rows["test"]]
    probabilities = model.predict_proba(test_x)[:, 1].tolist()
    predicted = [int(prob >= threshold) for prob in probabilities]
    counts = Counter(
        "TP" if p and y else "FP" if p else "FN" if y else "TN"
        for p, y in zip(predicted, test_y)
    )
    tp, fp, fn, tn = (counts[k] for k in ("TP", "FP", "FN", "TN"))
    def rate(a, b):
        return a / b if b else None
    bundle = {
        "schema": "predict-shield/ctu13-flow-logistic/1",
        "features": list(NUMERIC) + ["proto=" + p for p in PROTOCOLS],
        "coefficients": [float(x) for x in model.coef_[0]],
        "intercept": float(model.intercept_[0]),
        "threshold": threshold,
        "threshold_selection_method": "lowest_preregistered_grid_threshold_with_calibration_sample_fpr_at_or_below_cap",
        "training_source_digests": [s["source_sha256"] for s in stats if s["split"] == "train"],
        "production_deployable": False,
        "decision_authorized": False,
    }
    report = {
        "schema": "predict-shield/ctu13-flow-evaluation/1",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "scenario_source_stats": stats,
        "model_fingerprint": hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest(),
        "calibration_threshold_candidates": evaluations,
        "selected_threshold": threshold,
        "max_calibration_sample_false_positive_rate": max_fpr,
        "calibration_selected": chosen,
        "threshold_selected_using_test_labels": False,
        "evaluated_flows": len(test_y), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "sample_recall": rate(tp, tp + fn),
        "sample_precision": rate(tp, tp + fp),
        "sample_false_positive_rate": rate(fp, fp + tn),
        "test_scenario_ids": [s["scenario_id"] for s in stats if s["split"] == "test"],
        "unknown_or_ambiguous_excluded": sum(s["excluded_unknown"] for s in stats),
        "class_stratified_sampling": True,
        "sample_precision_is_operational_precision": False,
        "reviewer_ground_truth_independently_authenticated": False,
        "represents_current_infrastructure": False,
        "field_effectiveness_established": False,
        "model_is_trained": True,
        "model_calibrated": False,
        "calibration_split_used_for_threshold_only": True,
        "calibration_scores_probability_calibrated": False,
        "interpretation": "Historical CTU-13 sampled bidirectional network flows; only From-Botnet and From-Normal treated as labels, To-* and Background unknown; cross-scenario split, not operational precision.",
    }
    return bundle, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    bundle, report = run(json.loads(raw), raw, args.data_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"model": bundle, "report": report}, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
