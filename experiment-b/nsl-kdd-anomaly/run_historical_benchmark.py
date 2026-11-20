"""Auditable read-only signature-free anomaly evaluation on pinned NSL-KDD mirror.

Historical public benchmark, NOT original production telemetry or zero-day
effectiveness evidence. Train only on normal rows. Calibrate alarms on a
separate normal subset of the official train file. Frozen model and cutoff
preexist loading the official test file. Retain negative outcomes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import urllib.request

HERE = Path(__file__).resolve().parent
NUMERIC = (0, 4, 5, 22, 23, 24, 25, 26, 27, 28, 29, 31, 32, 33, 34, 37, 38, 39, 40)
RATES = frozenset((24, 25, 26, 27, 28, 29, 33, 34, 37, 38, 39, 40))
TRAIN_SEED = 20261119
MAX_BYTES = 35_000_000


def read_pinned(url: str, expected_blob: str) -> tuple[bytes, dict]:
    if not url.startswith("https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9/"):
        raise ValueError("Unapproved historical mirror or mutable Git reference")
    with urllib.request.urlopen(url, timeout=90) as stream:
        if stream.status != 200:
            raise ValueError("Mirror dataset unavailable")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Unbounded benchmark file")
    git_sha = hashlib.sha1(f"blob {len(data)}\\0".encode() + data).hexdigest()
    if git_sha != expected_blob:
        raise ValueError("Dataset bytes do not match the GitHub-pinned Git blob")
    return data, {"url": url, "bytes": len(data),
                  "git_blob_sha1_verified": git_sha, "sha256": hashlib.sha256(data).hexdigest()}


def rows(data: bytes, *, expected_count: int) -> list[tuple[tuple[float, ...], str, bytes]]:
    if expected_count < 10000:
        raise ValueError("Invalid expected benchmark denominator")
    out = []
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Unexpected non-UTF8 dataset") from exc
    for i, row in enumerate(csv.reader(io.StringIO(text))):
        if len(row) != 43:
            raise ValueError(f"Wrong NSL-KDD field count at line {i+1}")
        label = row[41].strip().lower()
        if not label or len(label) > 80 or not all(
                c.isascii() and (c.islower() or c.isdigit() or c in "._-")
                for c in label):
            raise ValueError("Invalid publisher attack label")
        vec = []
        for idx in NUMERIC:
            try:
                number = float(row[idx])
            except ValueError as exc:
                raise ValueError(f"Invalid numeric feature row {i+1}") from exc
            if not math.isfinite(number) or not 0 <= number <= 1e15:
                raise ValueError(f"Nonfinite/negative feature row {i+1}")
            if idx in RATES:
                if number > 1.000001:
                    raise ValueError("Probability feature outside [0,1]")
                vec.append(number)
            else:
                vec.append(math.log1p(number))
        canonical = ",".join(row).encode()
        out.append((tuple(vec), label, canonical))
    if len(out) != expected_count:
        raise ValueError(f"Wrong benchmark record count: {len(out)} != {expected_count}")
    return out


def cutoff_from_benign(scores: list[float], limit: float) -> float:
    if not scores or type(limit) not in (int, float) or not 0 <= limit <= .25:
        raise ValueError("Invalid calibration sample or false-alarm ceiling")
    # Strict greater-than alert. If k scores above cutoff, calibration FP <= k.
    k = math.floor(limit * len(scores))
    if k == 0:
        return max(scores)
    return sorted(scores, reverse=True)[k - 1]


def _model_fingerprint(model) -> str:
    digest = hashlib.sha256()
    for tree in model.estimators_:
        for arr in (tree.tree_.feature, tree.tree_.threshold,
                    tree.tree_.children_left, tree.tree_.children_right):
            digest.update(arr.tobytes())
    return digest.hexdigest()


def run(protocol: dict, *, downloader=read_pinned) -> dict:
    if protocol.get("schema") != "predict-shield/nsl-kdd-historical-normal-only-detection/1":
        raise ValueError("Unexpected frozen benchmark protocol")
    commit = protocol.get("mirror_commit")
    if commit != "27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9":
        raise ValueError("Unapproved benchmark commit")
    if (protocol.get("train_git_blob_sha1") != "20002897492adc110190a10509aa694f26f7f308"
            or protocol.get("test_git_blob_sha1") != "b30e89605285a5ccd8cf8fd38dba72906c20d3dd"
            or protocol.get("train_expected_rows") != 125973
            or protocol.get("test_expected_rows") != 22544
            or protocol.get("calibration_fpr_ceiling") != 0.05):
        raise ValueError("Registered source hashes, sample totals or threshold changed")
    prefix = f"https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/{commit}/"
    train_bytes, train_source = downloader(
        prefix + "KDDTrain%2B.txt", protocol["train_git_blob_sha1"])
    train_rows = rows(train_bytes, expected_count=protocol["train_expected_rows"])
    attack_types_seen_in_published_train = {
        label for _, label, _ in train_rows if label != "normal"}
    normals = [row for row in train_rows if row[1] == "normal"]
    train_normal, calibration = [], []
    for features, label, content in normals:
        group = int.from_bytes(hashlib.sha256(content).digest()[:8], "big") % 4
        (calibration if group == 0 else train_normal).append(features)
    if min(len(train_normal), len(calibration)) < 1000:
        raise ValueError("Insufficient genuine benchmark normal records")
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(n_estimators=100, max_samples=512,
                            random_state=TRAIN_SEED, contamination="auto", n_jobs=1)
    model.fit(train_normal)
    normal_scores = (-model.score_samples(calibration)).tolist()
    cutoff = cutoff_from_benign(normal_scores, protocol["calibration_fpr_ceiling"])
    calibration_false_alarms = sum(score > cutoff for score in normal_scores)
    assert calibration_false_alarms / len(normal_scores) <= .05
    # Freeze BEFORE opening the independently designated test source.
    model_digest = _model_fingerprint(model)
    train_source_hash = train_source["sha256"]
    freeze_sha = hashlib.sha256(json.dumps({
        "model": model_digest, "cutoff": float(cutoff),
        "train_source": train_source_hash,
        "registered_protocol_sha": hashlib.sha256(
            json.dumps(protocol, sort_keys=True).encode()).hexdigest(),
    }, sort_keys=True).encode()).hexdigest()
    test_bytes, test_source = downloader(
        prefix + "KDDTest%2B.txt", protocol["test_git_blob_sha1"])
    test_rows = rows(test_bytes, expected_count=protocol["test_expected_rows"])
    scores = (-model.score_samples([item[0] for item in test_rows])).tolist()
    total = Counter()
    novel = Counter()
    by_label = {}
    for (_, label, _), score in zip(test_rows, scores):
        malicious = label != "normal"
        alert = score > cutoff
        outcome = ("TP" if alert and malicious else
                   "FP" if alert else "FN" if malicious else "TN")
        total[outcome] += 1
        if malicious:
            slot = by_label.setdefault(label, {"tested": 0, "detected": 0})
            slot["tested"] += 1
            slot["detected"] += int(alert)
            if label not in attack_types_seen_in_published_train:
                novel[outcome] += 1
    def rate(numerator: int, denominator: int):
        return numerator / denominator if denominator else None
    assert sum(total.values()) == protocol["test_expected_rows"]
    return {
        "schema": "predict-shield/historical-external-nsl-kdd-anomaly-evaluation/1",
        "provenance": {"canonical_publisher": protocol["benchmark_authority"],
                       "nonpublisher_mirror_commit": commit,
                       "train_source": train_source, "test_source": test_source},
        "fit_normal_only": True,
        "train_malicious_examples_used_for_fit": 0,
        "fit_normal_rows": len(train_normal),
        "calibration_normal_rows": len(calibration),
        "calibration_false_alerts": calibration_false_alarms,
        "calibration_sample_false_alarm_rate":
            calibration_false_alarms / len(calibration),
        "calibration_ceiling": protocol["calibration_fpr_ceiling"],
        "frozen_threshold": float(cutoff),
        "fitted_model_sha256": model_digest,
        "pretest_freeze_sha256": freeze_sha,
        "test_file_read_after_freeze": True,
        "test_rows": len(test_rows),
        "TP": total["TP"], "FP": total["FP"], "FN": total["FN"], "TN": total["TN"],
        "test_attack_recall": rate(total["TP"], total["TP"] + total["FN"]),
        "test_false_positive_rate": rate(total["FP"], total["FP"] + total["TN"]),
        "test_precision": rate(total["TP"], total["TP"] + total["FP"]),
        "unseen_attack_type_names": sorted(n for n in by_label
                                           if n not in attack_types_seen_in_published_train),
        "unseen_attack_type_rows": sum(novel.values()),
        "unseen_attack_type_TP": novel["TP"],
        "unseen_attack_type_FN": novel["FN"],
        "unseen_attack_type_recall": rate(novel["TP"], novel["TP"] + novel["FN"]),
        "per_attack_type": by_label,
        "publisher_labels_independently_reauthenticated": False,
        "mirror_bytes_pinned_to_git_object": True,
        "operational_attack_detection_established": False,
        "zero_day_detection_established": False,
        "external_current_critical_infrastructure_effectiveness_established": False,
        "interpretation": "Fixed historical, non-operational NSL-KDD benchmark, not modern production telemetry; unseen means class-name absent from published train labels only. No signatures or attack examples used to fit model. Row-wise metric denominators are dependent; no operator-level inference.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=Path, default=HERE / "frozen_protocol.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(json.loads(args.protocol.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as dst:
        json.dump(result, dst, indent=2, sort_keys=True)
        dst.write("\n")
    print(json.dumps({key: result[key] for key in (
        "test_rows", "TP", "FP", "FN", "TN", "test_attack_recall",
        "test_false_positive_rate", "unseen_attack_type_rows",
        "unseen_attack_type_TP", "unseen_attack_type_FN",
        "unseen_attack_type_recall", "zero_day_detection_established",
        "operational_attack_detection_established")}, sort_keys=True))


if __name__ == "__main__":
    main()
