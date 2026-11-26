#!/usr/bin/env python3
"""Train and freeze a REAL supervised ML classifier on NSL-KDD's original split.

The output bundle is an executable browser inference model, not a simulated
score table. Official KDDTest+ is measured ONCE after all training and
threshold selection using training-only validation. Historical benchmark:
not operational critical-infrastructure or modern generalization evidence.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import urllib.request
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn import __version__ as sklearn_version
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

BASE = Path(__file__).resolve().parent
SOURCE_REPO = "Jehuty4949/NSL_KDD"
SOURCE_COMMIT = "27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9"
FILES = {
    "KDDTrain+_20Percent.txt": "74640e1046c65e3b9ff4e5fe1e5c11d6185429dc",
    "KDDTest+.txt": "b30e89605285a5ccd8cf8fd38dba72906c20d3dd",
}
CATS = [1, 2, 3]
NUMS = [i for i in range(41) if i not in CATS]
TRAIN_SEED = 20261126
SELECTED_LABELS = ("normal", "neptune", "guess_passwd", "satan", "portsweep", "mscan")
MAX_EXAMPLES_EACH = 4
SOURCE_URL = "https://github.com/Jehuty4949/NSL_KDD/tree/" + SOURCE_COMMIT
COLUMN_NAMES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
]


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\x00" + raw).hexdigest()


def download_or_verify(name: str, cache: Path) -> bytes:
    if name not in FILES:
        raise ValueError("unregistered dataset file")
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / name
    if path.is_file():
        raw = path.read_bytes()
    else:
        url = (f"https://raw.githubusercontent.com/{SOURCE_REPO}/"
               f"{SOURCE_COMMIT}/{name.replace('+','%2B')}")
        request = urllib.request.Request(url, headers={
            "User-Agent": "predict-shield-research-model-training/1"})
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read(15_000_001)
        if len(raw) > 15_000_000:
            raise ValueError("unexpectedly large source")
        path.write_bytes(raw)
    actual = git_blob_sha1(raw)
    if actual != FILES[name]:
        raise ValueError(f"publisher mirror's Git blob digest mismatch: {name}: {actual}")
    return raw


def parse(raw: bytes):
    rows, labels = [], []
    for i, line in enumerate(raw.decode("utf-8").splitlines()):
        fields = line.split(",")
        if len(fields) != 43:
            raise ValueError(f"invalid NSL-KDD row {i}: {len(fields)}")
        row = []
        for j in range(41):
            if j in CATS:
                row.append(fields[j])
            else:
                v = float(fields[j])
                if not math.isfinite(v):
                    raise ValueError("nonfinite NSL-KDD feature")
                row.append(v)
        rows.append(row)
        labels.append(fields[41])
    return rows, np.asarray([int(x != "normal") for x in labels]), labels


def numeric_features(rows):
    vals = np.asarray([[float(row[j]) for j in NUMS] for row in rows], dtype=np.float64)
    return np.sign(vals) * np.log1p(np.abs(vals))


def metrics(y, predictions):
    tp = int(((y == 1) & (predictions == 1)).sum())
    tn = int(((y == 0) & (predictions == 0)).sum())
    fp = int(((y == 0) & (predictions == 1)).sum())
    fn = int(((y == 1) & (predictions == 0)).sum())
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": len(y),
            "precision": tp/(tp+fp) if tp+fp else None,
            "recall": tp/(tp+fn) if tp+fn else None,
            "benign_false_alert_rate": fp/(fp+tn) if fp+tn else None,
            "balanced_accuracy": 0.5*(tp/(tp+fn)+tn/(tn+fp)) if tp+fn and tn+fp else None,
            "accuracy": (tp+tn)/len(y)}


def assemble(rows, numeric_scaler, categorical_encoder, fit=False):
    nums = numeric_features(rows)
    if fit:
        nums = numeric_scaler.fit_transform(nums)
    else:
        nums = numeric_scaler.transform(nums)
    cats = [[row[j] for j in CATS] for row in rows]
    catmatrix = categorical_encoder.fit_transform(cats) if fit else categorical_encoder.transform(cats)
    return np.column_stack([nums, catmatrix])


def run(cache: Path, output: Path):
    train_raw = download_or_verify("KDDTrain+_20Percent.txt", cache)
    test_raw = download_or_verify("KDDTest+.txt", cache)
    train_rows, train_labels, _ = parse(train_raw)
    heldout_rows, test_labels, attack_labels = parse(test_raw)
    assert len(train_rows) == 25_192 and len(heldout_rows) == 22_544
    train_ids, valid_ids = train_test_split(
        np.arange(len(train_rows)), test_size=0.25, stratify=train_labels, random_state=TRAIN_SEED)
    tr = [train_rows[i] for i in train_ids]
    val = [train_rows[i] for i in valid_ids]
    scaling = StandardScaler()
    encoding = OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float64)
    x_train = assemble(tr, scaling, encoding, fit=True)
    x_valid = assemble(val, scaling, encoding)
    clf = LogisticRegression(C=0.4, max_iter=600, solver="liblinear",
                             class_weight="balanced", random_state=TRAIN_SEED).fit(x_train, train_labels[train_ids])
    val_probs = clf.predict_proba(x_valid)[:, 1]
    # Calibrate from training-only validation to a 3% benign false-alert target.
    normal_probs = val_probs[train_labels[valid_ids] == 0]
    if len(normal_probs) < 100:
        raise ValueError("insufficient normal validation samples")
    threshold = float(np.quantile(normal_probs, 0.97))
    predicted_val = (val_probs > threshold).astype(int)
    val_metrics = metrics(train_labels[valid_ids], predicted_val)
    # Official holdout accessed only AFTER model and threshold are frozen.
    x_test = assemble(heldout_rows, scaling, encoding)
    test_probs = clf.predict_proba(x_test)[:, 1]
    predicted_test = (test_probs > threshold).astype(int)
    test_metrics = metrics(test_labels, predicted_test)
    rng = np.random.default_rng(TRAIN_SEED)
    examples = []
    for lab in SELECTED_LABELS:
        indices = np.asarray([i for i, value in enumerate(attack_labels) if value == lab])
        if not len(indices):
            raise ValueError("missing requested label " + lab)
        selected = rng.choice(indices, size=min(MAX_EXAMPLES_EACH, len(indices)), replace=False)
        for idx in selected:
            idx = int(idx)
            examples.append({
                "index": idx, "source_label": lab, "actual_is_attack": bool(test_labels[idx]),
                "features": heldout_rows[idx],
                # For a self-consistency check, not used to render prediction.
                "expected_probability": round(float(test_probs[idx]), 9),
            })
    model = {
        "schema": "predict-shield/nsl-kdd-trained-logistic/1",
        "kind": "REAL_TRAINED_SUPERVISED_BINARY_CLASSIFIER",
        "trained_on": "NSL-KDD legacy connection features",
        "training_split": "25,192 source rows -> 18,894 fit + 6,298 validation; official 22,544 untouched test",
        "mirror_url": SOURCE_URL,
        "source_git_commit": SOURCE_COMMIT,
        "source_git_blobs": FILES,
        "license_note": "NSL-KDD original rights are separate from the mirror's GitHub license; cite UNB authors, avoid redistribution of complete dataset.",
        "seed": TRAIN_SEED,
        "algorithm": "scikit-learn LogisticRegression; numeric log1p + StandardScaler, categoricals OneHotEncoder",
        "sklearn_version": sklearn_version,
        "classes": ["normal", "attack"],
        "feature_names": COLUMN_NAMES,
        "numeric_indices": NUMS,
        "categorical_indices": CATS,
        "numeric_mean": np.around(scaling.mean_, 12).tolist(),
        "numeric_scale": np.around(scaling.scale_, 12).tolist(),
        "categorical_values": [list(map(str, group)) for group in encoding.categories_],
        "coefficients": np.around(clf.coef_[0], 12).tolist(),
        "intercept": float(round(clf.intercept_[0], 12)),
        "threshold": threshold,
        "validation": val_metrics,
        "official_test": test_metrics,
        "testing_used_once": True,
        "ground_truth_source": "NSL-KDD original benchmark labels, not reviewed real operator traffic",
        "real_world_false_positive_rate": None,
        "operational_attack_accuracy": None,
        "live_telemetry_integrated": False,
        "examples": examples,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(model, separators=(",",":"), ensure_ascii=False) + "\n")
    assert len(model["coefficients"]) == len(NUMS) + sum(len(x) for x in model["categorical_values"])
    # Mirror JS inference precisely, including unknown categorical values.
    for example in examples:
        f = example["features"]
        z = model["intercept"]
        for p, idx in enumerate(NUMS):
            v = float(f[idx])
            v = math.copysign(math.log1p(abs(v)), v)
            z += model["coefficients"][p] * (v - model["numeric_mean"][p]) / model["numeric_scale"][p]
        cursor = len(NUMS)
        for idx, choices in zip(CATS, model["categorical_values"]):
            for option in choices:
                if option == f[idx]:
                    z += model["coefficients"][cursor]
                cursor += 1
        inferred = 1/(1+math.exp(-max(-100,min(100,z))))
        if abs(inferred - example["expected_probability"]) > 1e-6:
            raise AssertionError("JS export does not reproduce trained scikit-learn prediction")
    print("METRICS_JSON="+json.dumps({"fit":len(tr),"validation":len(val),"test":len(heldout_rows),
        "threshold":threshold,"validation_metrics":val_metrics,"official_test_metrics":test_metrics}, separators=(",",":")),flush=True)
    print("MODEL_JSON="+json.dumps(model,separators=(",",":"),ensure_ascii=False),flush=True)


if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--cache",type=Path,default=Path("/tmp/predict-shield-nsl-kdd"))
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    run(args.cache,args.output)
