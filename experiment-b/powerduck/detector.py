"""Learned GOOSE anomaly detector on PowerDuck. See protocol.json.

  python detector.py develop --archive powerduck.zip --out-dir frozen
  python detector.py test    --archive powerduck.zip --frozen-dir frozen --expected-freeze-sha256 H --output r.json

develop reads only the four normal captures. test verifies the freeze, then
reads every attack capture once.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import zipfile
from pathlib import Path

import numpy as np

import goose_features as gf

HERE = Path(__file__).resolve().parent
SEED = 20261121
FIT_SHARE = 0.7
BUDGET = 0.01
DETECTION_SCENARIOS_REQUIRED = 12
CODE_FILES = ("goose_features.py", "detector.py", "protocol.json")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def code_hashes(directory: Path = HERE) -> dict:
    return {n: sha256((directory / n).read_bytes()) for n in CODE_FILES}


def protocol(directory: Path = HERE) -> dict:
    return json.loads((directory / "protocol.json").read_text())


def check_archive(path: Path, proto: dict) -> None:
    got = sha256(Path(path).read_bytes())
    if got != proto["source"]["sha256"]:
        raise SystemExit(f"archive does not match its pin: {got}")


def load_capture(archive: Path, member: str):
    with zipfile.ZipFile(archive) as z:
        records = gf.read_ipal(z.read(member))
    x, streams = gf.capture_features(records)
    return records, x, streams


def fit(parts: list[tuple[np.ndarray, list[str]]]):
    """parts: (features, streams) per normal capture, in time order. Returns
    (model, threshold, known streams, row counts)."""
    from sklearn.ensemble import IsolationForest
    known = sorted({s for _, streams in parts for s in streams})
    fit_rows, thr_rows = [], []
    for x, streams in parts:
        cut = int(FIT_SHARE * len(x))
        xs = gf.with_streams(x, streams, known)
        fit_rows.append(xs[:cut])
        thr_rows.append(xs[cut:])
    x_fit, x_thr = np.vstack(fit_rows), np.vstack(thr_rows)
    model = IsolationForest(n_estimators=300, max_samples=min(2048, len(x_fit)), random_state=SEED).fit(x_fit)
    threshold = gf.normal_threshold(-model.score_samples(x_thr), BUDGET)
    return model, threshold, known, {"fit_rows": int(len(x_fit)), "threshold_rows": int(len(x_thr))}


def alerts(model, threshold: float, known: list[str], x: np.ndarray, streams: list[str]) -> np.ndarray:
    return -model.score_samples(gf.with_streams(x, streams, known)) > threshold


def develop(archive: Path, out_dir: Path) -> None:
    proto = protocol()
    check_archive(archive, proto)
    normals = proto["source"]["normal_members"]
    parts = {}
    for m in normals:
        records, x, streams = load_capture(archive, m)
        parts[m] = (x, streams)
        print(m, len(records), "messages,", len(set(streams)), "streams", flush=True)
    folds = {}
    for held in normals:
        model, thr, known, rows = fit([parts[m] for m in normals if m != held])
        x, streams = parts[held]
        a = alerts(model, thr, known, x, streams)
        folds[held] = {"messages": int(len(x)), "alerts": int(a.sum()), "alert_rate": float(a.mean()),
                       "alert_wilson_95": gf.wilson(int(a.sum()), len(x)),
                       "unseen_stream_messages": int(sum(s not in known for s in streams)), **rows}
        print("held out", held, folds[held], flush=True)
    model, thr, known, rows = fit([parts[m] for m in normals])
    out_dir.mkdir(parents=True, exist_ok=True)
    blob = pickle.dumps({"model": model, "threshold": thr, "known_streams": known,
                         "features": list(gf.BASE_FEATURES)}, protocol=5)
    (out_dir / "model.pkl").write_bytes(blob)
    freeze = {"schema": "predict-shield/powerduck-freeze/1", "model_sha256": sha256(blob), "threshold": thr,
              "known_streams": known, "code_sha256": code_hashes(), "archive_sha256": proto["source"]["sha256"],
              "sklearn": __import__("sklearn").__version__, **rows}
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (out_dir / "development-report.json").write_text(json.dumps(
        {"schema": "predict-shield/powerduck-development/1", "leave_one_capture_out": folds,
         "freeze_sha256": freeze["freeze_sha256"]}, indent=1, sort_keys=True) + "\n")
    print("FROZEN model", freeze["model_sha256"], "freeze", freeze["freeze_sha256"], flush=True)


def verify(frozen: Path, expected: str, archive: Path, code_dir: Path = HERE):
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes(code_dir) != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    blob = (frozen / "model.pkl").read_bytes()
    if sha256(blob) != freeze["model_sha256"]:
        raise SystemExit("model does not match the freeze")
    check_archive(archive, protocol(code_dir))
    freeze["freeze_sha256"] = rec
    return freeze, pickle.loads(blob)


def test(archive: Path, frozen: Path, expected: str, output: Path) -> None:
    freeze, bundle = verify(frozen, expected, archive)
    model, thr, known = bundle["model"], bundle["threshold"], bundle["known_streams"]
    with zipfile.ZipFile(archive) as z:
        members = sorted(n for n in z.namelist() if n.startswith("dataset/ipal/Attack/") and n.endswith(".ipal.gz"))
    scenarios, tot = {}, {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for m in members:
        records, x, streams = load_capture(archive, m)
        a = alerts(model, thr, known, x, streams)
        mal = np.array([gf.is_malicious(r) for r in records])
        tp, fp = int(np.sum(a & mal)), int(np.sum(a & ~mal))
        fn, tn = int(np.sum(~a & mal)), int(np.sum(~a & ~mal))
        for k, v in zip(("TP", "FP", "FN", "TN"), (tp, fp, fn, tn)):
            tot[k] += v
        t = np.array([float(r["timestamp"]) for r in records])
        delay = None
        if mal.any() and (a & mal).any():
            delay = float(t[np.argmax(a & mal)] - t[np.argmax(mal)])
        name = m.split("/")[-1].removesuffix(".ipal.gz")
        scenarios[name] = {"messages": int(len(x)), "malicious": int(mal.sum()), "TP": tp, "FP": fp, "FN": fn,
                           "TN": tn, "detected": bool(tp > 0),
                           "detection_rate": tp / int(mal.sum()) if mal.any() else None,
                           "seconds_from_first_malicious_to_first_detection": delay,
                           "unseen_stream_messages": int(sum(s not in known for s in streams))}
        print(name, scenarios[name], flush=True)
    tp, fp, fn, tn = (tot[k] for k in ("TP", "FP", "FN", "TN"))
    detected = sum(s["detected"] for s in scenarios.values())
    nar = fp / (fp + tn) if fp + tn else None
    report = {"schema": "predict-shield/powerduck-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "model_sha256": freeze["model_sha256"], "threshold": thr, "scenarios": scenarios,
              "messages": tp + fp + fn + tn, **tot,
              "detection_rate": tp / (tp + fn) if tp + fn else None, "detection_wilson_95": gf.wilson(tp, tp + fn),
              "non_malicious_alert_rate": nar, "non_malicious_alert_wilson_95": gf.wilson(fp, fp + tn),
              "precision": tp / (tp + fp) if tp + fp else None,
              "scenarios_detected": detected, "scenarios_total": len(scenarios),
              "pass_condition": "non-malicious alert rate at most 1% pooled AND at least 12 of 16 scenarios detected",
              "passed": bool(nar is not None and nar <= BUDGET and detected >= DETECTION_SCENARIOS_REQUIRED
                             and len(scenarios) == 16),
              "note": "Messages within a capture are dependent; Wilson intervals understate uncertainty."}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("messages", "TP", "FP", "FN", "TN", "detection_rate",
                                             "non_malicious_alert_rate", "precision", "scenarios_detected",
                                             "passed")}, indent=1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test"))
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.archive, a.out_dir)
    else:
        test(a.archive, a.frozen_dir, a.expected_freeze_sha256, a.output)


if __name__ == "__main__":
    main()
