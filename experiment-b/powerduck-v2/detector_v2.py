"""PowerDuck GOOSE detector, version 2. See protocol_v2.json.

  python detector_v2.py develop --archive powerduck.zip --out-dir frozen
  python detector_v2.py test    --archive powerduck.zip --frozen-dir frozen --expected-freeze-sha256 H --output r.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import zipfile
from pathlib import Path

import numpy as np

import history_features as hf

HERE = Path(__file__).resolve().parent
V1 = HERE.parent / "powerduck"
SEED = 20261124
FIT_SHARE = 0.7
BUDGET = 0.005
CEILING = 0.01
GAP_S = 2.0
SCENARIOS_REQUIRED = 12
CODE_FILES = {"history_features.py": HERE, "detector_v2.py": HERE, "protocol_v2.json": HERE, "goose_features.py": V1}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes(code_dir: Path = HERE) -> dict:
    return {n: sha256(((code_dir if d == HERE else V1) / n).read_bytes()) for n, d in CODE_FILES.items()}


def protocol(code_dir: Path = HERE) -> dict:
    return json.loads((code_dir / "protocol_v2.json").read_text())


def check_archive(path: Path, proto: dict) -> None:
    got = sha256(Path(path).read_bytes())
    if got != proto["source"]["sha256"]:
        raise SystemExit(f"archive does not match its pin: {got}")


def load(archive: Path, member: str):
    with zipfile.ZipFile(archive) as z:
        records = hf.read_ipal(z.read(member))
    x, streams = hf.capture_features(records)
    times = np.array([float(r["timestamp"]) for r in records])
    return records, x, streams, times


def fit(parts):
    from sklearn.ensemble import IsolationForest
    known = sorted({s for _, st in parts for s in st})
    fit_rows, thr_rows = [], []
    for x, st in parts:
        cut = int(FIT_SHARE * len(x))
        xs = hf.with_streams(x, st, known)
        fit_rows.append(xs[:cut])
        thr_rows.append(xs[cut:])
    x_fit, x_thr = np.vstack(fit_rows), np.vstack(thr_rows)
    model = IsolationForest(n_estimators=300, max_samples=min(2048, len(x_fit)), random_state=SEED).fit(x_fit)
    thr = hf.normal_threshold(-model.score_samples(x_thr), BUDGET)
    return model, thr, known, {"fit_rows": int(len(x_fit)), "threshold_rows": int(len(x_thr))}


def alerts(model, thr, known, x, st):
    return -model.score_samples(hf.with_streams(x, st, known)) > thr


def develop(archive: Path, out_dir: Path) -> None:
    proto = protocol()
    check_archive(archive, proto)
    normals = proto["source"]["normal_members"]
    parts = {}
    times = {}
    for m in normals:
        _, x, st, t = load(archive, m)
        parts[m], times[m] = (x, st), t
    folds = {}
    for held in normals:
        model, thr, known, rows = fit([parts[m] for m in normals if m != held])
        x, st = parts[held]
        a = alerts(model, thr, known, x, st)
        inc = hf.incidents(times[held], a, GAP_S)
        folds[held] = {"messages": int(len(x)), "alerts": int(a.sum()), "alert_rate": float(a.mean()),
                       "alert_wilson_95": hf.wilson(int(a.sum()), len(x)), "incidents": len(inc),
                       "hours": hf.hours(times[held]),
                       "incidents_per_hour": len(inc) / hf.hours(times[held]) if hf.hours(times[held]) else None, **rows}
        print("held out", held, folds[held], flush=True)
    model, thr, known, rows = fit([parts[m] for m in normals])
    out_dir.mkdir(parents=True, exist_ok=True)
    blob = pickle.dumps({"model": model, "threshold": thr, "known_streams": known}, protocol=5)
    (out_dir / "model.pkl").write_bytes(blob)
    freeze = {"schema": "predict-shield/powerduck-v2-freeze/1", "model_sha256": sha256(blob), "threshold": thr,
              "known_streams": known, "code_sha256": code_hashes(), "archive_sha256": proto["source"]["sha256"],
              "sklearn": __import__("sklearn").__version__, **rows}
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (out_dir / "development-report.json").write_text(json.dumps(
        {"schema": "predict-shield/powerduck-v2-development/1", "leave_one_capture_out": folds,
         "freeze_sha256": freeze["freeze_sha256"]}, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], flush=True)


def verify(frozen: Path, expected: str, archive: Path):
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    blob = (frozen / "model.pkl").read_bytes()
    if sha256(blob) != freeze["model_sha256"]:
        raise SystemExit("model does not match the freeze")
    check_archive(archive, protocol())
    freeze["freeze_sha256"] = rec
    return freeze, pickle.loads(blob)


def test(archive: Path, frozen: Path, expected: str, output: Path) -> None:
    freeze, b = verify(frozen, expected, archive)
    model, thr, known = b["model"], b["threshold"], b["known_streams"]
    with zipfile.ZipFile(archive) as z:
        members = sorted(n for n in z.namelist() if n.startswith("dataset/ipal/Attack/") and n.endswith(".ipal.gz"))
    tot = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "true_incidents": 0, "false_incidents": 0, "hours": 0.0}
    scenarios = {}
    for m in members:
        records, x, st, t = load(archive, m)
        a = alerts(model, thr, known, x, st)
        mal = np.array([hf.is_malicious(r) for r in records])
        inc = hf.incidents(t, a, GAP_S)
        true_inc = sum(1 for s, e in inc if mal[s:e + 1].any())
        tp, fp = int((a & mal).sum()), int((a & ~mal).sum())
        fn, tn = int((~a & mal).sum()), int((~a & ~mal).sum())
        hrs = hf.hours(t)
        for k, v in (("TP", tp), ("FP", fp), ("FN", fn), ("TN", tn), ("true_incidents", true_inc),
                     ("false_incidents", len(inc) - true_inc), ("hours", hrs)):
            tot[k] += v
        delay = float(t[np.argmax(a & mal)] - t[np.argmax(mal)]) if (a & mal).any() else None
        name = m.split("/")[-1].removesuffix(".ipal.gz")
        scenarios[name] = {"messages": int(len(x)), "malicious": int(mal.sum()), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                           "detected": bool(tp > 0), "detection_rate": tp / int(mal.sum()) if mal.any() else None,
                           "incidents": len(inc), "true_incidents": true_inc, "false_incidents": len(inc) - true_inc,
                           "hours": hrs, "seconds_to_first_detection": delay}
        print(name, scenarios[name], flush=True)
    tp, fp, fn, tn = (tot[k] for k in ("TP", "FP", "FN", "TN"))
    detected = sum(s["detected"] for s in scenarios.values())
    nar = fp / (fp + tn) if fp + tn else None
    report = {"schema": "predict-shield/powerduck-v2-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "threshold": thr, "scenarios": scenarios, **{k: tot[k] for k in ("TP", "FP", "FN", "TN")},
              "detection_rate": tp / (tp + fn), "detection_wilson_95": hf.wilson(tp, tp + fn),
              "non_malicious_alert_rate": nar, "non_malicious_alert_wilson_95": hf.wilson(fp, fp + tn),
              "scenarios_detected": detected, "scenarios_total": len(scenarios),
              "true_incidents": tot["true_incidents"], "false_incidents": tot["false_incidents"],
              "capture_hours": tot["hours"],
              "false_incidents_per_hour": tot["false_incidents"] / tot["hours"] if tot["hours"] else None,
              "pass_condition": protocol()["pass_condition"],
              "passed": bool(nar is not None and nar <= CEILING and detected >= SCENARIOS_REQUIRED and len(scenarios) == 16),
              "note": "Second measurement on the same 16 captures; version 1's results on them were seen. Messages within a capture are dependent."}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("detection_rate", "non_malicious_alert_rate", "scenarios_detected",
                                             "false_incidents", "false_incidents_per_hour", "passed")}, indent=1))


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
