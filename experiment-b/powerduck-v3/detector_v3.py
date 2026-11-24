"""PowerDuck GOOSE detector, version 3. See protocol_v3.json.

  python detector_v3.py develop --archive powerduck.zip --out-dir frozen
  python detector_v3.py test    --archive powerduck.zip --frozen-dir frozen --expected-freeze-sha256 H --output r.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import zipfile
from pathlib import Path

import numpy as np

import gated_history as gh

HERE = Path(__file__).resolve().parent
V1 = HERE.parent / "powerduck"
SEED = 20261125
FIT_SHARE = 0.7
BUDGET = 0.005
THRESHOLD_ROUNDS = 2
CEILING = 0.01
GAP_S = 2.0
FALSE_INCIDENTS_PER_HOUR = 2.0
SCENARIOS_REQUIRED = 12
CODE_FILES = {"gated_history.py": HERE, "detector_v3.py": HERE, "protocol_v3.json": HERE, "goose_features.py": V1}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes(code_dir: Path = HERE) -> dict:
    return {n: sha256(((code_dir if d == HERE else V1) / n).read_bytes()) for n, d in CODE_FILES.items()}


def protocol(code_dir: Path = HERE) -> dict:
    return json.loads((code_dir / "protocol_v3.json").read_text())


def check_archive(path: Path, proto: dict) -> None:
    got = sha256(Path(path).read_bytes())
    if got != proto["source"]["sha256"]:
        raise SystemExit(f"archive does not match its pin: {got}")


def load(archive: Path, member: str):
    with zipfile.ZipFile(archive) as z:
        records = gh.read_ipal(z.read(member))
    base, streams = gh.capture_features(records)
    times = np.array([float(r["timestamp"]) for r in records])
    return records, base, streams, times


def fit(captures: list[tuple[np.ndarray, list[str]]]):
    """Fit on the first 70% of each normal capture (history ungated: these are normal),
    then set the threshold on the last 30% by gated scoring, THRESHOLD_ROUNDS times."""
    from sklearn.ensemble import IsolationForest
    known = sorted({s for _, st in captures for s in st})
    feats = [gh.ungated_features(b, st, known) for b, st in captures]
    cuts = [int(FIT_SHARE * len(b)) for b, _ in captures]
    x_fit = np.vstack([f[:c] for f, c in zip(feats, cuts)])
    model = IsolationForest(n_estimators=300, max_samples=min(2048, len(x_fit)), random_state=SEED).fit(x_fit)
    thr = gh.normal_threshold(np.concatenate([-model.score_samples(f[c:]) for f, c in zip(feats, cuts)]), BUDGET)
    forest = gh.FastForest(model)
    rounds = [thr]
    for _ in range(THRESHOLD_ROUNDS):
        tail = []
        for (b, st), c in zip(captures, cuts):
            s, _ = gh.gated_scores(forest, thr, b, st, known)
            tail.append(s[c:])
        thr = gh.normal_threshold(np.concatenate(tail), BUDGET)
        rounds.append(thr)
    rows = {"fit_rows": int(len(x_fit)), "threshold_rows": int(sum(len(b) - c for (b, _), c in zip(captures, cuts))),
            "threshold_rounds": rounds}
    return model, forest, thr, known, rows


def develop(archive: Path, out_dir: Path) -> None:
    proto = protocol()
    check_archive(archive, proto)
    normals = proto["source"]["normal_members"]
    data = {m: load(archive, m) for m in normals}
    folds = {}
    tot_inc, tot_hours = 0, 0.0
    for held in normals:
        _, forest, thr, known, rows = fit([(data[m][1], data[m][2]) for m in normals if m != held])
        _, base, st, t = data[held]
        _, a = gh.gated_scores(forest, thr, base, st, known)
        inc = gh.incidents(t, a, GAP_S)
        hrs = gh.hours(t)
        tot_inc += len(inc)
        tot_hours += hrs
        folds[held] = {"messages": int(len(base)), "alerts": int(a.sum()), "alert_rate": float(a.mean()),
                       "alert_wilson_95": gh.wilson(int(a.sum()), len(base)), "incidents": len(inc), "hours": hrs,
                       "incidents_per_hour": len(inc) / hrs if hrs else None, **rows}
        print("held out", held, folds[held], flush=True)
    model, _, thr, known, rows = fit([(data[m][1], data[m][2]) for m in normals])
    out_dir.mkdir(parents=True, exist_ok=True)
    blob = pickle.dumps({"model": model, "threshold": thr, "known_streams": known}, protocol=5)
    (out_dir / "model.pkl").write_bytes(blob)
    held_out = {"incidents": tot_inc, "hours": tot_hours,
                "false_incidents_per_hour": tot_inc / tot_hours if tot_hours else None}
    freeze = {"schema": "predict-shield/powerduck-v3-freeze/1", "model_sha256": sha256(blob), "threshold": thr,
              "known_streams": known, "code_sha256": code_hashes(), "archive_sha256": proto["source"]["sha256"],
              "sklearn": __import__("sklearn").__version__, "held_out_normal": held_out, **rows}
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (out_dir / "development-report.json").write_text(json.dumps(
        {"schema": "predict-shield/powerduck-v3-development/1", "leave_one_capture_out": folds,
         "held_out_normal": held_out, "freeze_sha256": freeze["freeze_sha256"]}, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], json.dumps(held_out), flush=True)


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
    forest, thr, known = gh.FastForest(b["model"]), b["threshold"], b["known_streams"]
    with zipfile.ZipFile(archive) as z:
        members = sorted(n for n in z.namelist() if n.startswith("dataset/ipal/Attack/") and n.endswith(".ipal.gz"))
    tot = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "true_incidents": 0, "false_incidents": 0, "hours": 0.0}
    scenarios = {}
    for m in members:
        records, base, st, t = load(archive, m)
        _, a = gh.gated_scores(forest, thr, base, st, known)
        mal = np.array([gh.is_malicious(r) for r in records])
        inc = gh.incidents(t, a, GAP_S)
        true_inc = sum(1 for s, e in inc if mal[s:e + 1].any())
        tp, fp = int((a & mal).sum()), int((a & ~mal).sum())
        fn, tn = int((~a & mal).sum()), int((~a & ~mal).sum())
        hrs = gh.hours(t)
        for k, v in (("TP", tp), ("FP", fp), ("FN", fn), ("TN", tn), ("true_incidents", true_inc),
                     ("false_incidents", len(inc) - true_inc), ("hours", hrs)):
            tot[k] += v
        delay = float(t[np.argmax(a & mal)] - t[np.argmax(mal)]) if (a & mal).any() else None
        name = m.split("/")[-1].removesuffix(".ipal.gz")
        scenarios[name] = {"messages": int(len(base)), "malicious": int(mal.sum()), "TP": tp, "FP": fp, "FN": fn,
                           "TN": tn, "detected": bool(tp > 0),
                           "detection_rate": tp / int(mal.sum()) if mal.any() else None,
                           "incidents": len(inc), "true_incidents": true_inc, "false_incidents": len(inc) - true_inc,
                           "hours": hrs, "seconds_to_first_detection": delay}
        print(name, scenarios[name], flush=True)
    tp, fp, fn, tn = (tot[k] for k in ("TP", "FP", "FN", "TN"))
    detected = sum(s["detected"] for s in scenarios.values())
    nar = fp / (fp + tn) if fp + tn else None
    fiph = tot["false_incidents"] / tot["hours"] if tot["hours"] else None
    dev_fiph = freeze["held_out_normal"]["false_incidents_per_hour"]
    checks = {
        "non_malicious_alert_rate_at_most_1pct": bool(nar is not None and nar <= CEILING),
        "at_least_12_of_16_scenarios": bool(detected >= SCENARIOS_REQUIRED and len(scenarios) == 16),
        "attack_captures_false_incidents_per_hour_at_most_2": bool(fiph is not None and fiph <= FALSE_INCIDENTS_PER_HOUR),
        "held_out_normal_false_incidents_per_hour_at_most_2": bool(dev_fiph is not None and dev_fiph <= FALSE_INCIDENTS_PER_HOUR),
    }
    report = {"schema": "predict-shield/powerduck-v3-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "threshold": thr, "scenarios": scenarios, **{k: tot[k] for k in ("TP", "FP", "FN", "TN")},
              "detection_rate": tp / (tp + fn), "detection_wilson_95": gh.wilson(tp, tp + fn),
              "non_malicious_alert_rate": nar, "non_malicious_alert_wilson_95": gh.wilson(fp, fp + tn),
              "scenarios_detected": detected, "scenarios_total": len(scenarios),
              "true_incidents": tot["true_incidents"], "false_incidents": tot["false_incidents"],
              "capture_hours": tot["hours"], "false_incidents_per_hour": fiph,
              "held_out_normal_false_incidents_per_hour": dev_fiph,
              "checks": checks, "pass_condition": protocol()["pass_condition"], "passed": all(checks.values()),
              "note": "Third measurement on the same 16 captures; versions 1 and 2 results on them were seen. Messages within a capture are dependent."}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("detection_rate", "non_malicious_alert_rate", "scenarios_detected",
                                             "false_incidents_per_hour", "checks", "passed")}, indent=1))


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
