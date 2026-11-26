"""The DVWA v3 method applied to Superviz25-SQL. See protocol.json.

  python model_sql.py develop --data dataset.csv --out-dir frozen
  python model_sql.py test --data dataset.csv --frozen-dir frozen --expected-freeze-sha256 H --output r.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import pickle
import random
import string
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
V3 = HERE.parent / "dvwa-correlation-v3"
sys.path.insert(0, str(V3))
import model_v3 as v3  # noqa: E402

csv.field_size_limit(1 << 30)
SEED = 2026112801
FIT, CAL = 0.40, 0.35
BUDGET, CEILING, DETECT, PER_TECHNIQUE = 0.005, 0.01, 0.90, 0.75
TECHNIQUES = ("boolean", "error", "inline", "stacked", "time", "union", "insider")
PUNCT = list(string.punctuation)
CODE = {"model_sql.py": HERE, "protocol.json": HERE, "model_v3.py": V3}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha256((d / n).read_bytes()) for n, d in CODE.items()}


def check_source(path: Path) -> None:
    want = json.loads((HERE / "protocol.json").read_text())["source"]["sha256"]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    if h.hexdigest() != want:
        raise SystemExit("dataset does not match its pin")


def rows(path: Path, split: str):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            if r["split"] == split:
                yield r


# ------------------------------------------------------------------ evidence

def profiles(samples) -> dict:
    out: dict = {}
    for tpl, val in samples:
        p = out.setdefault(tpl, {"chars": set(), "min": len(val), "max": len(val)})
        p["chars"] |= {v3.char_class(c) for c in val}
        p["min"], p["max"] = min(p["min"], len(val)), max(p["max"], len(val))
    return {k: {"chars": sorted(p["chars"]), "min": p["min"], "max": p["max"]} for k, p in out.items()}


def input_novelty(tpl: str, val: str, prof: dict) -> float:
    p = prof.get(tpl)
    if p is None:
        return 10.0
    s = float(len({v3.char_class(c) for c in val} - set(p["chars"])))
    if len(val) > p["max"]:
        s += math.log2(1 + len(val) - p["max"])
    elif len(val) < p["min"]:
        s += 1.0
    return s


def vector(tpl: str, val: str, templates: list[str]) -> list[float]:
    c = Counter(val)
    return ([math.log1p(len(val)), float(len(val.split())),
             float(sum(ch.isdigit() for ch in val)), float(sum(ch.isalpha() for ch in val)), float(c.get(" ", 0))]
            + [float(c.get(p, 0)) for p in PUNCT]
            + [float(tpl == t) for t in templates] + [float(tpl not in templates)])


def evidence(samples, state, model) -> np.ndarray:
    nov = np.array([input_novelty(t, v, state["profiles"]) for t, v in samples])
    out = np.empty(len(samples))
    step = 200_000
    for i in range(0, len(samples), step):
        x = np.asarray([vector(t, v, state["templates"]) for t, v in samples[i:i + step]])
        out[i:i + step] = -model.score_samples(x)
    return np.column_stack([nov, out])


# ------------------------------------------------------------------ stages

def develop(data: Path, out_dir: Path) -> None:
    check_source(data)
    train = [(r["query_template_id"], r["user_inputs"]) for r in rows(data, "train") if r["label"] == "0"]
    random.Random(SEED).shuffle(train)
    a, b = int(FIT * len(train)), int((FIT + CAL) * len(train))
    state = {"profiles": profiles(train[:a]), "templates": sorted({t for t, _ in train[:a]})}
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(n_estimators=300, random_state=SEED).fit(
        np.asarray([vector(t, v, state["templates"]) for t, v in train[:a]]))
    raw = evidence(train[a:], state, model)
    cal, thr_rows = raw[: b - a], raw[b - a:]
    state["calibration"] = cal.tolist()
    thresholds = {"fused": v3.v1.normal_threshold(v3.fused(thr_rows, cal, range(2)), BUDGET),
                  "input_novelty": v3.v1.normal_threshold(thr_rows[:, 0], BUDGET),
                  "learned_anomaly": v3.v1.normal_threshold(thr_rows[:, 1], BUDGET)}
    state["thresholds"] = thresholds
    blob = pickle.dumps({"state": state, "model": model}, protocol=5)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "model.pkl").write_bytes(blob)
    held = v3.fused(thr_rows, cal, range(2)) > thresholds["fused"]
    freeze = {"schema": "predict-shield/superviz25-sql-freeze/1", "model_sha256": sha256(blob), "code_sha256": code_hashes(),
              "thresholds": thresholds, "rows": {"fit": a, "calibration": b - a, "threshold": len(train) - b},
              "threshold_split_alert_rate": float(held.mean()), "sklearn": __import__("sklearn").__version__}
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], json.dumps(thresholds), flush=True)


def verify(frozen: Path, expected: str):
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    blob = (frozen / "model.pkl").read_bytes()
    if sha256(blob) != freeze["model_sha256"]:
        raise SystemExit("model does not match the freeze")
    freeze["freeze_sha256"] = rec
    return freeze, pickle.loads(blob)


def test(data: Path, frozen: Path, expected: str, output: Path) -> None:
    if output.exists():
        raise SystemExit("a test report already exists; the test runs once")
    freeze, bundle = verify(frozen, expected)
    check_source(data)
    state, model = bundle["state"], bundle["model"]
    meta, samples = [], []
    for r in rows(data, "test"):
        samples.append((r["query_template_id"], r["user_inputs"]))
        meta.append((r["label"], r["attack_technique"], r["attack_stage"], r["attack_status"], r["tamper_method"]))
    raw = evidence(samples, state, model)
    cal, thr = np.asarray(state["calibration"]), state["thresholds"]
    alerts = {"fused": v3.fused(raw, cal, range(2)) > thr["fused"],
              "input_novelty": raw[:, 0] > thr["input_novelty"], "learned_anomaly": raw[:, 1] > thr["learned_anomaly"]}
    label = np.array([m[0] == "1" for m in meta])

    def rate(a, mask):
        k, n = int((a & mask).sum()), int(mask.sum())
        return {"alerts": k, "of": n, "rate": k / n if n else None, "wilson_95": v3.v1.wilson(k, n)}

    groups = {g: defaultdict(list) for g in ("technique", "stage", "status", "tamper")}
    for i, m in enumerate(meta):
        if m[0] == "1":
            for g, v in zip(("technique", "stage", "status", "tamper"), m[1:]):
                groups[g][v or "(none)"].append(i)
    results = {}
    for name, a in alerts.items():
        res = {"benign": rate(a, ~label), "attacks": rate(a, label)}
        for g, d in groups.items():
            res["by_" + g] = {k: {"alerts": int(a[idx].sum()), "of": len(idx), "rate": float(a[idx].mean())}
                              for k, idx in sorted(d.items())}
        results[name] = res
    f = results["fused"]
    checks = {"benign_alert_rate_at_most_1pct": f["benign"]["rate"] <= CEILING,
              "attack_detection_at_least_90pct": f["attacks"]["rate"] >= DETECT,
              "each_technique_at_least_75pct": all(t in f["by_technique"] and f["by_technique"][t]["rate"] >= PER_TECHNIQUE
                                                   for t in TECHNIQUES)}
    report = {"schema": "predict-shield/superviz25-sql-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "results": results, "checks": checks, "passed": all(checks.values()),
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"]}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    for name, r in results.items():
        print(name, "benign", r["benign"]["alerts"], "/", r["benign"]["of"], "attacks", r["attacks"]["alerts"], "/",
              r["attacks"]["of"], {k: round(v["rate"], 3) for k, v in r["by_technique"].items()})
    print(json.dumps(checks), "PASSED" if report["passed"] else "FAILED")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test"))
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.data, a.out_dir)
    else:
        test(a.data, a.frozen_dir, a.expected_freeze_sha256, a.output)


if __name__ == "__main__":
    main()
