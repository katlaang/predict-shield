"""The v3 SQL method on Superviz26-SQL, one model per arm. See protocol.json.

  python model26.py develop --zip superviz26.zip --out-dir frozen --models-dir models
  python model26.py test --zip superviz26.zip --frozen-dir frozen --models-dir models \
      --expected-freeze-sha256 H --output frozen/test-report.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import pickle
import random
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
S25 = HERE.parent / "superviz25-sql"
V3 = HERE.parent / "dvwa-correlation-v3"
sys.path.insert(0, str(S25))
sys.path.insert(0, str(V3))
import model_sql as s25  # noqa: E402
import model_v3 as v3  # noqa: E402

csv.field_size_limit(1 << 30)
SEED = s25.SEED
FIT, CAL, BUDGET = s25.FIT, s25.CAL, s25.BUDGET
CEILING, DETECT, PER_TECHNIQUE, MIN_TECHNIQUE_ROWS = 0.01, 0.90, 0.75, 1000
DOMAINS = "abcd"
PRIMARY = ("b", "c", "d")
FEWSHOT = (500, 5000)
CODE = {"model26.py": HERE, "protocol.json": HERE, "model_sql.py": S25, "model_v3.py": V3}


def arms() -> dict:
    """arm name -> (zip member, few-shot size or None)."""
    out = {}
    for x in DOMAINS:
        out[f"indomain-{x}"] = (f"superviz26-lodo/{x}-{x}.csv", None)
        others = "".join(d for d in DOMAINS if d != x)
        out[f"lodo-{x}"] = (f"superviz26-lodo/{others}-{x}.csv", None)
        out[f"drift-{x}"] = (f"superviz26-cd/{x}.csv", None)
    for x in PRIMARY:
        for n in FEWSHOT:
            out[f"fewshot-{x}-{n}"] = (f"superviz26-lodo/{x}-{x}.csv", n)
    return dict(sorted(out.items()))


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha256((d / n).read_bytes()) for n, d in CODE.items()}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def check_source(path: Path) -> None:
    want = json.loads((HERE / "protocol.json").read_text())["source"]["sha256"]
    if file_sha256(path) != want:
        raise SystemExit("archive does not match its pin")


def rows(z: zipfile.ZipFile, member: str, split: str):
    with z.open(member) as raw:
        for r in csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")):
            if r["split"] == split:
                yield r


def fit(train: list) -> tuple[dict, object, dict]:
    """The Superviz25 development procedure, unchanged, on one arm's benign rows."""
    train = list(train)
    random.Random(SEED).shuffle(train)
    a, b = int(FIT * len(train)), int((FIT + CAL) * len(train))
    state = {"profiles": s25.profiles(train[:a]), "templates": sorted({t for t, _ in train[:a]})}
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(n_estimators=300, random_state=SEED).fit(
        np.asarray([s25.vector(t, v, state["templates"]) for t, v in train[:a]]))
    raw = s25.evidence(train[a:], state, model)
    cal, thr_rows = raw[: b - a], raw[b - a:]
    state["calibration"] = cal.tolist()
    thresholds = {"fused": v3.v1.normal_threshold(v3.fused(thr_rows, cal, range(2)), BUDGET),
                  "input_novelty": v3.v1.normal_threshold(thr_rows[:, 0], BUDGET),
                  "learned_anomaly": v3.v1.normal_threshold(thr_rows[:, 1], BUDGET)}
    state["thresholds"] = thresholds
    held = v3.fused(thr_rows, cal, range(2)) > thresholds["fused"]
    info = {"rows": {"fit": a, "calibration": b - a, "threshold": len(train) - b},
            "templates_seen": len(state["templates"]), "threshold_split_alert_rate": float(held.mean())}
    return state, model, info


def develop(zpath: Path, out_dir: Path, models_dir: Path) -> None:
    check_source(zpath)
    if (out_dir / "freeze.json").exists():
        raise SystemExit("a freeze already exists")
    models_dir.mkdir(parents=True, exist_ok=True)
    freeze = {"schema": "predict-shield/superviz26-sql-freeze/1", "source_sha256": file_sha256(zpath),
              "code_sha256": code_hashes(), "sklearn": __import__("sklearn").__version__, "arms": {}}
    by_member = defaultdict(list)
    for name, (member, n) in arms().items():
        by_member[member].append((name, n))
    with zipfile.ZipFile(zpath) as z:
        for member, group in sorted(by_member.items()):
            train = [(r["query_template_id"], r["user_inputs"]) for r in rows(z, member, "train") if r["label"] == "0"]
            for name, n in group:
                data = train
                if n is not None:
                    data = list(train)
                    random.Random(SEED + n).shuffle(data)
                    data = data[:n]
                state, model, info = fit(data)
                blob = pickle.dumps({"state": state, "model": model}, protocol=5)
                (models_dir / f"{name}.pkl").write_bytes(blob)
                freeze["arms"][name] = {"member": member, "fewshot": n, "train_rows": len(data),
                                        "model_sha256": sha256(blob), "thresholds": state["thresholds"], **info}
                print("FIT", name, len(data), json.dumps(info), flush=True)
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], flush=True)


def verify(frozen: Path, models_dir: Path, expected: str):
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    bundles = {}
    for name, a in freeze["arms"].items():
        blob = (models_dir / f"{name}.pkl").read_bytes()
        if sha256(blob) != a["model_sha256"]:
            raise SystemExit(f"model {name} does not match the freeze")
        bundles[name] = pickle.loads(blob)
    freeze["freeze_sha256"] = rec
    return freeze, bundles


def rate(a: np.ndarray, mask: np.ndarray) -> dict:
    k, n = int((a & mask).sum()), int(mask.sum())
    return {"alerts": k, "of": n, "rate": k / n if n else None, "wilson_95": v3.v1.wilson(k, n)}


def score(bundle: dict, samples: list, meta: list, with_drift: bool) -> dict:
    state, model = bundle["state"], bundle["model"]
    raw = s25.evidence(samples, state, model)
    cal, thr = np.asarray(state["calibration"]), state["thresholds"]
    alerts = {"fused": v3.fused(raw, cal, range(2)) > thr["fused"],
              "input_novelty": raw[:, 0] > thr["input_novelty"], "learned_anomaly": raw[:, 1] > thr["learned_anomaly"]}
    label = np.array([m["label"] == "1" for m in meta])
    keys = ("attack_technique", "attack_stage", "attack_status", "tamper_method")
    groups = {k: defaultdict(list) for k in keys}
    for i, m in enumerate(meta):
        if m["label"] == "1":
            for k in keys:
                groups[k][m[k] or "(none)"].append(i)
    drift = defaultdict(list)
    if with_drift:
        for i, m in enumerate(meta):
            drift[m.get("drift_set") or "(none)"].append(i)
    out = {}
    for name, a in alerts.items():
        res = {"benign": rate(a, ~label), "attacks": rate(a, label)}
        for k, d in groups.items():
            res["by_" + k] = {v: {"alerts": int(a[idx].sum()), "of": len(idx), "rate": float(a[idx].mean())}
                              for v, idx in sorted(d.items())}
        if with_drift:
            res["by_drift_set"] = {}
            for v, idx in sorted(drift.items()):
                m = np.zeros(len(label), dtype=bool)
                m[idx] = True
                res["by_drift_set"][v] = {"benign": rate(a, m & ~label), "attacks": rate(a, m & label)}
        out[name] = res
    return out


def checks_for(f: dict) -> dict:
    big = {t: v for t, v in f["by_attack_technique"].items() if v["of"] >= MIN_TECHNIQUE_ROWS}
    return {"benign_alert_rate_at_most_1pct": f["benign"]["rate"] is not None and f["benign"]["rate"] <= CEILING,
            "attack_detection_at_least_90pct": f["attacks"]["rate"] is not None and f["attacks"]["rate"] >= DETECT,
            "each_technique_at_least_75pct": bool(big) and all(v["rate"] >= PER_TECHNIQUE for v in big.values())}


def test(zpath: Path, frozen: Path, models_dir: Path, expected: str, output: Path) -> None:
    if output.exists():
        raise SystemExit("a test report already exists; the test runs once")
    freeze, bundles = verify(frozen, models_dir, expected)
    check_source(zpath)
    by_member = defaultdict(list)
    for name, a in freeze["arms"].items():
        by_member[a["member"]].append(name)
    results = {}
    with zipfile.ZipFile(zpath) as z:
        for member, names in sorted(by_member.items()):
            samples, meta = [], []
            for r in rows(z, member, "test"):
                samples.append((r["query_template_id"], r["user_inputs"]))
                meta.append({k: r.get(k, "") for k in ("label", "attack_technique", "attack_stage", "attack_status",
                                                         "tamper_method", "drift_set")})
            for name in sorted(names):
                results[name] = score(bundles[name], samples, meta, name.startswith("drift-"))
                f = results[name]["fused"]
                print(name, "benign", f["benign"]["alerts"], "/", f["benign"]["of"],
                      "attacks", f["attacks"]["alerts"], "/", f["attacks"]["of"], flush=True)
            del samples, meta
    checks = {x: checks_for(results[f"indomain-{x}"]["fused"]) for x in DOMAINS}
    passed = {x: all(c.values()) for x, c in checks.items()}
    report = {"schema": "predict-shield/superviz26-sql-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "results": results, "indomain_checks": checks, "indomain_passed": passed,
              "primary_domains_passed": sum(passed[x] for x in PRIMARY), "primary_domains": list(PRIMARY),
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"]}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps(checks), "PRIMARY PASSED", report["primary_domains_passed"], "of", len(PRIMARY))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test"))
    ap.add_argument("--zip", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.zip, a.out_dir, a.models_dir)
    else:
        test(a.zip, a.frozen_dir, a.models_dir, a.expected_freeze_sha256, a.output)


if __name__ == "__main__":
    main()
