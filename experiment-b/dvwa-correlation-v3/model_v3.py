"""DVWA correlation detector v3: per-field request profiles and calibrated evidence fusion.

Four kinds of evidence per request, each learned from benign traffic only:

  request_novelty   character classes, lengths and parameter names never seen in
                    that field of that page during development
  host_novelty      programs, connection endpoints and files never seen during
                    development
  response_shift    distance of the response's structure from the page's benign
                    profile (robust z, largest component)
  learned_anomaly   IsolationForest over the v1 correlated features

Each score becomes a tail probability against a separate benign calibration
split; the four are fused with Fisher's method, so no weight is chosen by hand.
The alert threshold is set on a third benign split.

Test traffic comes from the existing v1 generator (lab.benign, lab.attacks) with
new seeds. Success is judged by lab.judge from responses and the canary.

  python model_v3.py develop --out-dir frozen
  python model_v3.py test --frozen-dir frozen --expected-freeze-sha256 H --output r.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import pickle
import random
import re
import sys
import tempfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
V1 = HERE.parent / "dvwa-correlation"
sys.path.insert(0, str(V1))
import detector as v1  # noqa: E402
import lab  # noqa: E402

DEV_SEED = 2026112701
TEST_BENIGN_SEED = 2026112711
TEST_ATTACK_SEED = 2026112712
TEST_ORDER_SEED = 2026112713
N_DEV = 3000
FIT_SHARE, CAL_SHARE = 0.40, 0.35   # the remaining 25% sets the threshold
N_TEST_BENIGN = 1000
ATTACKS_PER_FAMILY = 40
BUDGET = 0.005
CEILING = 0.01
DETECTION_REQUIRED = 0.90
FAMILY_REQUIRED = 0.75
COMPONENTS = ("request_novelty", "host_novelty", "response_shift", "learned_anomaly")
CODE_FILES = {"model_v3.py": HERE, "protocol.json": HERE, "lab.py": V1, "detector.py": V1}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha256((d / n).read_bytes()) for n, d in CODE_FILES.items()}


# ------------------------------------------------------------------ evidence

def char_class(ch: str) -> str:
    return "digit" if ch.isdigit() else "alpha" if ch.isalpha() else ch


def request_profiles(exchanges) -> dict:
    """Per (page, parameter): character classes and length range seen in benign traffic."""
    paths, fields = set(), {}
    for e in exchanges:
        paths.add(e.path)
        for k, v in e.params.items():
            v = str(v)
            f = fields.setdefault(f"{e.path}|{k}", {"chars": set(), "min": len(v), "max": len(v)})
            f["chars"] |= {char_class(c) for c in v}
            f["min"], f["max"] = min(f["min"], len(v)), max(f["max"], len(v))
    return {"paths": sorted(paths),
            "fields": {k: {"chars": sorted(f["chars"]), "min": f["min"], "max": f["max"]} for k, f in fields.items()}}


def request_novelty(e: lab.Exchange, prof: dict) -> float:
    if e.path not in prof["paths"]:
        return 10.0
    s = 0.0
    for k, v in e.params.items():
        f = prof["fields"].get(f"{e.path}|{k}")
        if f is None:
            s += 3.0
            continue
        v = str(v)
        s += len({char_class(c) for c in v} - set(f["chars"]))
        if len(v) > f["max"]:
            s += math.log2(1 + len(v) - f["max"])
        elif len(v) < f["min"]:
            s += 1.0
    return s


def host_novelty(row: dict) -> float:
    return float(row["process"][2] + row["network"][2] + row["file"][2])


def response_vector(e: lab.Exchange) -> np.ndarray:
    b = e.body
    text = re.sub(r"<[^>]+>", " ", b)
    return np.array([math.log1p(len(b)), b.count("<pre>"), len(re.findall(r"<br\s*/?>", b)),
                     len(re.findall(r"\b(?:error|warning|notice|fatal)\b", text, re.I)),
                     math.log1p(len(text.split())), float(e.status)], dtype=np.float64)


def response_profiles(exchanges) -> dict:
    groups: dict = {}
    for e in exchanges:
        groups.setdefault(e.path, []).append(response_vector(e))
    out = {}
    for p, rows in groups.items():
        x = np.vstack(rows)
        med = np.median(x, axis=0)
        mad = np.median(np.abs(x - med), axis=0) * 1.4826
        out[p] = {"median": med.tolist(), "scale": np.maximum(mad, 0.5).tolist()}
    return out


def response_shift(e: lab.Exchange, prof: dict) -> float:
    p = prof.get(e.path)
    if p is None:
        return 10.0
    z = np.abs(response_vector(e) - np.asarray(p["median"])) / np.asarray(p["scale"])
    return float(min(50.0, z.max()))


def evidence(exchanges, per, docroot, state, model) -> np.ndarray:
    """Rows of the four raw component scores (higher is more suspicious)."""
    vocab = lab.Vocab.from_json(state["vocab"])
    rows = [lab.features(e, c, vocab, docroot) for e, c in zip(exchanges, per)]
    corr = np.asarray([r["correlated"] for r in rows], dtype=np.float64)
    anomaly = -model.score_samples(corr)
    return np.column_stack([
        [request_novelty(e, state["request_profiles"]) for e in exchanges],
        [host_novelty(r) for r in rows],
        [response_shift(e, state["response_profiles"]) for e in exchanges],
        anomaly,
    ])


def tail_p(scores: np.ndarray, reference: np.ndarray) -> np.ndarray:
    """P(benign score >= s), with the +1 correction so it is never zero."""
    ref = np.sort(reference)
    ge = len(ref) - np.searchsorted(ref, scores, side="left")
    return (1.0 + ge) / (1.0 + len(ref))


def fused(raw: np.ndarray, calibration: np.ndarray, columns=range(len(COMPONENTS))) -> np.ndarray:
    """Fisher's statistic over the chosen components."""
    return sum(-2.0 * np.log(tail_p(raw[:, j], calibration[:, j])) for j in columns)


# ------------------------------------------------------------------ stages

def develop(out_dir: Path) -> None:
    rng = random.Random(DEV_SEED)
    with tempfile.TemporaryDirectory() as tmp:
        exchanges, per, docroot = v1.session([lab.benign(rng) for _ in range(N_DEV)], Path(tmp), False)
        a, b = int(FIT_SHARE * len(exchanges)), int((FIT_SHARE + CAL_SHARE) * len(exchanges))
        fit_x, fit_p = exchanges[:a], per[:a]
        state = {"vocab": lab.build_vocab(fit_x, fit_p, docroot).to_json(),
                 "request_profiles": request_profiles(fit_x), "response_profiles": response_profiles(fit_x)}
        vocab = lab.Vocab.from_json(state["vocab"])
        corr = np.asarray([lab.features(e, c, vocab, docroot)["correlated"] for e, c in zip(fit_x, fit_p)])
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(n_estimators=300, random_state=DEV_SEED).fit(corr)
        raw = evidence(exchanges, per, docroot, state, model)
    cal, thr_rows = raw[a:b], raw[b:]
    state["calibration"] = cal.tolist()
    thresholds = {"fused": v1.normal_threshold(fused(thr_rows, cal), BUDGET)}
    for j, name in enumerate(COMPONENTS):
        thresholds[name] = v1.normal_threshold(thr_rows[:, j], BUDGET)
    thresholds["fused_without_learned_anomaly"] = v1.normal_threshold(fused(thr_rows, cal, range(3)), BUDGET)
    state["thresholds"] = thresholds
    held = fused(thr_rows, cal) > thresholds["fused"]
    blob = pickle.dumps({"state": state, "model": model}, protocol=5)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "model.pkl").write_bytes(blob)
    freeze = {"schema": "predict-shield/dvwa-v3-freeze/1", "model_sha256": sha256(blob),
              "code_sha256": code_hashes(), "dvwa_commit": lab.DVWA_COMMIT,
              "sklearn": __import__("sklearn").__version__, "thresholds": thresholds,
              "rows": {"fit": a, "calibration": b - a, "threshold": len(exchanges) - b},
              "threshold_split_alert_rate": float(held.mean())}
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


def test(frozen: Path, expected: str, output: Path) -> None:
    if output.exists():
        raise SystemExit("a test report already exists; the test session runs once")
    freeze, bundle = verify(frozen, expected)
    state, model = bundle["state"], bundle["model"]
    brng = random.Random(TEST_BENIGN_SEED)
    benign = [lab.benign(brng) for _ in range(N_TEST_BENIGN)]

    def build(canary_port: int):
        allx = benign + lab.attacks(random.Random(TEST_ATTACK_SEED), canary_port, ATTACKS_PER_FAMILY)
        random.Random(TEST_ORDER_SEED).shuffle(allx)
        return allx

    with tempfile.TemporaryDirectory() as tmp:
        exchanges, per, docroot = v1.session(build, Path(tmp), True)
        raw = evidence(exchanges, per, docroot, state, model)
    cal, thr = np.asarray(state["calibration"]), state["thresholds"]
    kind = np.array([e.kind for e in exchanges])
    fam = np.array([e.family for e in exchanges])
    succ = np.array([bool(e.success) for e in exchanges])
    ben, att = kind == "benign", kind == "attack"
    success, failed = att & succ, att & ~succ
    families = sorted(set(fam[att]))
    alerts = {"fused": fused(raw, cal) > thr["fused"],
              "fused_without_learned_anomaly": fused(raw, cal, range(3)) > thr["fused_without_learned_anomaly"]}
    for j, name in enumerate(COMPONENTS):
        alerts[name] = raw[:, j] > thr[name]
    results = {m: {"benign": v1.rates(a, ben), "successful_attacks": v1.rates(a, success),
                   "failed_attempts": v1.rates(a, failed),
                   "successful_by_family": {f: v1.rates(a, success & (fam == f)) for f in families}}
               for m, a in alerts.items()}
    r = results["fused"]
    checks = {
        "benign_alert_rate_at_most_1pct": bool(r["benign"]["rate"] <= CEILING),
        "successful_attack_detection_at_least_90pct": bool((r["successful_attacks"]["rate"] or 0) >= DETECTION_REQUIRED),
        "each_family_at_least_75pct": bool(len(families) == 4 and all(
            (r["successful_by_family"][f]["rate"] or 0) >= FAMILY_REQUIRED for f in families)),
    }
    report = {"schema": "predict-shield/dvwa-v3-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "requests": len(exchanges), "benign": int(ben.sum()),
              "attack_attempts": {f: {"attempts": int((att & (fam == f)).sum()),
                                      "successful": int((success & (fam == f)).sum())} for f in families},
              "results": results, "checks": checks, "passed": all(checks.values()),
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"],
              "note": "One test session from new seeds. Attack payloads come from the v1 generator and were seen in earlier versions; benign traffic is synthetic."}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    for m, v in results.items():
        print(m, v["benign"]["alerts"], "benign;", v["successful_attacks"]["alerts"], "/",
              v["successful_attacks"]["of"], {f: x["alerts"] for f, x in v["successful_by_family"].items()})
    print(json.dumps(checks), "PASSED" if report["passed"] else "FAILED")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test"))
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.out_dir)
    else:
        test(a.frozen_dir, a.expected_freeze_sha256, a.output)


if __name__ == "__main__":
    main()
