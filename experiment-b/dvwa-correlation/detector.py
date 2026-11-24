"""Request-process-network-file correlation detector on a live DVWA. See protocol.json.

  python detector.py develop --out-dir frozen                     benign traffic only; fit, threshold, freeze
  python detector.py test --frozen-dir frozen --expected-freeze-sha256 H --output r.json
                                                                   one mixed session; score once

Both stages need MariaDB on 127.0.0.1:3306 (user dvwa / p@ssw0rd, database dvwa), php-cli with mysqli, strace.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import random
import tempfile
import time
from pathlib import Path

import numpy as np

import lab

HERE = Path(__file__).resolve().parent
DEV_SEED = 20261124
TEST_BENIGN_SEED = 20261209
TEST_ATTACK_SEED = 20261210
TEST_ORDER_SEED = 20261211
N_DEV = 2000
N_TEST_BENIGN = 1000
ATTACKS_PER_FAMILY = 40
FIT_SHARE = 0.7
BUDGET = 0.005
CEILING = 0.01
DETECTION_REQUIRED = 0.90
FAMILY_REQUIRED = 0.75
MODALITIES = ("request", "process", "network", "file", "correlated")
CODE_FILES = ("lab.py", "detector.py", "protocol.json")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha256((HERE / n).read_bytes()) for n in CODE_FILES}


def normal_threshold(scores, rate: float) -> float:
    s = np.sort(np.asarray(scores, dtype=np.float64))
    allowed = int(np.floor(rate * len(s)))
    return float(s[len(s) - 1 - allowed])


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [float(max(0.0, c - h)), float(min(1.0, c + h))]


def session(exchanges: list[lab.Exchange], workdir: Path, attack_session: bool):
    """Run exchanges in order against a fresh traced DVWA; return exchanges, per-request calls, docroot."""
    docroot = workdir / "dvwa"
    lab.clone_dvwa(docroot)
    trace = workdir / "trace.txt"
    server = lab.TracedDvwa(docroot, 8093, trace)
    canary = lab.Canary() if attack_session else None
    try:
        server.setup_database()
        legit = lab.legit_rows(server)
        if attack_session:
            exchanges = exchanges(canary.port)
        for i, ex in enumerate(exchanges):
            server.send(ex)
            if i % 200 == 0:
                print(f"  request {i}/{len(exchanges)}", flush=True)
        time.sleep(2.0)
    finally:
        server.stop()
        if canary:
            canary.stop()
    if attack_session:
        facts = lab.host_facts()
        for ex in exchanges:
            if ex.kind == "attack":
                ex.success = lab.judge(ex, legit, canary, facts)
    calls = lab.parse_strace(trace.read_text())
    per = lab.attribute(exchanges, calls)
    empty = sum(1 for c in per if not c)
    print(f"  {len(calls)} system calls; {empty} requests with none attributed", flush=True)
    return exchanges, per, str(docroot)


def matrices(exchanges, per, vocab, docroot):
    rows = [lab.features(e, c, vocab, docroot) for e, c in zip(exchanges, per)]
    return {m: np.asarray([r[m] for r in rows], dtype=np.float64) for m in MODALITIES}


def develop(out_dir: Path) -> None:
    rng = random.Random(DEV_SEED)
    exchanges = [lab.benign(rng) for _ in range(N_DEV)]
    with tempfile.TemporaryDirectory() as tmp:
        exchanges, per, docroot = session(exchanges, Path(tmp), False)
    cut = int(FIT_SHARE * len(exchanges))
    vocab = lab.build_vocab(exchanges[:cut], per[:cut], docroot)
    x = matrices(exchanges, per, vocab, docroot)
    from sklearn.ensemble import IsolationForest
    models, thresholds, dev = {}, {}, {}
    for m in MODALITIES:
        model = IsolationForest(n_estimators=300, random_state=DEV_SEED).fit(x[m][:cut])
        thr = normal_threshold(-model.score_samples(x[m][cut:]), BUDGET)
        models[m], thresholds[m] = model, thr
        held = -model.score_samples(x[m][cut:]) > thr
        dev[m] = {"threshold_rows": int(len(held)), "alerts": int(held.sum()), "alert_rate": float(held.mean())}
    out_dir.mkdir(parents=True, exist_ok=True)
    blob = pickle.dumps({"models": models, "thresholds": thresholds, "vocab": vocab.to_json()}, protocol=5)
    (out_dir / "models.pkl").write_bytes(blob)
    families = {}
    for e in exchanges:
        families[e.family] = families.get(e.family, 0) + 1
    freeze = {"schema": "predict-shield/dvwa-correlation-freeze/1", "models_sha256": sha256(blob),
              "thresholds": thresholds, "vocab": vocab.to_json(), "code_sha256": code_hashes(),
              "dvwa_commit": lab.DVWA_COMMIT, "sklearn": __import__("sklearn").__version__,
              "development_requests": len(exchanges), "fit_rows": cut, "benign_families": families}
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (out_dir / "development-report.json").write_text(json.dumps(
        {"schema": "predict-shield/dvwa-correlation-development/1", "held_out_benign": dev,
         "freeze_sha256": freeze["freeze_sha256"]}, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], json.dumps(dev), flush=True)


def verify(frozen: Path, expected: str):
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    blob = (frozen / "models.pkl").read_bytes()
    if sha256(blob) != freeze["models_sha256"]:
        raise SystemExit("models do not match the freeze")
    freeze["freeze_sha256"] = rec
    return freeze, pickle.loads(blob)


def test_session_plan():
    rng = random.Random(TEST_BENIGN_SEED)
    benign = [lab.benign(rng) for _ in range(N_TEST_BENIGN)]

    def build(canary_port: int):
        attacks = lab.attacks(random.Random(TEST_ATTACK_SEED), canary_port, ATTACKS_PER_FAMILY)
        allx = benign + attacks
        random.Random(TEST_ORDER_SEED).shuffle(allx)
        return allx
    return build


def rates(alerts: np.ndarray, mask: np.ndarray) -> dict:
    k, n = int((alerts & mask).sum()), int(mask.sum())
    return {"alerts": k, "of": n, "rate": k / n if n else None, "wilson_95": wilson(k, n)}


def test(frozen: Path, expected: str, output: Path) -> None:
    freeze, b = verify(frozen, expected)
    with tempfile.TemporaryDirectory() as tmp:
        exchanges, per, docroot = session(test_session_plan(), Path(tmp), True)
    vocab = lab.Vocab.from_json(b["vocab"])
    x = matrices(exchanges, per, vocab, docroot)
    kind = np.array([e.kind for e in exchanges])
    fam = np.array([e.family for e in exchanges])
    succ = np.array([bool(e.success) for e in exchanges])
    benign, attack = kind == "benign", kind == "attack"
    success, failed = attack & succ, attack & ~succ
    families = sorted(set(fam[attack]))
    alerts = {m: -b["models"][m].score_samples(x[m]) > b["thresholds"][m] for m in MODALITIES}
    alerts["any_single_modality"] = alerts["request"] | alerts["process"] | alerts["network"] | alerts["file"]
    results = {}
    for m, a in alerts.items():
        results[m] = {"benign": rates(a, benign), "successful_attacks": rates(a, success),
                      "failed_attempts": rates(a, failed),
                      "successful_by_family": {f: rates(a, success & (fam == f)) for f in families}}
    c = results["correlated"]
    checks = {
        "benign_alert_rate_at_most_1pct": bool(c["benign"]["rate"] <= CEILING),
        "successful_attack_detection_at_least_90pct": bool(c["successful_attacks"]["rate"] is not None
                                                           and c["successful_attacks"]["rate"] >= DETECTION_REQUIRED),
        "each_family_at_least_75pct": bool(len(families) == 4 and all(
            c["successful_by_family"][f]["rate"] is not None and c["successful_by_family"][f]["rate"] >= FAMILY_REQUIRED
            for f in families)),
    }
    attempts = {f: {"attempts": int((attack & (fam == f)).sum()), "successful": int((success & (fam == f)).sum())}
                for f in families}
    report = {"schema": "predict-shield/dvwa-correlation-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "requests": len(exchanges), "benign": int(benign.sum()), "attack_attempts": attempts,
              "results": results, "checks": checks, "passed": all(checks.values()),
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"],
              "note": "One test session, generated live from fixed seeds after the freeze. Benign traffic is synthetic."}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({m: {"benign": r["benign"]["rate"], "successful": r["successful_attacks"]["rate"],
                          "by_family": {f: v["rate"] for f, v in r["successful_by_family"].items()}}
                      for m, r in results.items()}, indent=1))
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
