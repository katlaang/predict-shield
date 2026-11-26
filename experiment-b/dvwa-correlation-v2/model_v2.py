"""Follow-up DVWA anomaly experiment with learned response and host novelty.

Independent of v1 frozen model and its results. V1's telemetry collector is
reused but model, threshold, benign-only freeze and test session are new.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import random
import re
import sys
import tempfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dvwa-correlation"))
import detector as v1  # noqa: E402
import lab  # noqa: E402

DEV_SEED = 2026112601
BENIGN_SEED = 2026112602
ATTACK_SEED = 2026112603
ORDER_SEED = 2026112604
DEV_REQUESTS = 1400
TEST_NORMAL = 500
ATTEMPTS_PER_FAMILY = 30
FIT_SHARE = 0.7
CALIBRATION_BUDGET = 0.005
MODALITIES = ("process", "network", "file")
CODE_FILES = ("model_v2.py", "protocol.json")


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def code_hashes() -> dict:
    # Pin imported v1 collector separately, so a modified collector invalidates freeze.
    paths = {n: HERE / n for n in CODE_FILES}
    for n in ("lab.py", "detector.py"):
        paths["v1-" + n] = HERE.parent / "dvwa-correlation" / n
    return {k: sha(v.read_bytes()) for k, v in paths.items()}


def response_vector(ex: lab.Exchange) -> np.ndarray:
    """Structure-only, no attack success oracle or attack family as input."""
    body = ex.body
    text = re.sub(r"<[^>]+>", " ", body)
    return np.asarray([
        np.log1p(len(body)),
        np.log1p(len(re.findall(r"<(?:a|form|input|table|tr|pre)\b", body, re.I))),
        np.log1p(len(re.findall(r"<br\s*/?>", body, re.I))),
        np.log1p(len(re.findall(r"(?:error|warning|notice)", text, re.I))),
        np.log1p(len(text.strip().split())),
        float(ex.status),
    ], dtype=np.float64)


def response_profiles(exchanges) -> dict:
    """Per-page 1st/99th-percentile responses learned on benign development only."""
    groups = {}
    for ex in exchanges:
        groups.setdefault(ex.path, []).append(response_vector(ex))
    profiles = {}
    for path, values in groups.items():
        x = np.vstack(values)
        if len(x) < 10:
            continue
        profiles[path] = {
            "lo": np.quantile(x, 0.01, axis=0).tolist(),
            "hi": np.quantile(x, 0.99, axis=0).tolist(),
            "scale": np.maximum(np.std(x, axis=0), 0.25).tolist(),
            "n": len(x),
        }
    return profiles


def response_novelty(ex: lab.Exchange, profiles: dict) -> float:
    p = profiles.get(ex.path)
    if p is None:
        return 4.0  # unseen page; the calibration set is still benign
    row = response_vector(ex)
    lo, hi, scale = (np.asarray(p[k], dtype=np.float64) for k in ("lo", "hi", "scale"))
    excess = np.maximum(0.0, np.maximum(lo - row, row - hi)) / scale
    return float(min(10.0, np.max(excess)))  # conservative bounded contribution


def scores(model, vocab: lab.Vocab, profiles: dict, exchanges, per, docroot) -> np.ndarray:
    matrices = v1.matrices(exchanges, per, vocab, docroot)
    # IF remains learned anomaly core; novelty features are separately
    # scored because constant-zero training columns cannot split trees.
    anomaly = -model.score_samples(matrices["correlated"])
    unseen = (matrices["process"][:, 2] + matrices["network"][:, 2] +
              matrices["file"][:, 2])
    novelty = np.minimum(6.0, np.log1p(np.maximum(unseen, 0)))
    response = np.array([response_novelty(e, profiles) for e in exchanges])
    return anomaly + 0.08 * novelty + 0.025 * response


def fit(exchanges, per, docroot):
    from sklearn.ensemble import IsolationForest
    cut = int(FIT_SHARE * len(exchanges))
    if cut < 100 or len(exchanges) - cut < 100 or any(e.kind != "benign" for e in exchanges):
        raise ValueError("development must contain sufficiently many benign-only requests")
    vocab = lab.build_vocab(exchanges[:cut], per[:cut], docroot)
    profiles = response_profiles(exchanges[:cut])
    x = v1.matrices(exchanges, per, vocab, docroot)["correlated"]
    model = IsolationForest(n_estimators=250, max_samples=min(512, cut),
                            random_state=DEV_SEED).fit(x[:cut])
    cal = scores(model, vocab, profiles, exchanges[cut:], per[cut:], docroot)
    threshold = v1.normal_threshold(cal, CALIBRATION_BUDGET)
    return {"model": model, "vocab": vocab.to_json(), "response_profiles": profiles,
            "threshold": threshold}, {"fit_rows": cut, "calibration_rows": len(cal),
                                      "calibration_alerts": int((cal > threshold).sum()),
                                      "threshold": threshold}


def develop(out_dir: Path):
    rng = random.Random(DEV_SEED)
    benign = [lab.benign(rng) for _ in range(DEV_REQUESTS)]
    with tempfile.TemporaryDirectory() as temp:
        exchanges, per, docroot = v1.session(benign, Path(temp), False)
        payload, rows = fit(exchanges, per, docroot)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = pickle.dumps(payload, protocol=5)
    (out_dir / "model.pkl").write_bytes(data)
    frozen = {"schema": "predict-shield/dvwa-v2-freeze/1", "model_sha256": sha(data),
              "code_sha256": code_hashes(), "dvwa_commit": lab.DVWA_COMMIT,
              "calibration": rows, "development_seed": DEV_SEED,
              "method": "normal-only IsolationForest plus response/novelty calibration"}
    frozen["freeze_sha256"] = sha(json.dumps(frozen, sort_keys=True).encode())
    (out_dir / "freeze.json").write_text(json.dumps(frozen, sort_keys=True, indent=2) + "\n")
    print("FROZEN", frozen["freeze_sha256"], json.dumps(rows), flush=True)
    return frozen["freeze_sha256"]


def verify(frozen_dir: Path):
    frozen = json.loads((frozen_dir / "freeze.json").read_text())
    got = frozen.pop("freeze_sha256")
    if sha(json.dumps(frozen, sort_keys=True).encode()) != got:
        raise ValueError("freeze record altered")
    if code_hashes() != frozen["code_sha256"]:
        raise ValueError("collector, model, or protocol changed after freeze")
    raw = (frozen_dir / "model.pkl").read_bytes()
    if sha(raw) != frozen["model_sha256"]:
        raise ValueError("frozen model altered")
    frozen["freeze_sha256"] = got
    return frozen, pickle.loads(raw)


def planned_attack_session():
    rng = random.Random(BENIGN_SEED)
    benign = [lab.benign(rng) for _ in range(TEST_NORMAL)]
    def build(canary_port):
        attempts = lab.attacks(random.Random(ATTACK_SEED), canary_port, ATTEMPTS_PER_FAMILY)
        items = benign + attempts
        random.Random(ORDER_SEED).shuffle(items)
        return items
    return build


def test(frozen_dir: Path, output: Path):
    if output.exists():
        raise ValueError("test report already exists; refusing a second held-out run")
    frozen, payload = verify(frozen_dir)
    with tempfile.TemporaryDirectory() as tmp:
        ex, per, docroot = v1.session(planned_attack_session(), Path(tmp), True)
        score = scores(payload["model"], lab.Vocab.from_json(payload["vocab"]),
                       payload["response_profiles"], ex, per, docroot)
    alert = score > payload["threshold"]
    kind = np.array([e.kind for e in ex])
    family = np.array([e.family for e in ex])
    success = np.array([bool(e.success) for e in ex])
    benign = kind == "benign"
    detected = (kind == "attack") & success
    unknown = (kind == "attack") & ~success
    def counts(mask):
        return {"alerts": int((alert & mask).sum()), "rows": int(mask.sum()),
                "rate": float((alert & mask).sum() / mask.sum()) if mask.any() else None}
    by_family = {f: counts(detected & (family == f)) for f in sorted(set(family[kind == "attack"]))}
    checks = {"normal_at_most_1pct": counts(benign)["rate"] <= 0.01,
              "attacks_at_least_90pct": counts(detected)["rate"] is not None and counts(detected)["rate"] >= 0.90,
              "each_family_at_least_75pct": all(x["rows"] > 0 and x["rate"] >= 0.75 for x in by_family.values())}
    report = {"schema": "predict-shield/dvwa-v2-fresh-session/1",
              "freeze_sha256": frozen["freeze_sha256"],
              "development_is_benign_only": True,
              "attack_families_previously_examined": True, "test_seeds_distinct_from_development": True,
              "same_fixed_seed_on_future_replay": True,
              "benign": counts(benign), "successful_attacks": counts(detected),
              "unsuccessful_attack_attempts": counts(unknown),
              "attack_families": by_family, "checks": checks, "passed": all(checks.values()),
              "limitations": "Fresh test traffic, same synthetic DVWA scenario families as earlier tests, not operational or zero-day evidence."}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("develop", "test"))
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--frozen-dir", type=Path)
    parser.add_argument("--output", type=Path)
    a = parser.parse_args()
    if a.stage == "develop":
        if a.out_dir is None or (a.out_dir / "freeze.json").exists():
            raise ValueError("development requires a fresh out-dir")
        develop(a.out_dir)
    else:
        if a.frozen_dir is None or a.output is None:
            raise ValueError("test requires frozen-dir and output")
        test(a.frozen_dir, a.output)


if __name__ == "__main__":
    main()
