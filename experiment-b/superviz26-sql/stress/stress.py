"""Input-noise stress test on Superviz26-SQL. See protocol.json.

  python stress.py develop --zip s26.zip --out-dir frozen --models-dir M
  python stress.py test --zip s26.zip --frozen-dir frozen --models-dir M --base-models-dir B \
      --expected-freeze-sha256 H --output frozen/test-report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import random
import re
import sys
import zipfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import model26 as m26  # noqa: E402

s25, v3 = m26.s25, m26.v3
LOCALES = ("en_US", "en_IE", "fr_FR", "de_DE", "es_ES", "pt_BR", "tr_TR", "pl_PL", "vi_VN", "ja_JP", "zh_CN",
           "ar_AA", "hi_IN", "sw")
KINDS = ("name", "street_address", "company", "city")
PER = 2000
TRAIN_POOL_SEED, TEST_POOL_SEED, TRAIN_ROW_SEED, TEST_ROW_SEED = 2026112901, 2026112902, 2026112903, 2026112904
RATES = (1, 5, 20)
BASE_FREEZE = "b739c5846f913c5e786b105f2038b7f030b72f992d9fb18f64dc77db64dced35"
SPAN = re.compile(r"[A-Za-z][A-Za-z]+(?: [A-Za-z][A-Za-z]+)*")
CODE_DIRS = {"stress.py": HERE, "protocol.json": HERE, "model26.py": m26.HERE, "model_sql.py": m26.S25,
             "model_v3.py": m26.V3}


def code_hashes() -> dict:
    return {f"{d.name}/{n}": m26.sha256((d / n).read_bytes()) for n, d in CODE_DIRS.items()}


def pool(seed: int) -> list[str]:
    from faker import Faker
    out = []
    for i, loc in enumerate(LOCALES):
        f = Faker(loc)
        f.seed_instance(seed + i)
        for k in KINDS:
            out.extend(str(getattr(f, k)()).replace("\n", ", ") for _ in range(PER))
    return out


def pool_sha(p: list[str]) -> str:
    return m26.sha256("\n".join(p).encode())


def perturb(val: str, rng: random.Random, values: list[str]) -> str | None:
    """Replace the first run of Latin-letter words; None if the row has none."""
    mt = SPAN.search(val)
    if mt is None:
        return None
    return val[:mt.start()] + rng.choice(values) + val[mt.end():]


def noisy_train(pairs: list, r: float, values: list[str]) -> tuple[list, int]:
    rng, out, k = random.Random(TRAIN_ROW_SEED), [], 0
    for t, v in pairs:
        if rng.random() < r:
            p = perturb(v, rng, values)
            if p is not None:
                v, k = p, k + 1
        out.append((t, v))
    return out, k


def develop(zpath: Path, out_dir: Path, models_dir: Path) -> None:
    m26.check_source(zpath)
    if (out_dir / "freeze.json").exists():
        raise SystemExit("a freeze already exists")
    train_pool = pool(TRAIN_POOL_SEED)
    models_dir.mkdir(parents=True, exist_ok=True)
    freeze = {"schema": "predict-shield/superviz26-stress-freeze/1", "source_sha256": m26.file_sha256(zpath),
              "code_sha256": code_hashes(), "faker": __import__("faker").VERSION,
              "train_pool_sha256": pool_sha(train_pool), "test_pool_sha256": pool_sha(pool(TEST_POOL_SEED)),
              "sklearn": __import__("sklearn").__version__, "arms": {}}
    with zipfile.ZipFile(zpath) as z:
        for x in m26.DOMAINS:
            member = f"superviz26-lodo/{x}-{x}.csv"
            clean = [(r["query_template_id"], r["user_inputs"]) for r in m26.rows(z, member, "train") if r["label"] == "0"]
            for rate in RATES:
                name = f"matched-{x}-{rate}"
                data, k = noisy_train(clean, rate / 100, train_pool)
                state, model, info = m26.fit(data)
                blob = pickle.dumps({"state": state, "model": model}, protocol=5)
                (models_dir / f"{name}.pkl").write_bytes(blob)
                freeze["arms"][name] = {"member": member, "rate": rate, "train_rows": len(data), "perturbed_train_rows": k,
                                        "model_sha256": m26.sha256(blob), "thresholds": state["thresholds"], **info}
                print("FIT", name, k, json.dumps(info), flush=True)
    freeze["freeze_sha256"] = m26.sha256(json.dumps(freeze, sort_keys=True).encode())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], flush=True)


def load(models_dir: Path, name: str, want: str) -> dict:
    blob = (models_dir / f"{name}.pkl").read_bytes()
    if m26.sha256(blob) != want:
        raise SystemExit(f"model {name} does not match its freeze")
    return pickle.loads(blob)


def alerts(bundle: dict, samples: list) -> dict:
    state, model = bundle["state"], bundle["model"]
    raw = s25.evidence(samples, state, model)
    cal, thr = np.asarray(state["calibration"]), state["thresholds"]
    return {"fused": v3.fused(raw, cal, range(2)) > thr["fused"],
            "input_novelty": raw[:, 0] > thr["input_novelty"], "learned_anomaly": raw[:, 1] > thr["learned_anomaly"]}


def summarise(a: dict, label: np.ndarray, pert: np.ndarray, tech: list) -> dict:
    out = {}
    for name, x in a.items():
        res = {"benign": m26.rate(x, ~label), "attacks": m26.rate(x, label),
               "perturbed_benign": m26.rate(x, pert), "unperturbed_benign": m26.rate(x, ~label & ~pert)}
        if name == "fused":
            by = {}
            for i, t in enumerate(tech):
                if label[i]:
                    by.setdefault(t or "(none)", []).append(i)
            res["by_attack_technique"] = {t: {"alerts": int(x[idx].sum()), "of": len(idx), "rate": float(x[idx].mean())}
                                          for t, idx in sorted(by.items())}
        out[name] = res
    return out


def test(zpath: Path, frozen: Path, models_dir: Path, base_dir: Path, base_frozen: Path, expected: str,
         output: Path) -> None:
    if output.exists():
        raise SystemExit("a test report already exists; the test runs once")
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or m26.sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    base = json.loads((base_frozen / "freeze.json").read_text())
    if base["freeze_sha256"] != BASE_FREEZE:
        raise SystemExit("base freeze does not match")
    test_pool = pool(TEST_POOL_SEED)
    if pool_sha(test_pool) != freeze["test_pool_sha256"]:
        raise SystemExit("test pool differs from the freeze")
    m26.check_source(zpath)
    results, checks = {}, {}
    with zipfile.ZipFile(zpath) as z:
        for x in m26.DOMAINS:
            member = f"superviz26-lodo/{x}-{x}.csv"
            clean, label, tech = [], [], []
            for r in m26.rows(z, member, "test"):
                clean.append((r["query_template_id"], r["user_inputs"]))
                label.append(r["label"] == "1")
                tech.append(r["attack_technique"])
            label = np.array(label)
            # shock: every eligible benign row perturbed, frozen indomain model
            rng, shocked, pert = random.Random(TEST_ROW_SEED), [], np.zeros(len(clean), dtype=bool)
            for i, (t, v) in enumerate(clean):
                p = None if label[i] else perturb(v, rng, test_pool)
                pert[i] = p is not None
                shocked.append((t, v if p is None else p))
            bname = f"indomain-{x}"
            res = summarise(alerts(load(base_dir, bname, base["arms"][bname]["model_sha256"]), shocked), label, pert, tech)
            f = res["fused"]
            clean_rate = f["unperturbed_benign"]["rate"]
            res["eligible_benign_share"] = float(pert.sum() / (~label).sum())
            res["implied_benign_rate"] = {}
            for rate in RATES:
                q = rate / 100 * res["eligible_benign_share"]
                res["implied_benign_rate"][str(rate)] = None if clean_rate is None else \
                    (1 - q) * clean_rate + q * f["perturbed_benign"]["rate"]
            results[f"shock-{x}"] = res
            print("shock", x, "perturbed benign alert rate", round(f["perturbed_benign"]["rate"], 4),
                  "eligible", round(res["eligible_benign_share"], 3), flush=True)
            del shocked
            for rate in RATES:
                name = f"matched-{x}-{rate}"
                rng, noisy, pert = random.Random(TEST_ROW_SEED + rate), [], np.zeros(len(clean), dtype=bool)
                for i, (t, v) in enumerate(clean):
                    p = None
                    if not label[i] and rng.random() < rate / 100:
                        p = perturb(v, rng, test_pool)
                    pert[i] = p is not None
                    noisy.append((t, v if p is None else p))
                res = summarise(alerts(load(models_dir, name, freeze["arms"][name]["model_sha256"]), noisy), label, pert, tech)
                results[name] = res
                f = res["fused"]
                print(name, "benign", round(f["benign"]["rate"], 4), "perturbed", f["perturbed_benign"]["rate"],
                      "attacks", round(f["attacks"]["rate"], 4), flush=True)
                if rate == 5:
                    checks[x] = {"benign_alert_rate_at_most_1pct": f["benign"]["rate"] <= 0.01,
                                 "attack_detection_at_least_90pct": f["attacks"]["rate"] >= 0.90}
                del noisy
    passed = {x: all(c.values()) for x, c in checks.items()}
    report = {"schema": "predict-shield/superviz26-stress-test/1", "freeze_sha256": rec, "base_freeze_sha256": BASE_FREEZE,
              "results": results, "matched_5pct_checks": checks, "matched_5pct_passed": passed,
              "primary_domains_passed": sum(passed[x] for x in m26.PRIMARY),
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"]}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps(checks), "PRIMARY PASSED", report["primary_domains_passed"], "of 3")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test"))
    ap.add_argument("--zip", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--base-models-dir", type=Path)
    ap.add_argument("--base-frozen-dir", type=Path, default=HERE.parent / "frozen")
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.zip, a.out_dir, a.models_dir)
    else:
        test(a.zip, a.frozen_dir, a.models_dir, a.base_models_dir, a.base_frozen_dir, a.expected_freeze_sha256, a.output)


if __name__ == "__main__":
    main()
