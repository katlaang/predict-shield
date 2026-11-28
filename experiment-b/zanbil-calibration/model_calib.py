"""Calibration comparison on one site's raw access log. See protocol.json.

  python model_calib.py select  --log access.log[.zip] --out-dir frozen
  python model_calib.py test    --log access.log[.zip] --frozen-dir frozen --expected-freeze-sha256 H --output frozen/test-report.json
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import sys
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "real-logs-indonesia"))
import model_logs as m  # noqa: E402

SEED, BUDGET = m.SEED, m.BUDGET
CANDIDATES = ("C0-random", "C1-temporal", "C2-temporal-strata", "C3-temporal-abstain")
MIN_STRATUM, MIN_REF, MAX_ABSTAIN, TIE = 1000, 200, 0.05, 0.001
LO, HI = 0.0025, 0.01
CODE = {"model_calib.py": HERE, "protocol.json": HERE, "model_logs.py": HERE.parent / "real-logs-indonesia",
        "model_sql.py": m.S25, "model_v3.py": m.V3}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha((d / n).read_bytes()) for n, d in CODE.items()}


def check_source(path: Path, pinned: bool) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if pinned and digest != json.loads((HERE / "protocol.json").read_text())["source"]["received"]["sha256"]:
        raise SystemExit("archive does not match the pinned SHA-256 (amendment 1)")
    return digest


def lines(path: Path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            name = "access.log" if "access.log" in z.namelist() else max(
                (i for i in z.infolist() if not i.is_dir()), key=lambda i: i.file_size).filename
            with z.open(name) as raw:
                yield from io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
    else:
        with open(path, encoding="utf-8", errors="replace") as f:
            yield from f


def rows(path: Path) -> list:
    out = []
    for line in lines(path):
        mt = m.LINE.match(line)
        if not mt:
            continue
        p = m.parse(mt.group(4))
        if p is None:
            continue
        try:
            t = datetime.strptime(mt.group(2), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        out.append((t, f"shop|{mt.group(3)}|{p[0]}", p[1]))
    out.sort(key=lambda r: r[0])
    return out


def periods(data: list) -> dict:
    days = sorted({r[0].strftime("%Y-%m-%d") for r in data})
    k = max(2, int(0.6 * len(days)))
    if k >= len(days):
        raise SystemExit("too few days for a development and test split")
    dev = [r for r in data if r[0].strftime("%Y-%m-%d") in days[:k]]
    test = [r for r in data if r[0].strftime("%Y-%m-%d") in days[k:]]
    t0, t1 = dev[0][0], dev[-1][0]
    cut = t0 + (t1 - t0) * 2 / 3
    return {"days": days, "dev_days": days[:k], "test_days": days[k:], "dev": dev, "test": test,
            "sel_fit": [r for r in dev if r[0] < cut], "sel": [r for r in dev if r[0] >= cut]}


def split(cand: str, train: list) -> tuple[list, list, list]:
    pairs = [(t, v) for _, t, v in train]
    if cand == "C0-random":
        pairs = list(pairs)
        random.Random(SEED).shuffle(pairs)
    a, b = int(0.40 * len(pairs)), int(0.75 * len(pairs))
    return pairs[:a], pairs[a:b], pairs[b:]


def fit(cand: str, train: list) -> dict:
    from sklearn.ensemble import IsolationForest
    fit_rows, cal_rows, thr_rows = split(cand, train)
    state = {"profiles": m.s25.profiles(fit_rows), "counts": dict(Counter(t for t, _ in fit_rows))}
    model = IsolationForest(n_estimators=300, random_state=SEED).fit(
        np.asarray([m.vector(t, v, state["counts"]) for t, v in fit_rows]))
    cal, thr = m.evidence(cal_rows, state, model), m.evidence(thr_rows, state, model)
    seen_c = np.array([t in state["profiles"] for t, _ in cal_rows])
    seen_t = np.array([t in state["profiles"] for t, _ in thr_rows])
    refs = {"all": (cal, m.v3.v1.normal_threshold(m.v3.fused(thr, cal, range(2)), BUDGET))}
    fallback = []
    if cand == "C2-temporal-strata":
        for name, sc, st in (("seen", seen_c, seen_t), ("unseen", ~seen_c, ~seen_t)):
            if sc.sum() >= MIN_REF and st.sum() >= MIN_REF:
                refs[name] = (cal[sc], m.v3.v1.normal_threshold(m.v3.fused(thr[st], cal[sc], range(2)), BUDGET))
            else:
                fallback.append(name)
    return {"cand": cand, "state": state, "model": model, "refs": refs, "fallback": fallback,
            "rows": {"fit": len(fit_rows), "calibration": len(cal_rows), "threshold": len(thr_rows)},
            "cal_unseen_share": float((~seen_c).mean()) if len(seen_c) else None}


def score(f: dict, data: list) -> dict:
    samples = [(t, v) for _, t, v in data]
    raw = m.evidence(samples, f["state"], f["model"])
    seen = np.array([t in f["state"]["profiles"] for t, _ in samples])
    alert = np.zeros(len(samples), dtype=bool)
    for name, mask in (("seen", seen), ("unseen", ~seen)):
        cal, thr = f["refs"].get(name, f["refs"]["all"])
        if mask.any():
            alert[mask] = m.v3.fused(raw[mask], cal, range(2)) > thr
    abstain = ~seen if f["cand"] == "C3-temporal-abstain" else np.zeros(len(samples), dtype=bool)
    alert &= ~abstain
    days = len({r[0].strftime("%Y-%m-%d") for r in data})
    out = {"requests": len(samples), "abstain_share": float(abstain.mean()), "unseen_share": float((~seen).mean()),
           "alert_rate": float(alert.mean()), "alerts_per_day": float(alert.sum() / max(days, 1)), "strata": {}}
    for name, mask in (("seen", seen), ("unseen", ~seen)):
        n = int(mask.sum())
        out["strata"][name] = {"requests": n, "alerts": int(alert[mask].sum()),
                               "rate": float(alert[mask].mean()) if n else None,
                               "scored": not (name == "unseen" and f["cand"] == "C3-temporal-abstain")}
    out["_alert"] = alert
    return out


def selection_score(cand: str, r: dict) -> float | None:
    if cand == "C3-temporal-abstain" and r["abstain_share"] > MAX_ABSTAIN:
        return None
    devs = [abs(s["rate"] - BUDGET) for s in r["strata"].values() if s["scored"] and s["requests"] >= MIN_STRATUM]
    return max(devs) if devs else None


def choose(results: dict) -> str:
    scored = [(results[c]["selection_score"], results[c]["abstain_share"], i, c) for i, c in enumerate(CANDIDATES)
              if results[c]["selection_score"] is not None]
    if not scored:
        raise SystemExit("no eligible candidate")
    best = min(s for s, *_ in scored)
    tied = [x for x in scored if x[0] <= best + TIE]
    return min(tied, key=lambda x: (x[1], x[2]))[3]


def clean(r: dict) -> dict:
    return {k: v for k, v in r.items() if not k.startswith("_")}


def select(log: Path, out_dir: Path, pinned: bool = True) -> None:
    if (out_dir / "freeze.json").exists():
        raise SystemExit("a freeze already exists")
    md5 = check_source(log, pinned)
    p = periods(rows(log))
    results = {}
    for c in CANDIDATES:
        f = fit(c, p["sel_fit"])
        r = score(f, p["sel"])
        r["selection_score"] = selection_score(c, r)
        r["fallback"], r["cal_unseen_share"] = f["fallback"], f["cal_unseen_share"]
        results[c] = clean(r)
        print("SELECT", c, json.dumps({k: results[c][k] for k in ("selection_score", "abstain_share")}),
              json.dumps(results[c]["strata"]), flush=True)
    winner = choose(results)
    freeze = {"schema": "predict-shield/zanbil-calibration-freeze/1", "source_sha256": md5, "code_sha256": code_hashes(),
              "days": p["days"], "dev_days": p["dev_days"], "test_days": p["test_days"],
              "counts": {k: len(p[k]) for k in ("dev", "test", "sel_fit", "sel")},
              "selection": results, "winner": winner}
    freeze["freeze_sha256"] = sha(json.dumps(freeze, sort_keys=True).encode())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("WINNER", winner, "FROZEN", freeze["freeze_sha256"], flush=True)


def test(log: Path, frozen: Path, expected: str, output: Path, pinned: bool = True) -> None:
    if output.exists():
        raise SystemExit("a test report already exists; the test runs once")
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    if check_source(log, pinned) != freeze["source_sha256"]:
        raise SystemExit("log differs from the one used at selection")
    p = periods(rows(log))
    if p["test_days"] != freeze["test_days"]:
        raise SystemExit("periods differ from the freeze")
    lib = None
    try:
        import libinjection
        lib = np.array([any(bool(libinjection.is_sql_injection(x)["is_sqli"]) or bool(libinjection.is_xss(x)["is_xss"])
                            for x in v.split(" ") if x) for _, _, v in p["test"]])
    except ImportError:
        pass
    results = {}
    for c in CANDIDATES:
        r = score(fit(c, p["dev"]), p["test"])
        a = r.pop("_alert")
        if lib is not None:
            r["libinjection_flagged"] = int(lib.sum())
            r["alerts_libinjection_flagged"] = int((a & lib).sum())
            r["agreement"] = float(a[lib].mean()) if lib.any() else None
        results[c] = r
        print("TEST", c, json.dumps({"alert_rate": r["alert_rate"], "strata": r["strata"]}), flush=True)
    w = freeze["winner"]
    big = [s for s in results[w]["strata"].values() if s["scored"] and s["requests"] >= MIN_STRATUM]
    passed = bool(big) and all(LO <= s["rate"] <= HI for s in big) and (
        w != "C3-temporal-abstain" or results[w]["abstain_share"] <= MAX_ABSTAIN)
    report = {"schema": "predict-shield/zanbil-calibration-test/1", "freeze_sha256": rec, "winner": w,
              "results": results, "passed": passed,
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"]}
    output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("WINNER", w, "PASSED", passed)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("select", "test"))
    ap.add_argument("--log", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "select":
        select(a.log, a.out_dir)
    else:
        test(a.log, a.frozen_dir, a.expected_freeze_sha256, a.output)


if __name__ == "__main__":
    main()
