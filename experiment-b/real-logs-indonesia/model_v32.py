"""v3 and v3.2 arms on real web logs. See protocol_v32.json.

  python model_v32.py develop --zips X.zip Y.zip --out-dir frozen-v32 --models-dir M
  python model_v32.py test --zips X.zip Y.zip --frozen-dir frozen-v32 --models-dir M --expected-freeze-sha256 H --work W
  then model_logs.py libinj/crs on W, and: python model_v32.py report --work W --frozen-dir frozen-v32 --output ...
"""
from __future__ import annotations

import argparse
import json
import pickle
import random
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_logs as m  # noqa: E402

WIB = m.WIB
FAR_PAST, FAR_FUTURE = datetime(2000, 1, 1, tzinfo=WIB), datetime(2100, 1, 1, tzinfo=WIB)
WINDOWS = {
    "early": {"organization-x": (datetime(2025, 9, 23, tzinfo=WIB), datetime(2025, 9, 28, tzinfo=WIB), datetime(2025, 10, 1, tzinfo=WIB)),
              "organization-y": (FAR_PAST, datetime(2025, 4, 15, tzinfo=WIB), datetime(2025, 4, 22, tzinfo=WIB))},
    "original": {o: (FAR_PAST, s, FAR_FUTURE) for o, s in m.SPLIT.items()},
}
ARMS = {"v3-early": ("v3", "early"), "v32-early": ("v32", "early"), "v32-original": ("v32", "original")}
CODE = {"model_v32.py": HERE, "protocol_v32.json": HERE, **m.CODE}


def code_hashes() -> dict:
    return {n: m.sha256((d / n).read_bytes()) for n, d in CODE.items()}


def pooled(profiles: dict) -> dict:
    out: dict = {}
    for tpl, p in profiles.items():
        site, method, _ = tpl.split("|", 2)
        q = out.setdefault(f"{site}|{method}", {"chars": set(), "min": p["min"], "max": p["max"]})
        q["chars"] |= set(p["chars"])
        q["min"], q["max"] = min(q["min"], p["min"]), max(q["max"], p["max"])
    return {k: {"chars": sorted(v["chars"]), "min": v["min"], "max": v["max"]} for k, v in out.items()}


def novelty(version: str, tpl: str, val: str, state: dict) -> float:
    if version == "v32" and tpl not in state["profiles"]:
        site, method, _ = tpl.split("|", 2)
        return m.s25.input_novelty(f"{site}|{method}", val, state["pooled"])
    return m.s25.input_novelty(tpl, val, state["profiles"])


def evidence(version: str, samples, state, model) -> np.ndarray:
    nov = np.array([novelty(version, t, v, state) for t, v in samples])
    out = np.empty(len(samples))
    for i in range(0, len(samples), 200_000):
        out[i:i + 200_000] = -model.score_samples(
            np.asarray([m.vector(t, v, state["counts"]) for t, v in samples[i:i + 200_000]]))
    return np.column_stack([nov, out])


def fit(version: str, train: list):
    from sklearn.ensemble import IsolationForest
    train = list(train)
    random.Random(m.SEED).shuffle(train)
    a, b = int(m.FIT * len(train)), int((m.FIT + m.CAL) * len(train))
    state = {"profiles": m.s25.profiles(train[:a]), "counts": dict(Counter(t for t, _ in train[:a]))}
    state["pooled"] = pooled(state["profiles"])
    model = IsolationForest(n_estimators=300, random_state=m.SEED).fit(
        np.asarray([m.vector(t, v, state["counts"]) for t, v in train[:a]]))
    raw = evidence(version, train[a:], state, model)
    cal, thr = raw[: b - a], raw[b - a:]
    state["calibration"] = cal.tolist()
    state["thresholds"] = {"fused": m.v3.v1.normal_threshold(m.v3.fused(thr, cal, range(2)), m.BUDGET),
                           "input_novelty": m.v3.v1.normal_threshold(thr[:, 0], m.BUDGET),
                           "learned_anomaly": m.v3.v1.normal_threshold(thr[:, 1], m.BUDGET)}
    return state, model, {"train": len(train), "templates": len(state["counts"])}


def load_all(zips):
    data = {}
    for zp in zips:
        org = m.check_zip(zp)
        data[org] = list(m.requests(zp))
    return data


def develop(zips, out_dir: Path, models_dir: Path) -> None:
    if (out_dir / "freeze.json").exists():
        raise SystemExit("a freeze already exists")
    models_dir.mkdir(parents=True, exist_ok=True)
    data = load_all(zips)
    freeze = {"schema": "predict-shield/real-logs-v32-freeze/1", "code_sha256": code_hashes(), "arms": {}}
    for arm, (version, win) in ARMS.items():
        for org, rows in data.items():
            lo, split, _ = WINDOWS[win][org]
            train = [(m.template(s, mm, p), v) for s, t, mm, p, v, *_ in rows if lo <= t < split]
            state, model, info = fit(version, train)
            blob = pickle.dumps({"state": state, "model": model}, protocol=5)
            (models_dir / f"{arm}.{org}.pkl").write_bytes(blob)
            freeze["arms"][f"{arm}.{org}"] = {"model_sha256": m.sha256(blob), "thresholds": state["thresholds"], **info}
            print("FIT", arm, org, json.dumps(info), flush=True)
    freeze["freeze_sha256"] = m.sha256(json.dumps(freeze, sort_keys=True).encode())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], flush=True)


def test(zips, frozen: Path, models_dir: Path, expected: str, work: Path) -> None:
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or m.sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    if (frozen / "test-report.json").exists():
        raise SystemExit("a test report already exists; the test runs once")
    work.mkdir(parents=True, exist_ok=True)
    data = load_all(zips)
    for win in WINDOWS:
        for org, rows in data.items():
            _, split, hi = WINDOWS[win][org]
            sel = [r for r in rows if split <= r[1] < hi]
            key = f"{win}-{org}"
            (work / f"{key}.targets.json").write_text(json.dumps([r[5] for r in sel]))
            (work / f"{key}.inputs.json").write_text(json.dumps([r[4] for r in sel]))
            samples = [(m.template(s, mm, p), v) for s, t, mm, p, v, *_ in sel]
            out = {"day": np.array([r[1].astimezone(WIB).strftime("%Y-%m-%d") for r in sel])}
            for arm, (version, w) in ARMS.items():
                if w != win:
                    continue
                blob = (models_dir / f"{arm}.{org}.pkl").read_bytes()
                if m.sha256(blob) != freeze["arms"][f"{arm}.{org}"]["model_sha256"]:
                    raise SystemExit(f"model {arm}.{org} does not match the freeze")
                b = pickle.loads(blob)
                raw = evidence(version, samples, b["state"], b["model"])
                cal, thr = np.asarray(b["state"]["calibration"]), b["state"]["thresholds"]
                out[f"{arm}.fused"] = m.v3.fused(raw, cal, range(2)) > thr["fused"]
                out[f"{arm}.seen"] = np.array([t in b["state"]["profiles"] for t, _ in samples])
            np.savez_compressed(work / f"{key}.npz", **out)
            print("TESTED", key, len(sel), flush=True)


def report(work: Path, frozen: Path, output: Path) -> None:
    if output.exists():
        raise SystemExit("a test report already exists")
    freeze = json.loads((frozen / "freeze.json").read_text())
    out = {"schema": "predict-shield/real-logs-v32-test/1", "freeze_sha256": freeze["freeze_sha256"], "results": {}}
    for f in sorted(work.glob("*.npz")):
        if "." in f.stem:
            continue
        key = f.stem
        d = np.load(f)
        indep = (np.load(work / f"{key}.libinj.npz")["flag"] | (np.load(work / f"{key}.crs1.npz")["status"] == 403)
                 | (np.load(work / f"{key}.crs2.npz")["status"] == 403))
        days = len(set(d["day"].tolist()))
        for arm in sorted({k.split(".")[0] for k in d.files if "." in k}):
            a, seen = d[f"{arm}.fused"], d[f"{arm}.seen"]
            org = key.split("-", 1)[1]
            r = {"test_requests": len(a), "days": days, "independent_evidence": int(indep.sum()),
                 "alerts": int(a.sum()), "alert_rate": float(a.mean()) if len(a) else None,
                 "alerts_per_day": float(a.sum() / days) if days else None,
                 "unconfirmed_alerts": int((a & ~indep).sum()),
                 "unconfirmed_alert_rate": float((a & ~indep).mean()) if len(a) else None,
                 "unseen_template_share": float((~seen).mean()) if len(a) else None,
                 "alert_rate_seen": float(a[seen].mean()) if seen.any() else None,
                 "alert_rate_unseen": float(a[~seen].mean()) if (~seen).any() else None,
                 "detection_proxy": float(a[indep].mean()) if indep.any() else None}
            r["passed"] = r["unconfirmed_alert_rate"] is not None and r["unconfirmed_alert_rate"] <= m.CEILING
            out["results"][f"{arm}.{org}"] = r
            print(arm, org, json.dumps({k: r[k] for k in ("test_requests", "alert_rate", "unconfirmed_alert_rate",
                                                          "detection_proxy", "passed")}), flush=True)
    out["primary_orgs_passed"] = sum(out["results"][f"v32-early.{o}"]["passed"] for o in m.SPLIT)
    out["pass_condition"] = json.loads((HERE / "protocol_v32.json").read_text())["pass_condition"]
    output.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test", "report"))
    ap.add_argument("--zips", type=Path, nargs="+")
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--models-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--work", type=Path)
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.zips, a.out_dir, a.models_dir)
    elif a.stage == "test":
        test(a.zips, a.frozen_dir, a.models_dir, a.expected_freeze_sha256, a.work)
    else:
        report(a.work, a.frozen_dir, a.output)


if __name__ == "__main__":
    main()
