"""Baselines on the Superviz25-SQL test split. See protocol_baselines.json.

  python baselines.py sample  --data dataset.csv --out sample.npz
  python baselines.py ours    --data dataset.csv --frozen-dir frozen --expected-freeze-sha256 H --out ours.npz
  python baselines.py libinj  --data dataset.csv --out libinj.npz
  python baselines.py supervised --data dataset.csv --sample sample.npz --out sup.npz
  python baselines.py crs     --data dataset.csv --sample sample.npz --url http://127.0.0.1:8080/ --level N --out crsN.npz
  python baselines.py report  --data dataset.csv --sample sample.npz --inputs ours.npz libinj.npz sup.npz crs1.npz ... --output r.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import random
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_sql as ms  # noqa: E402

SAMPLE_SEED = 2026112901
BENIGN_SHARE, ATTACK_SHARE = 0.10, 0.25
RATES = (0.001, 0.005, 0.01)
# Sent with every CRS request, so CRS judges the input and not the HTTP client.
BROWSER_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "identity", "Connection": "keep-alive"}
PROBES = ("Vieques Airport", "MX 950.0", "Fort Cavazos", "GB 2")


def test_rows(data: Path):
    """(template, input, label, technique, stage, attack_id) for every test row, in file order."""
    out = []
    with open(data, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            if r["split"] == "test":
                out.append((r["query_template_id"], r["user_inputs"], int(r["label"]), r["attack_technique"],
                            r["attack_stage"], r["attack_id"]))
    return out


def cmd_sample(a):
    rows = test_rows(a.data)
    rng = random.Random(SAMPLE_SEED)
    keep = np.array([rng.random() < (ATTACK_SHARE if r[2] else BENIGN_SHARE) for r in rows])
    np.savez_compressed(a.out, keep=keep)
    print("sample:", int(keep.sum()), "rows;", int(sum(1 for r, k in zip(rows, keep) if k and r[2])), "attacks")


def cmd_ours(a):
    ms.check_source(a.data)
    freeze, bundle = ms.verify(a.frozen_dir, a.expected_freeze_sha256)
    rows = test_rows(a.data)
    raw = ms.evidence([(r[0], r[1]) for r in rows], bundle["state"], bundle["model"])
    cal = np.asarray(bundle["state"]["calibration"])
    np.savez_compressed(a.out, score=ms.v3.fused(raw, cal, range(2)), threshold=bundle["state"]["thresholds"]["fused"])


def cmd_libinj(a):
    import libinjection
    rows = test_rows(a.data)
    np.savez_compressed(a.out, alert=np.array([bool(libinjection.is_sql_injection(r[1])["is_sqli"]) for r in rows]))


def cmd_supervised(a):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    rows = test_rows(a.data)
    keep = np.load(a.sample)["keep"]
    idx = np.flatnonzero(keep)
    rng = random.Random(SAMPLE_SEED + 1)
    groups = []
    for i in idx:
        r = rows[i]
        groups.append(("a:" + r[5]) if r[2] else ("b:%d" % rng.randrange(1000)))
    uniq = sorted(set(groups))
    random.Random(SAMPLE_SEED + 2).shuffle(uniq)
    fold_of = {g: k % 5 for k, g in enumerate(uniq)}
    folds = np.array([fold_of[g] for g in groups])
    text = [rows[i][1] for i in idx]
    y = np.array([rows[i][2] for i in idx])
    score = np.empty(len(idx))
    for k in range(5):
        tr, te = folds != k, folds == k
        vec = TfidfVectorizer(analyzer="char", ngram_range=(1, 4), max_features=200_000, sublinear_tf=True)
        xtr = vec.fit_transform([t for t, m in zip(text, tr) if m])
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000).fit(xtr, y[tr])
        score[te] = clf.decision_function(vec.transform([t for t, m in zip(text, te) if m]))
        print("fold", k, "done", flush=True)
    full = np.full(len(rows), np.nan)
    full[idx] = score
    np.savez_compressed(a.out, score=full)


def cmd_crs(a):
    rows = test_rows(a.data)
    keep = np.load(a.sample)["keep"]
    idx = np.flatnonzero(keep)
    opener = urllib.request.build_opener()

    def get(q):
        req = urllib.request.Request(f"{a.url}?q={q}", headers=BROWSER_HEADERS)
        return opener.open(req, timeout=30)

    # Harness check: benign training-style inputs must pass at every level, or the client
    # (not the input) is what CRS is reacting to.
    for probe in PROBES:
        try:
            with get(urllib.parse.quote(probe, safe="")) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        if code != 200:
            raise SystemExit(f"harness check failed at level {a.level}: benign probe {probe!r} returned {code}")

    def send(i):
        q = urllib.parse.quote(rows[i][1], safe="")
        for attempt in range(3):
            try:
                with get(q) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code
            except OSError:
                if attempt == 2:
                    raise
        return 0

    status = np.zeros(len(rows), dtype=np.int16)
    with cf.ThreadPoolExecutor(64) as ex:
        for n, (i, s) in enumerate(zip(idx, ex.map(send, idx, chunksize=256))):
            status[i] = s
            if n % 50_000 == 0:
                print("  sent", n, flush=True)
    codes = dict(zip(*np.unique(status[idx], return_counts=True)))
    print("level", a.level, "status codes", {int(k): int(v) for k, v in codes.items()})
    alert = np.full(len(rows), -1, dtype=np.int8)
    alert[idx] = (status[idx] == 403).astype(np.int8)
    np.savez_compressed(a.out, alert=alert, status=status)


def wilson(k, n):
    return ms.v3.v1.wilson(int(k), int(n))


def cmd_report(a):
    from sklearn.metrics import roc_auc_score
    rows = test_rows(a.data)
    keep = np.load(a.sample)["keep"]
    y = np.array([r[2] for r in rows], dtype=bool)
    tech = np.array([r[3] for r in rows])
    stage = np.array([r[4] for r in rows])
    out = {"schema": "predict-shield/superviz25-baselines/1", "sample": {"benign": int((keep & ~y).sum()),
           "attacks": int((keep & y).sum())}, "detectors": {}}

    def breakdown(alert, mask):
        res = {}
        for name, col in (("technique", tech), ("stage", stage)):
            res["by_" + name] = {v: float(alert[mask & y & (col == v)].mean()) for v in sorted(set(col[mask & y]))}
        return res

    for path in a.inputs:
        d = np.load(path)
        name = Path(path).stem
        if "score" in d:
            s = d["score"]
            for scope, mask in (("sample", keep), ("full", np.isfinite(s))):
                if scope == "full" and not np.isfinite(s).all():
                    continue
                ben = np.sort(s[mask & ~y])
                ent = {"roc_auc": float(roc_auc_score(y[mask], s[mask])), "at_benign_rate": {}}
                for r in RATES:
                    thr = ben[len(ben) - 1 - int(np.floor(r * len(ben)))]
                    al = s > thr
                    k, n = int((al & mask & y).sum()), int((mask & y).sum())
                    ent["at_benign_rate"][str(r)] = {"detection": k / n, "wilson_95": wilson(k, n),
                                                    "benign_alert_rate": float(al[mask & ~y].mean())}
                    if r == 0.005:
                        ent.update(breakdown(al, mask))
                if "threshold" in d:
                    al = s > float(d["threshold"])
                    ent["at_frozen_threshold"] = {"detection": float(al[mask & y].mean()),
                                                  "benign_alert_rate": float(al[mask & ~y].mean())}
                out["detectors"].setdefault(name, {})[scope] = ent
        else:
            al = d["alert"]
            for scope in ("sample", "full"):
                mask = keep if scope == "sample" else (al >= 0)
                if scope == "full" and not (al >= 0).all():
                    continue
                alb = al == 1
                k, n = int((alb & mask & y).sum()), int((mask & y).sum())
                ent = {"detection": k / n, "wilson_95": wilson(k, n),
                       "benign_alert_rate": float(alb[mask & ~y].mean()),
                       "benign_alerts": int((alb & mask & ~y).sum()), **breakdown(alb, mask)}
                out["detectors"].setdefault(name, {})[scope] = ent
    a.output.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for name, v in out["detectors"].items():
        s = v["sample"]
        if "roc_auc" in s:
            print(name, "AUC %.4f" % s["roc_auc"], {k: round(x["detection"], 4) for k, x in s["at_benign_rate"].items()})
        else:
            print(name, "detection %.4f benign %.5f" % (s["detection"], s["benign_alert_rate"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("sample", "ours", "libinj", "supervised", "crs", "report"))
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--sample", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--url")
    ap.add_argument("--level")
    ap.add_argument("--inputs", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    globals()["cmd_" + a.cmd](a)


if __name__ == "__main__":
    main()
