"""The DVWA v3 detector method on OWASP Juice Shop. See protocol.json.

  python model_js.py develop --log proxy.jsonl --trace trace.txt --docroot DIR --out-dir frozen
  python model_js.py test --log proxy.jsonl --trace trace.txt --docroot DIR --alerts alerts.json \
      --scanners scanners.json --sqlmap-log sqlmap.txt --frozen-dir frozen --expected-freeze-sha256 H --output r.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import re
import sys
import urllib.parse
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
V1 = HERE.parent / "dvwa-correlation"
V3 = HERE.parent / "dvwa-correlation-v3"
sys.path.insert(0, str(V1))
sys.path.insert(0, str(V3))
import lab  # noqa: E402
import model_v3 as v3  # noqa: E402

SEED = 2026112901
FIT, CAL = 0.40, 0.35
BUDGET, CEILING, DETECT, MIN_CONFIRMED = 0.005, 0.01, 0.90, 30
CODE = {"model_js.py": HERE, "serial_proxy.py": HERE, "benign.py": HERE, "protocol.json": HERE,
        "model_v3.py": V3, "lab.py": V1, "detector.py": V1}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha256((d / n).read_bytes()) for n, d in CODE.items()}


# ------------------------------------------------------------------ records to request rows

SEG_NUM = re.compile(r"^\d+$")
SEG_ID = re.compile(r"^(?=.*\d)[0-9a-fA-F-]{8,}$")


def norm_path(path: str) -> str:
    segs = urllib.parse.urlsplit(path).path.split("/")
    return "/".join("N" if SEG_NUM.match(s) else "X" if SEG_ID.match(s) else s for s in segs)


def flatten(obj, prefix="") -> dict:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for v in obj:
            out.update(flatten(v, prefix + "[]"))
    else:
        out[prefix or "_value"] = "" if obj is None else str(obj)
    return out


def fields(rec: dict) -> dict:
    out = {k: v for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(rec["path"]).query, keep_blank_values=True)}
    body = rec.get("body") or ""
    if body:
        try:
            out.update({"body." + k: v for k, v in flatten(json.loads(body)).items()})
        except ValueError:
            if "x-www-form-urlencoded" in rec.get("content_type", ""):
                out.update({"form." + k: v for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)})
            else:
                out["_body"] = body
    return out


def load(log: Path, trace: Path):
    recs = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    recs.sort(key=lambda r: r["t_send"])
    ex = [lab.Exchange("x", r["source"], r["method"], norm_path(r["path"]), fields(r), r["t_send"], r["t_recv"],
                       r["status"], r["response"]) for r in recs]
    per = lab.attribute(ex, lab.parse_strace(trace.read_text(errors="replace")))
    return recs, ex, per


# ------------------------------------------------------------------ stages

def develop(a) -> None:
    recs, ex, per = load(a.log, a.trace)
    keep = [i for i, r in enumerate(recs) if r["source"] == "benign"]
    ex, per = [ex[i] for i in keep], [per[i] for i in keep]
    docroot = str(a.docroot)
    n1, n2 = int(FIT * len(ex)), int((FIT + CAL) * len(ex))
    state = {"vocab": lab.build_vocab(ex[:n1], per[:n1], docroot).to_json(),
             "request_profiles": v3.request_profiles(ex[:n1]), "response_profiles": v3.response_profiles(ex[:n1])}
    vocab = lab.Vocab.from_json(state["vocab"])
    from sklearn.ensemble import IsolationForest
    corr = np.asarray([lab.features(e, c, vocab, docroot)["correlated"] for e, c in zip(ex[:n1], per[:n1])])
    model = IsolationForest(n_estimators=300, random_state=SEED).fit(corr)
    raw = v3.evidence(ex, per, docroot, state, model)
    cal, thr = raw[n1:n2], raw[n2:]
    state["calibration"] = cal.tolist()
    th = {"fused": v3.v1.normal_threshold(v3.fused(thr, cal), BUDGET),
          "fused_without_learned_anomaly": v3.v1.normal_threshold(v3.fused(thr, cal, range(3)), BUDGET)}
    for j, name in enumerate(v3.COMPONENTS):
        th[name] = v3.v1.normal_threshold(thr[:, j], BUDGET)
    state["thresholds"] = th
    blob = pickle.dumps({"state": state, "model": model}, protocol=5)
    a.out_dir.mkdir(parents=True, exist_ok=True)
    (a.out_dir / "model.pkl").write_bytes(blob)
    freeze = {"schema": "predict-shield/juiceshop-v3-freeze/1", "model_sha256": sha256(blob), "code_sha256": code_hashes(),
              "thresholds": th, "rows": {"fit": n1, "calibration": n2 - n1, "threshold": len(ex) - n2},
              "threshold_split_alert_rate": float((v3.fused(thr, cal) > th["fused"]).mean()),
              "sklearn": __import__("sklearn").__version__}
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    (a.out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], json.dumps(freeze["rows"]), flush=True)


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


def family(name: str) -> str:
    n = name.lower()
    if "sql injection" in n:
        return "sqli (seen in DVWA)"
    if "command injection" in n or "remote os" in n:
        return "cmdi (seen in DVWA)"
    if "path traversal" in n or "file inclusion" in n:
        return "lfi (seen in DVWA)"
    return "unseen: " + name


def label(recs, scanners: dict) -> list[str]:
    out = []
    for r in recs:
        if r["source"] == "benign":
            out.append("benign")
        elif r["plugin"]:
            out.append("zap:" + r["plugin"].split()[0])
        elif "sqlmap" in r.get("user_agent", "").lower():
            out.append("sqlmap")
        else:
            out.append("unknown")   # crawl and anything unlabelled: excluded, never counted as benign
    return out


def confirmed(recs, labels, alerts) -> np.ndarray:
    """Requests that a ZAP alert of Medium or High risk names as its evidence."""
    conf = np.zeros(len(recs), dtype=bool)
    by_plugin = defaultdict(list)
    for i, l in enumerate(labels):
        if l.startswith("zap:"):
            by_plugin[l[4:]].append(i)
    for al in alerts:
        if al.get("risk") not in ("High", "Medium") or not al.get("attack"):
            continue
        attack = al["attack"]
        want = urllib.parse.urlsplit(al.get("url", "")).path
        for i in by_plugin.get(str(al.get("pluginId")), []):
            r = recs[i]
            text = urllib.parse.unquote_plus(r["path"]) + "\n" + (r.get("body") or "")
            if attack in text and urllib.parse.urlsplit(r["path"]).path == want:
                conf[i] = True
    return conf


def test(a) -> None:
    if a.output.exists():
        raise SystemExit("a test report already exists; the test runs once")
    freeze, bundle = verify(a.frozen_dir, a.expected_freeze_sha256)
    recs, ex, per = load(a.log, a.trace)
    scanners = {str(s["id"]): s["name"] for s in json.loads(a.scanners.read_text()).get("scanners", [])}
    alerts = json.loads(a.alerts.read_text()).get("alerts", [])
    labels = label(recs, scanners)
    if not any(l.startswith("zap:") for l in labels):
        raise SystemExit("harness check failed: no request carried a ZAP plugin id")
    raw = v3.evidence(ex, per, str(a.docroot), bundle["state"], bundle["model"])
    cal, th = np.asarray(bundle["state"]["calibration"]), bundle["state"]["thresholds"]
    alerts_by = {"fused": v3.fused(raw, cal) > th["fused"],
                 "fused_without_learned_anomaly": v3.fused(raw, cal, range(3)) > th["fused_without_learned_anomaly"]}
    for j, name in enumerate(v3.COMPONENTS):
        alerts_by[name] = raw[:, j] > th[name]
    lab_arr = np.array(labels)
    benign = lab_arr == "benign"
    attack = np.array([l.startswith("zap:") or l == "sqlmap" for l in labels])
    conf = confirmed(recs, labels, alerts)
    fam = np.array([("sqli (seen in DVWA)" if l == "sqlmap" else family(scanners.get(l[4:], "plugin " + l[4:])))
                    if (l.startswith("zap:") or l == "sqlmap") else "" for l in labels])
    sqlmap_text = a.sqlmap_log.read_text(errors="replace") if a.sqlmap_log and a.sqlmap_log.exists() else ""

    def rate(al, mask):
        k, n = int((al & mask).sum()), int(mask.sum())
        return {"alerts": k, "of": n, "rate": k / n if n else None, "wilson_95": v3.v1.wilson(k, n)}

    results = {}
    for name, al in alerts_by.items():
        res = {"benign": rate(al, benign), "attack_attempts": rate(al, attack), "confirmed_attacks": rate(al, conf),
               "attempts_by_family": {f: rate(al, attack & (fam == f)) for f in sorted(set(fam[attack]))},
               "confirmed_by_family": {f: rate(al, conf & (fam == f)) for f in sorted(set(fam[conf]))}}
        results[name] = res
    f = results["fused"]
    n_conf = int(conf.sum())
    checks = {"benign_alert_rate_at_most_1pct": f["benign"]["rate"] is not None and f["benign"]["rate"] <= CEILING,
              "confirmed_attacks_at_least_90pct": (f["confirmed_attacks"]["rate"] or 0) >= DETECT,
              "enough_confirmed_attacks": n_conf >= MIN_CONFIRMED}
    outcome = "inconclusive" if not checks["enough_confirmed_attacks"] else (
        "passed" if checks["benign_alert_rate_at_most_1pct"] and checks["confirmed_attacks_at_least_90pct"] else "failed")
    report = {"schema": "predict-shield/juiceshop-v3-test/1", "freeze_sha256": freeze["freeze_sha256"],
              "requests": len(recs), "label_counts": {k: int((lab_arr == k).sum()) for k in ("benign", "unknown", "sqlmap")},
              "zap_requests": int(sum(1 for l in labels if l.startswith("zap:"))), "confirmed": n_conf,
              "zap_alerts_medium_high": sum(1 for x in alerts if x.get("risk") in ("High", "Medium")),
              "sqlmap_reported_injectable": bool(re.search(r"is vulnerable|identified the following injection point", sqlmap_text)),
              "results": results, "checks": checks, "outcome": outcome,
              "pass_condition": json.loads((HERE / "protocol.json").read_text())["pass_condition"]}
    a.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    for name, r in results.items():
        print(name, "benign", r["benign"]["alerts"], "/", r["benign"]["of"], "attempts", r["attack_attempts"]["alerts"],
              "/", r["attack_attempts"]["of"], "confirmed", r["confirmed_attacks"]["alerts"], "/", r["confirmed_attacks"]["of"])
    print(json.dumps(checks), outcome.upper())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test"))
    ap.add_argument("--log", type=Path, required=True)
    ap.add_argument("--trace", type=Path, required=True)
    ap.add_argument("--docroot", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--alerts", type=Path)
    ap.add_argument("--scanners", type=Path)
    ap.add_argument("--sqlmap-log", type=Path)
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    develop(a) if a.stage == "develop" else test(a)


if __name__ == "__main__":
    main()
