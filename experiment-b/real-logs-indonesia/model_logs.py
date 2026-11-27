"""Benign-only detector on real web logs. See protocol.json.

  python model_logs.py develop --zips X.zip Y.zip --out-dir frozen --models-dir M
  python model_logs.py test --zips X.zip Y.zip --frozen-dir frozen --models-dir M --expected-freeze-sha256 H --work W
  python model_logs.py libinj --work W
  python model_logs.py crs --work W --level L --url http://127.0.0.1:8080
  python model_logs.py report --work W --frozen-dir frozen --output frozen/test-report.json --review W/review
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import math
import pickle
import random
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
S25 = HERE.parent / "superviz25-sql"
V3 = HERE.parent / "dvwa-correlation-v3"
sys.path.insert(0, str(S25))
sys.path.insert(0, str(V3))
import model_sql as s25  # noqa: E402
import model_v3 as v3  # noqa: E402

SEED, FIT, CAL, BUDGET = s25.SEED, s25.FIT, s25.CAL, s25.BUDGET
WIB = timezone(timedelta(hours=7))
SPLIT = {"organization-x": datetime(2025, 10, 1, tzinfo=WIB), "organization-y": datetime(2025, 4, 22, tzinfo=WIB)}
CEILING = 0.01
REVIEW_SEED, REVIEW_N = 2026112702, 200
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]{3,8}) (\S+)(?: HTTP/[\d.]+)?" (\d{3}) \S+(?: "([^"]*)" "([^"]*)")?')
DIGITS = re.compile(r"\d+")
CODE = {"model_logs.py": HERE, "protocol.json": HERE, "model_sql.py": S25, "model_v3.py": V3}
BROWSER_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "identity", "Connection": "keep-alive"}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def code_hashes() -> dict:
    return {n: sha256((d / n).read_bytes()) for n, d in CODE.items()}


def check_zip(path: Path) -> str:
    org = path.stem
    want = json.loads((HERE / "protocol.json").read_text())["source"][path.name]["sha256"]
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    if h != want:
        raise SystemExit(f"{path.name} does not match its pin")
    return org


def in_scope(name: str) -> str | None:
    """Site name for an in-scope access log member, else None."""
    parts = name.split("/")
    if parts[0] == "organization-x" and "/web-access.log" in name:
        return "x"
    if parts[0] == "organization-y" and len(parts) > 4 and parts[2] == "home" and ".access_log" in parts[-1]:
        return parts[3]
    return None


def parse(target: str) -> tuple[str, str] | None:
    if "?" not in target:
        return None
    path, _, query = target.partition("?")
    vals = [v for _, v in urllib.parse.parse_qsl(query, keep_blank_values=True, errors="replace")]
    return DIGITS.sub("9", path), " ".join(vals)


def requests(zpath: Path):
    """Yield (site, time, method, template_path, inputs, target, client, agent) for in-scope requests."""
    with zipfile.ZipFile(zpath) as z:
        for info in sorted(z.infolist(), key=lambda i: i.filename):
            site = in_scope(info.filename)
            if site is None or info.is_dir():
                continue
            data = z.read(info)
            if info.filename.endswith(".gz"):
                data = gzip.decompress(data)
            for line in data.decode("utf-8", "replace").splitlines():
                m = LINE.match(line)
                if not m:
                    continue
                p = parse(m.group(4))
                if p is None:
                    continue
                try:
                    t = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z")
                except ValueError:
                    continue
                yield site, t, m.group(3), p[0], p[1], m.group(4), m.group(1), m.group(7) or ""


def template(site: str, method: str, path: str) -> str:
    return f"{site}|{method}|{path}"


def vector(tpl: str, val: str, counts: dict) -> list[float]:
    c = Counter(val)
    return ([math.log1p(len(val)), float(len(val.split())), float(sum(ch.isdigit() for ch in val)),
             float(sum(ch.isalpha() for ch in val)), float(c.get(" ", 0))]
            + [float(c.get(p, 0)) for p in s25.PUNCT] + [math.log1p(counts.get(tpl, 0))])


def evidence(samples, state, model) -> np.ndarray:
    nov = np.array([s25.input_novelty(t, v, state["profiles"]) for t, v in samples])
    out = np.empty(len(samples))
    for i in range(0, len(samples), 200_000):
        out[i:i + 200_000] = -model.score_samples(np.asarray([vector(t, v, state["counts"]) for t, v in samples[i:i + 200_000]]))
    return np.column_stack([nov, out])


def fit(train: list):
    from sklearn.ensemble import IsolationForest
    train = list(train)
    random.Random(SEED).shuffle(train)
    a, b = int(FIT * len(train)), int((FIT + CAL) * len(train))
    state = {"profiles": s25.profiles(train[:a]), "counts": dict(Counter(t for t, _ in train[:a]))}
    model = IsolationForest(n_estimators=300, random_state=SEED).fit(
        np.asarray([vector(t, v, state["counts"]) for t, v in train[:a]]))
    raw = evidence(train[a:], state, model)
    cal, thr = raw[: b - a], raw[b - a:]
    state["calibration"] = cal.tolist()
    state["thresholds"] = {"fused": v3.v1.normal_threshold(v3.fused(thr, cal, range(2)), BUDGET),
                           "input_novelty": v3.v1.normal_threshold(thr[:, 0], BUDGET),
                           "learned_anomaly": v3.v1.normal_threshold(thr[:, 1], BUDGET)}
    info = {"fit": a, "calibration": b - a, "threshold": len(train) - b, "templates": len(state["counts"]),
            "threshold_split_alert_rate": float((v3.fused(thr, cal, range(2)) > state["thresholds"]["fused"]).mean())}
    return state, model, info


def develop(zips: list[Path], out_dir: Path, models_dir: Path) -> None:
    if (out_dir / "freeze.json").exists():
        raise SystemExit("a freeze already exists")
    models_dir.mkdir(parents=True, exist_ok=True)
    freeze = {"schema": "predict-shield/real-logs-freeze/1", "code_sha256": code_hashes(),
              "sklearn": __import__("sklearn").__version__, "orgs": {}}
    for zp in zips:
        org = check_zip(zp)
        train = [(template(s, m, p), v) for s, t, m, p, v, *_ in requests(zp) if t < SPLIT[org]]
        state, model, info = fit(train)
        blob = pickle.dumps({"state": state, "model": model}, protocol=5)
        (models_dir / f"{org}.pkl").write_bytes(blob)
        freeze["orgs"][org] = {"train_requests": len(train), "model_sha256": sha256(blob),
                               "thresholds": state["thresholds"], **info}
        print("FIT", org, len(train), json.dumps(info), flush=True)
    freeze["freeze_sha256"] = sha256(json.dumps(freeze, sort_keys=True).encode())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    print("FROZEN", freeze["freeze_sha256"], flush=True)


def test(zips: list[Path], frozen: Path, models_dir: Path, expected: str, work: Path) -> None:
    freeze = json.loads((frozen / "freeze.json").read_text())
    rec = freeze.pop("freeze_sha256")
    if rec != expected or sha256(json.dumps(freeze, sort_keys=True).encode()) != rec:
        raise SystemExit("freeze record does not match")
    if code_hashes() != freeze["code_sha256"]:
        raise SystemExit("code changed after freeze")
    if (frozen / "test-report.json").exists():
        raise SystemExit("a test report already exists; the test runs once")
    work.mkdir(parents=True, exist_ok=True)
    for zp in zips:
        org = check_zip(zp)
        blob = (models_dir / f"{org}.pkl").read_bytes()
        if sha256(blob) != freeze["orgs"][org]["model_sha256"]:
            raise SystemExit(f"model {org} does not match the freeze")
        b = pickle.loads(blob)
        state, model = b["state"], b["model"]
        rows = [r for r in requests(zp) if r[1] >= SPLIT[org]]
        samples = [(template(s, m, p), v) for s, t, m, p, v, *_ in rows]
        raw = evidence(samples, state, model)
        cal, thr = np.asarray(state["calibration"]), state["thresholds"]
        np.savez_compressed(
            work / f"{org}.npz",
            fused=v3.fused(raw, cal, range(2)) > thr["fused"], novelty=raw[:, 0] > thr["input_novelty"],
            forest=raw[:, 1] > thr["learned_anomaly"], seen=np.array([t in state["profiles"] for t, _ in samples]),
            day=np.array([r[1].astimezone(WIB).strftime("%Y-%m-%d") for r in rows]),
            site=np.array([r[0] for r in rows]))
        (work / f"{org}.targets.json").write_text(json.dumps([r[5] for r in rows]))
        (work / f"{org}.inputs.json").write_text(json.dumps([r[4] for r in rows]))
        (work / f"{org}.review.json").write_text(json.dumps([[r[1].isoformat(), r[2], r[5], r[7]] for r in rows]))
        print("TESTED", org, len(rows), flush=True)


def libinj(work: Path) -> None:
    import libinjection
    for f in sorted(work.glob("*.inputs.json")):
        org = f.name.split(".")[0]
        flags = []
        for joined in json.loads(f.read_text()):
            flags.append(any(bool(libinjection.is_sql_injection(v)["is_sqli"]) or bool(libinjection.is_xss(v)["is_xss"])
                             for v in joined.split(" ") if v))
        np.savez_compressed(work / f"{org}.libinj.npz", flag=np.array(flags))
        print("LIBINJ", org, int(sum(flags)), "of", len(flags), flush=True)


def crs(work: Path, level: int, url: str) -> None:
    opener = urllib.request.build_opener()

    def send(target: str) -> int:
        safe = urllib.parse.quote(target, safe="/?&=%+:;,@!$'()*~.-_")
        for attempt in range(3):
            try:
                with opener.open(urllib.request.Request(url + (safe if safe.startswith("/") else "/" + safe),
                                                        headers=BROWSER_HEADERS), timeout=30) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code
            except (OSError, ValueError):
                if attempt == 2:
                    return 0
        return 0

    for probe in ("/?q=Jakarta", "/?id=9"):
        if send(probe) not in (200, 404):
            raise SystemExit(f"harness check failed at level {level}")
    for f in sorted(work.glob("*.targets.json")):
        org = f.name.split(".")[0]
        targets = json.loads(f.read_text())
        with cf.ThreadPoolExecutor(64) as ex:
            status = np.array(list(ex.map(send, targets, chunksize=256)), dtype=np.int16)
        np.savez_compressed(work / f"{org}.crs{level}.npz", status=status)
        print("CRS", level, org, dict(Counter(status.tolist()).most_common(5)), flush=True)


def report(work: Path, frozen: Path, output: Path, review_dir: Path) -> None:
    if output.exists():
        raise SystemExit("a test report already exists")
    freeze = json.loads((frozen / "freeze.json").read_text())
    out = {"schema": "predict-shield/real-logs-test/1", "freeze_sha256": freeze["freeze_sha256"], "orgs": {}}
    review_dir.mkdir(parents=True, exist_ok=True)
    for f in sorted(work.glob("*.npz")):
        if "." in f.stem:
            continue
        org = f.stem
        d = np.load(f)
        lib = np.load(work / f"{org}.libinj.npz")["flag"]
        c1 = np.load(work / f"{org}.crs1.npz")["status"] == 403
        c2 = np.load(work / f"{org}.crs2.npz")["status"] == 403
        indep = lib | c1 | c2
        n = len(indep)
        res = {"test_requests": n, "days": int(len(set(d["day"].tolist()))),
               "unseen_template_share": float((~d["seen"]).mean()),
               "independent_evidence": {"any": int(indep.sum()), "crs_pl1": int(c1.sum()), "crs_pl2": int(c2.sum()),
                                        "libinjection": int(lib.sum())}}
        for comp in ("fused", "novelty", "forest"):
            a = d[comp]
            res[comp] = {"alerts": int(a.sum()), "alert_rate": float(a.mean()),
                         "alerts_per_day": float(a.sum() / res["days"]),
                         "alerts_with_independent_evidence": int((a & indep).sum()),
                         "alerts_without_independent_evidence": int((a & ~indep).sum()),
                         "unconfirmed_alert_rate": float((a & ~indep).mean()),
                         "alert_rate_seen_templates": float(a[d["seen"]].mean()) if d["seen"].any() else None,
                         "alert_rate_unseen_templates": float(a[~d["seen"]].mean()) if (~d["seen"]).any() else None,
                         "detection_proxy": float(a[indep].mean()) if indep.any() else None,
                         "detection_proxy_crs_pl1": float(a[c1].mean()) if c1.any() else None}
        a = d["fused"]
        res["fused"]["by_day"] = {k: {"requests": int((d["day"] == k).sum()), "alerts": int(a[d["day"] == k].sum())}
                                  for k in sorted(set(d["day"].tolist()))}
        sites = Counter(d["site"].tolist())
        res["fused"]["by_site"] = {f"site-{i:02d}": {"requests": c, "alerts": int(a[d["site"] == s].sum())}
                                   for i, (s, c) in enumerate(sorted(sites.items()))}
        res["passed"] = res["fused"]["unconfirmed_alert_rate"] <= CEILING
        out["orgs"][org] = res
        idx = np.flatnonzero(a & ~indep).tolist()
        pick = sorted(random.Random(REVIEW_SEED).sample(idx, min(REVIEW_N, len(idx))))
        rows = json.loads((work / f"{org}.review.json").read_text())
        (review_dir / f"{org}-unconfirmed-alerts.json").write_text(
            json.dumps([{"time": rows[i][0], "method": rows[i][1], "target": rows[i][2], "agent": rows[i][3]} for i in pick],
                       indent=1, ensure_ascii=False))
        print("REPORT", org, json.dumps({k: res["fused"][k] for k in ("alerts", "alert_rate", "unconfirmed_alert_rate",
                                                                      "detection_proxy")}), "passed", res["passed"])
    out["orgs_passed"] = sum(r["passed"] for r in out["orgs"].values())
    out["pass_condition"] = json.loads((HERE / "protocol.json").read_text())["pass_condition"]
    output.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("develop", "test", "libinj", "crs", "report"))
    ap.add_argument("--zips", type=Path, nargs="+")
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--models-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--work", type=Path)
    ap.add_argument("--level", type=int)
    ap.add_argument("--url")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--review", type=Path)
    a = ap.parse_args()
    if a.stage == "develop":
        develop(a.zips, a.out_dir, a.models_dir)
    elif a.stage == "test":
        test(a.zips, a.frozen_dir, a.models_dir, a.expected_freeze_sha256, a.work)
    elif a.stage == "libinj":
        libinj(a.work)
    elif a.stage == "crs":
        crs(a.work, a.level, a.url)
    else:
        report(a.work, a.frozen_dir, a.output, a.review)


if __name__ == "__main__":
    main()
