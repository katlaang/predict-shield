"""Version 3 development on two networks, CIC-IDS2017 and CSE-CIC-IDS2018
(improved versions), then freeze. Never opens the test archive.

Steps, fixed in protocol_v3.json:
1. Sample each network: for every (file, family) keep the rows with the k
   smallest SHA-256 priorities (k_benign for benign, k_attack per attack
   family), and record how many rows each kept row stands for.
2. Leave one network out, for every configuration in the grid: fit the
   supervised model on the other network; calibrate on the held-out
   network's verified-normal flows only (benign, split bucket 0 fits the
   anomaly model, bucket 1 sets both thresholds); evaluate on buckets 2-9.
   The same configuration is also scored on its own training network
   (training fit).
3. Choose the configuration with the highest mean held-out detection over
   the two folds among those whose held-out normal alert rate is at most 1%
   on both folds; ties go to the smaller model.
4. Learning curve for the chosen configuration (10%, 30%, 100% of the
   training network).
5. Fit the chosen configuration on both networks' samples and freeze.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import pickle
import time
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

import features_v3 as fv

HERE = Path(__file__).resolve().parent
SEED = 20261121
BUDGET_EACH = 0.005
NORMAL_CEILING = 0.01
ANOMALY_FIT_MAX = 200_000
CODE_FILES = ("features_v3.py", "train_dev_v3.py", "score_test_v3.py", "protocol_v3.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            h.update(block)
    return h.hexdigest()


def code_hashes(directory: Path = HERE) -> dict:
    return {name: sha256_file(directory / name) for name in CODE_FILES}


def protocol() -> dict:
    return json.loads((HERE / "protocol_v3.json").read_text())


def priority_and_bucket(source: str, row_ids) -> tuple[np.ndarray, np.ndarray]:
    """Two independent uniforms from one SHA-256: sampling priority and split bucket."""
    pri = np.empty(len(row_ids))
    bucket = np.empty(len(row_ids), dtype=np.int8)
    for i, rid in enumerate(row_ids):
        d = hashlib.sha256(f"{source}\x00{rid}".encode()).digest()
        pri[i] = int.from_bytes(d[:8], "big") / 2.0 ** 64
        bucket[i] = int(int.from_bytes(d[8:16], "big") / 2.0 ** 64 * 10)
    return pri, bucket


class BottomK:
    """Keeps the k rows with the smallest priority for one key."""

    def __init__(self, k: int):
        self.k, self.parts, self.size, self.seen = k, [], 0, 0

    def add(self, pri, payload: dict):
        self.seen += len(pri)
        self.parts.append((pri, payload))
        self.size += len(pri)
        if self.size > 2 * self.k:
            self.prune()

    def prune(self):
        pri = np.concatenate([p for p, _ in self.parts])
        keys = self.parts[0][1].keys()
        payload = {k: np.concatenate([d[k] for _, d in self.parts]) for k in keys}
        keep = np.argsort(pri, kind="stable")[: self.k]
        self.parts = [(pri[keep], {k: v[keep] for k, v in payload.items()})]
        self.size = len(keep)

    def result(self):
        if not self.parts:
            return None
        self.prune()
        return self.parts[0]


def sample_network(archive: Path, network: str, k_benign: int, k_attack: int, chunksize: int = 250_000):
    """Stream every CSV member once and keep a bottom-k sample per (member, family)."""
    with zipfile.ZipFile(archive) as z:
        members = sorted(i.filename for i in z.infolist() if i.filename.lower().endswith(".csv"))
    keepers: dict[tuple, BottomK] = {}
    columns = None
    labels_seen = defaultdict(int)
    for member in members:
        started = time.monotonic()
        with zipfile.ZipFile(archive) as z, z.open(member) as raw:
            header = list(pd.read_csv(raw, nrows=0).columns)
        cols = fv.resolve_cic(header)
        if columns is None:
            columns = cols
        usecols = sorted(set(cols.values()) | {fv.CIC_PORT, fv.CIC_ID, fv.CIC_LABEL})
        rows = 0
        with zipfile.ZipFile(archive) as z, z.open(member) as raw:
            for chunk in pd.read_csv(raw, usecols=usecols, chunksize=chunksize, low_memory=False):
                rows += len(chunk)
                x = fv.build(chunk, cols, fv.CIC_PORT, hikari=False, feature_set="flow+service")
                labels = chunk[fv.CIC_LABEL].astype(str).to_numpy()
                classes = [fv.label_class(v) for v in labels]
                fam = np.array([f for _, f in classes], dtype=object)
                for lab in labels:
                    labels_seen[lab] += 1
                pri, bucket = priority_and_bucket(f"{network}/{member}", chunk[fv.CIC_ID].to_numpy())
                for family in np.unique(fam):
                    m = fam == family
                    key = (member, family)
                    if key not in keepers:
                        keepers[key] = BottomK(k_benign if family == "benign" else k_attack)
                    keepers[key].add(pri[m], {"x": x[m], "bucket": bucket[m]})
        print(network, member, rows, "rows", round(time.monotonic() - started), "s", flush=True)
    xs, fams, buckets, members_of, weights = [], [], [], [], []
    for (member, family), keeper in sorted(keepers.items()):
        res = keeper.result()
        if res is None:
            continue
        _, d = res
        n = len(d["x"])
        xs.append(d["x"])
        buckets.append(d["bucket"])
        fams += [family] * n
        members_of += [member] * n
        weights.append(np.full(n, keeper.seen / n))
    fams = np.array(fams, dtype=object)
    return {
        "network": network, "x": np.vstack(xs), "family": fams, "attack": fams != "benign",
        "bucket": np.concatenate(buckets), "member": np.array(members_of, dtype=object),
        "weight": np.concatenate(weights), "columns": columns,
        "rows_by_key": {f"{m}|{f}": k.seen for (m, f), k in sorted(keepers.items())},
        "labels": dict(sorted(labels_seen.items())),
    }


def select_columns(x: np.ndarray, feature_set: str) -> np.ndarray:
    return x[:, : len(fv.feature_names(feature_set))]


def fit_supervised(x, y, max_leaf_nodes: int, max_iter: int):
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(max_iter=max_iter, learning_rate=0.1, max_leaf_nodes=max_leaf_nodes,
                                          class_weight="balanced", early_stopping=False,
                                          random_state=SEED).fit(x, y)


def calibrate(x_fit_normal, x_threshold_normal, supervised):
    """Shared with the test stage. Both inputs are verified-normal flows only."""
    from sklearn.ensemble import IsolationForest
    anomaly = IsolationForest(n_estimators=200, max_samples=1024, random_state=SEED).fit(
        x_fit_normal[:ANOMALY_FIT_MAX])
    t_s = fv.normal_threshold(supervised.predict_proba(x_threshold_normal)[:, 1], BUDGET_EACH)
    t_a = fv.normal_threshold(-anomaly.score_samples(x_threshold_normal), BUDGET_EACH)
    return anomaly, t_s, t_a


def evaluate(net: dict, feature_set: str, supervised) -> dict:
    """Calibrate on net's verified-normal buckets 0 and 1, score buckets 2-9.
    Rates are weighted back to the full network with each row's weight."""
    x = select_columns(net["x"], feature_set)
    normal, b = net["family"] == "benign", net["bucket"]
    if np.any(net["attack"][normal]):
        raise AssertionError("an attack row entered the verified-normal set")
    anomaly, t_s, t_a = calibrate(x[normal & (b == 0)], x[normal & (b == 1)], supervised)
    ev = b >= 2
    fire_s = supervised.predict_proba(x[ev])[:, 1] > t_s
    fire_a = -anomaly.score_samples(x[ev]) > t_a
    alert = fire_s | fire_a
    att, w, fam = net["attack"][ev], net["weight"][ev], net["family"][ev]
    det = float(np.sum(w[alert & att]) / np.sum(w[att])) if att.any() else None
    nar = float(np.sum(w[alert & ~att]) / np.sum(w[~att])) if (~att).any() else None
    families = {}
    for f in sorted(set(fam.tolist()) - {"benign"}):
        m = fam == f
        families[f] = {"sampled_flows": int(m.sum()), "detected": int(alert[m].sum()),
                       "by_supervised": int(fire_s[m].sum()), "by_anomaly_only": int((fire_a & ~fire_s)[m].sum()),
                       "detection_rate": float(alert[m].mean())}
    return {"detection_weighted": det, "normal_alert_rate_weighted": nar,
            "sampled": {"attack": int(att.sum()), "normal": int((~att).sum()),
                        "TP": int((alert & att).sum()), "FP": int((alert & ~att).sum())},
            "thresholds": {"supervised": t_s, "anomaly": t_a},
            "calibration_rows": {"anomaly_fit": int(min(np.sum(normal & (b == 0)), ANOMALY_FIT_MAX)),
                                 "thresholds": int(np.sum(normal & (b == 1)))},
            "by_family": families}


def grid(spec: dict):
    for fs, leaves, iters in itertools.product(spec["feature_sets"], spec["max_leaf_nodes"], spec["max_iter"]):
        yield {"feature_set": fs, "max_leaf_nodes": leaves, "max_iter": iters}


def capacity(cfg: dict) -> tuple:
    return (cfg["max_leaf_nodes"] * cfg["max_iter"], fv.FEATURE_SETS.index(cfg["feature_set"]))


def choose(results: list[dict]) -> dict:
    eligible = [r for r in results
                if all(f["held_out"]["normal_alert_rate_weighted"] <= NORMAL_CEILING for f in r["folds"].values())]
    pool = eligible or results
    best = max(pool, key=lambda r: (round(r["mean_held_out_detection"], 6), tuple(-v for v in capacity(r["config"]))))
    return {"config": best["config"], "eligible_configs": len(eligible),
            "rule": "highest mean held-out detection among configurations at most 1% normal alerts on both folds; ties to the smaller model"}


def subsample(net: dict, fraction: float) -> dict:
    keep = net["bucket"] >= 0
    if fraction < 1:
        pri, _ = priority_and_bucket("learning-curve", np.arange(len(net["x"])))
        keep = pri < fraction
    return {k: (v[keep] if isinstance(v, np.ndarray) else v) for k, v in net.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive-2017", type=Path, required=True)
    ap.add_argument("--archive-2018", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()
    proto = protocol()
    dev = proto["sources"]["development"]
    for key, path in (("cic2017", args.archive_2017), ("cic2018", args.archive_2018)):
        digest = sha256_file(path)
        if digest != dev[key]["sha256"]:
            raise SystemExit(f"{key} archive does not match its pin: {digest}")
    spec = proto["development"]
    nets = {
        "cic2017": sample_network(args.archive_2017, "cic2017", spec["k_benign"], spec["k_attack"]),
        "cic2018": sample_network(args.archive_2018, "cic2018", spec["k_benign"], spec["k_attack"]),
    }
    for name, net in nets.items():
        print(name, "sampled", len(net["x"]), "attack", int(net["attack"].sum()), flush=True)

    results = []
    for cfg in grid(spec["grid"]):
        folds = {}
        for held, train in (("cic2017", "cic2018"), ("cic2018", "cic2017")):
            t = nets[train]
            started = time.monotonic()
            model = fit_supervised(select_columns(t["x"], cfg["feature_set"]), t["attack"],
                                   cfg["max_leaf_nodes"], cfg["max_iter"])
            folds[held] = {"train_network": train, "held_out": evaluate(nets[held], cfg["feature_set"], model),
                           "training_fit": evaluate(t, cfg["feature_set"], model),
                           "seconds": round(time.monotonic() - started)}
            print("config", cfg, "held out", held, "detection",
                  round(folds[held]["held_out"]["detection_weighted"], 4), "normal alerts",
                  round(folds[held]["held_out"]["normal_alert_rate_weighted"], 4), "| training fit",
                  round(folds[held]["training_fit"]["detection_weighted"], 4), flush=True)
        results.append({"config": cfg, "folds": folds,
                        "mean_held_out_detection": float(np.mean([f["held_out"]["detection_weighted"]
                                                                  for f in folds.values()]))})
    chosen = choose(results)
    cfg = chosen["config"]
    print("CHOSEN", chosen, flush=True)

    curve = {}
    for fraction in spec["learning_curve_fractions"]:
        curve[str(fraction)] = {}
        for held, train in (("cic2017", "cic2018"), ("cic2018", "cic2017")):
            t = subsample(nets[train], fraction)
            model = fit_supervised(select_columns(t["x"], cfg["feature_set"]), t["attack"],
                                   cfg["max_leaf_nodes"], cfg["max_iter"])
            curve[str(fraction)][held] = {"training_rows": int(len(t["x"])),
                                          "held_out_detection": evaluate(nets[held], cfg["feature_set"], model)[
                                              "detection_weighted"]}
        print("learning curve", fraction, curve[str(fraction)], flush=True)

    x_all = np.vstack([select_columns(n["x"], cfg["feature_set"]) for n in nets.values()])
    y_all = np.concatenate([n["attack"] for n in nets.values()])
    supervised = fit_supervised(x_all, y_all, cfg["max_leaf_nodes"], cfg["max_iter"])
    args.out_dir.mkdir(parents=True, exist_ok=True)
    bundle = pickle.dumps({"supervised": supervised, "config": cfg,
                           "feature_names": fv.feature_names(cfg["feature_set"])}, protocol=5)
    (args.out_dir / "supervised.pkl").write_bytes(bundle)
    families = sorted(set().union(*(set(n["family"].tolist()) for n in nets.values())) - {"benign"})
    freeze = {"schema": "predict-shield/cic-flow-v3-freeze/1",
              "supervised_sha256": hashlib.sha256(bundle).hexdigest(), "config": cfg,
              "code_sha256": code_hashes(),
              "development_archives_sha256": {k: dev[k]["sha256"] for k in ("cic2017", "cic2018")},
              "test_pin": proto["sources"]["test"]["sha256"], "development_families": families,
              "training_rows": int(len(x_all)),
              "sklearn": __import__("sklearn").__version__, "numpy": np.__version__, "pandas": pd.__version__}
    freeze["freeze_sha256"] = hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest()
    report = {"schema": "predict-shield/cic-flow-v3-development/1", "freeze_sha256": freeze["freeze_sha256"],
              "networks": {k: {"sampled_rows": int(len(n["x"])), "sampled_attack_rows": int(n["attack"].sum()),
                               "columns": n["columns"], "rows_by_key": n["rows_by_key"], "labels": n["labels"]}
                           for k, n in nets.items()},
              "grid_results": results, "chosen": chosen, "learning_curve": curve}
    (args.out_dir / "freeze.json").write_text(json.dumps(freeze, indent=1, sort_keys=True) + "\n")
    (args.out_dir / "development-report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print("FROZEN supervised", freeze["supervised_sha256"], "freeze", freeze["freeze_sha256"], flush=True)


if __name__ == "__main__":
    main()
