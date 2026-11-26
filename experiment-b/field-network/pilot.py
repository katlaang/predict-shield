"""Read-only PREDICT-SHIELD field pilot on Zeek JSON conn.log.

Train a separate, *new* model on an operator-controlled site's observed
baseline; calibrate on a disjoint later period; evaluate subsequently observed
flows. No packets are transmitted, no targets are scanned, and no defensive
actions are executed. Output is aggregate-only and never claims ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pickle
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn import __version__ as SKLEARN_VERSION
from sklearn.ensemble import IsolationForest

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parents[1] / "engine"
SCHEMA = "predict-shield/authorized-field-network/1"
SEED = 20261126
MAX_ROWS = 300_000
MAX_LINE = 128 * 1024
TRAIN_MIN = 200
CAL_MIN = 100
CALIBRATION_TARGET = 0.005
NUMERIC = ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
FEATURES = tuple("log_" + f for f in NUMERIC) + tuple("missing_" + f for f in NUMERIC) + (
    "proto_tcp", "proto_udp", "proto_icmp", "state_sf", "state_s0", "state_rej"
)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def numeric(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    x = float(value)
    return x if math.isfinite(x) and x >= 0 else None


def parse_flow(line: bytes):
    if len(line) > MAX_LINE:
        return None
    try:
        record = json.loads(line)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(record, dict) or numeric(record.get("ts")) is None:
        return None
    if not isinstance(record.get("proto"), str) or not record["proto"]:
        return None
    vals = [numeric(record.get(k)) for k in NUMERIC]
    if not any(v is not None for v in vals[1:]):
        return None
    protocol = record["proto"].lower()
    state = str(record.get("conn_state", ""))
    feats = [math.log1p(v) if v is not None else 0.0 for v in vals]
    feats += [float(v is None) for v in vals]
    feats += [float(protocol == x) for x in ("tcp", "udp", "icmp")]
    feats += [float(state == x) for x in ("SF", "S0", "REJ")]
    return float(record["ts"]), feats


def load_flows(path: Path, max_rows: int = MAX_ROWS):
    if not path.is_file():
        raise FileNotFoundError(path)
    vectors, timestamps = [], []
    seen = 0
    counts = Counter()
    with path.open("rb") as fp:
        for raw in fp:
            seen += 1
            if seen > max_rows:
                raise ValueError("Zeek log exceeds the registered row cap; split by whole time windows")
            parsed = parse_flow(raw)
            if parsed is None:
                counts["unsupported_or_invalid"] += 1
                continue
            ts, vec = parsed
            timestamps.append(ts)
            vectors.append(vec)
    counts["log_lines"] = seen
    counts["scorable_flows"] = len(vectors)
    x = np.asarray(vectors, dtype=np.float64).reshape(-1, len(FEATURES))
    return x, timestamps, dict(counts)


def threshold_at_budget(scores: np.ndarray, target: float):
    if not 0 < target < 0.05:
        raise ValueError("invalid calibration alert budget")
    ordered = np.sort(np.asarray(scores, dtype=np.float64))
    if not len(ordered) or not np.all(np.isfinite(ordered)):
        raise ValueError("no usable calibration values")
    index = min(len(ordered) - 1, math.ceil((1 - target) * len(ordered)) - 1)
    return float(ordered[index])


def assert_approved(authorized: bool, site: str):
    if not authorized:
        raise ValueError("explicit --operator-authorized flag required")
    if not site or len(site) > 64 or not all(c.isalnum() or c in "-_" for c in site):
        raise ValueError("site ID must be non-identifying, 1-64 letters, digits, hyphens or underscores")


def train(baseline: Path, calibration: Path, out_dir: Path, site: str, authorized: bool):
    assert_approved(authorized, site)
    if out_dir.exists():
        raise FileExistsError("refusing to overwrite existing model output directory")
    if baseline.resolve() == calibration.resolve() or sha(baseline) == sha(calibration):
        raise ValueError("baseline and calibration must be distinct captures")
    fit_x, fit_ts, fit_counts = load_flows(baseline)
    cal_x, cal_ts, cal_counts = load_flows(calibration)
    if len(fit_x) < TRAIN_MIN or len(cal_x) < CAL_MIN:
        raise ValueError("insufficient actual flow observations to fit and calibrate")
    if min(cal_ts) <= max(fit_ts):
        raise ValueError("calibration must be chronologically after the baseline")
    model = IsolationForest(n_estimators=200, max_samples=min(256, len(fit_x)),
                            random_state=SEED, n_jobs=1)
    model.fit(fit_x)
    scores = -model.score_samples(cal_x)
    threshold = threshold_at_budget(scores, CALIBRATION_TARGET)
    alerts = int((scores > threshold).sum())
    blob = pickle.dumps(model, protocol=5)
    # Model and manifest are private operator data; do not commit or upload.
    out_dir.mkdir(mode=0o700, parents=True)
    (out_dir / "model.pkl").write_bytes(blob)
    (out_dir / "model.pkl").chmod(0o600)
    freeze = {
        "schema": SCHEMA + "/freeze", "source": "zeek-json-conn-log",
        "site": site, "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_sha256": sha(baseline), "calibration_sha256": sha(calibration),
        "baseline_max_ts": max(fit_ts), "calibration_min_ts": min(cal_ts),
        "calibration_max_ts": max(cal_ts),
        "fit_rows": len(fit_x), "calibration_rows": len(cal_x),
        "fit_readability": fit_counts, "calibration_readability": cal_counts,
        "calibration_target": CALIBRATION_TARGET, "calibration_alerts": alerts,
        "calibration_alert_fraction": alerts / len(cal_x),
        "threshold": threshold, "feature_names": FEATURES,
        "model_sha256": hashlib.sha256(blob).hexdigest(),
        "implementation_sha256": sha(HERE / "pilot.py"),
        "protocol_sha256": sha(HERE / "protocol.json"),
        "sklearn": SKLEARN_VERSION,
        "policy": "MONITOR_ONLY_NO_AUTO_RESPONSE",
        "assumed_normal_baseline_not_ground_truth": True,
        "real_world_false_positive_rate": None,
        "detection_recall": None,
    }
    freeze["freeze_sha256"] = hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest()
    (out_dir / "freeze.json").write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
    (out_dir / "freeze.json").chmod(0o600)
    return freeze


def load_frozen(directory: Path, site: str):
    frozen = json.loads((directory / "freeze.json").read_text())
    saved = frozen.pop("freeze_sha256")
    if saved != hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest():
        raise ValueError("freeze record changed")
    if frozen["site"] != site or tuple(frozen["feature_names"]) != FEATURES:
        raise ValueError("wrong site or feature schema")
    if frozen["implementation_sha256"] != sha(HERE / "pilot.py"):
        raise ValueError("feature implementation changed; model no longer frozen")
    if frozen["protocol_sha256"] != sha(HERE / "protocol.json"):
        raise ValueError("field protocol changed after model freeze")
    if frozen["sklearn"] != SKLEARN_VERSION:
        raise ValueError("model runtime library version changed")
    raw = (directory / "model.pkl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != frozen["model_sha256"]:
        raise ValueError("model integrity check failed")
    frozen["freeze_sha256"] = saved
    # NEVER load pickles received from untrusted sources. The model directory
    # must have been generated locally with private filesystem permissions.
    return frozen, pickle.loads(raw)


def report(site: str, frozen: dict, total: int, alerts: int, invalid: int,
           first_ts, last_ts, *, source_sha=None, observation_seconds=None):
    flow_rate = alerts / total if total else None
    return {
        "schema": SCHEMA + "/observation",
        "site": site, "frozen_model_sha256": frozen["freeze_sha256"],
        "source_kind": "zeek-json-conn-log", "source_sha256": source_sha,
        "operational_scope": "authorized_network_passive_observation_only",
        "flow_records_scored": total, "anomaly_alerts": alerts,
        "invalid_or_incomplete_records": invalid,
        "anomaly_alert_fraction": flow_rate,
        "anomalies_per_1000_flows": 1000 * flow_rate if flow_rate is not None else None,
        "first_connection_ts": first_ts, "last_connection_ts": last_ts,
        "observation_wall_seconds": observation_seconds,
        "confirmed_malicious": 0, "confirmed_benign": 0,
        "ground_truth": "UNKNOWN", "false_positive_rate": None,
        "attack_detection_recall": None,
        "response_actions_attempted": 0, "changes_to_network": False,
        "notes": [
            "Anomalies are not confirmed attacks; independent adjudication is required.",
            "Calibration traffic was assumed normal, not independently proved benign.",
            "This is a new field-network model, NOT the frozen DVWA v3 fused detector.",
            "No production efficacy or critical-infrastructure resilience claim follows from these observations."
        ]
    }


def write_new(path: Path, value: dict):
    if path.exists():
        raise FileExistsError("refusing to overwrite earlier evaluation evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def evaluate(path: Path, model_dir: Path, output: Path, site: str, authorized: bool):
    assert_approved(authorized, site)
    if output.exists():
        raise FileExistsError("evaluation report already exists; refusing to rescore")
    frozen, model = load_frozen(model_dir, site)
    file_hash = sha(path)
    if file_hash in (frozen["baseline_sha256"], frozen["calibration_sha256"]):
        raise ValueError("evaluation may not reuse fitting/calibration capture")
    x, stamps, counts = load_flows(path)
    if not len(x):
        raise ValueError("no valid Zeek conn.log observations")
    if min(stamps) <= frozen["calibration_max_ts"]:
        raise ValueError("evaluation timestamps must be after calibration")
    scores = -model.score_samples(x)
    alerts = int((scores > frozen["threshold"]).sum())
    output_doc = report(site, frozen, len(x), alerts, counts.get("unsupported_or_invalid", 0),
                        min(stamps), max(stamps), source_sha=file_hash)
    write_new(output, output_doc)
    return output_doc


def watch(path: Path, model_dir: Path, output: Path, site: str, authorized: bool,
          duration_s: int, dashboard_port: int | None = None):
    assert_approved(authorized, site)
    if not (1 <= duration_s <= 86400):
        raise ValueError("watch must have a bounded duration of 1 to 86400 seconds")
    if output.exists():
        raise FileExistsError("watch report already exists")
    frozen, model = load_frozen(model_dir, site)
    if not path.is_file():
        raise FileNotFoundError("Zeek JSON conn.log must already exist")
    state = server = None
    if dashboard_port is not None:
        if not 1024 <= dashboard_port <= 65535:
            raise ValueError("invalid dashboard port")
        sys.path.insert(0, str(ENGINE))
        from predict_shield.live_feed import LiveFeedServer, LiveState
        state = LiveState()
        server = LiveFeedServer(state, host="127.0.0.1", port=dashboard_port,
                                page=HERE / "dashboard.html",
                                script=HERE / "dashboard.js").start()
        print("LOCAL READ-ONLY DASHBOARD:", server.url, flush=True)
    count = alerts = invalid = 0
    first = last = None
    begin = time.monotonic()
    # Start at EOF by design: historical data must be handled by 'evaluate'.
    handle = path.open("rb")
    handle.seek(0, os.SEEK_END)
    inode = path.stat().st_ino
    try:
        while time.monotonic() - begin < duration_s:
            raw = handle.readline()
            if raw and raw.endswith(b"\n"):
                parsed = parse_flow(raw)
                if parsed is None:
                    invalid += 1
                else:
                    ts, vec = parsed
                    v = np.asarray([vec])
                    flag = float(-model.score_samples(v)[0]) > frozen["threshold"]
                    count += 1
                    alerts += bool(flag)
                    first = ts if first is None else min(first, ts)
                    last = ts if last is None else max(last, ts)
            elif raw:
                handle.seek(-len(raw), os.SEEK_CUR)  # incomplete log line
            else:
                time.sleep(0.25)
                try:
                    s = path.stat()
                    if s.st_ino != inode or s.st_size < handle.tell():
                        handle.close()
                        handle = path.open("rb")
                        inode = s.st_ino
                except FileNotFoundError:
                    pass  # Zeek may briefly rotate the file
            if state is not None:
                state.panel("field_network", {"site": site, "flow_records": count,
                    "anomalies": alerts, "invalid_records": invalid,
                    "alert_fraction": alerts / count if count else None,
                    "monitor_only": True, "ground_truth": "UNKNOWN",
                    "model_sha256": frozen["freeze_sha256"]})
    except KeyboardInterrupt:
        print("STOPPED BY OPERATOR; aggregate evidence retained", flush=True)
    finally:
        handle.close()
        if server is not None:
            server.stop()
    result = report(site, frozen, count, int(alerts), invalid, first, last,
                    observation_seconds=round(time.monotonic() - begin, 3))
    write_new(output, result)
    return result


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="stage", required=True)
    for name in ("fit", "evaluate", "watch"):
        a = sub.add_parser(name)
        a.add_argument("--site", required=True, help="non-identifying operator-defined ID")
        a.add_argument("--operator-authorized", action="store_true",
                       help="attest permission to collect/score this network's telemetry")
        if name == "fit":
            a.add_argument("--baseline", type=Path, required=True)
            a.add_argument("--calibration", type=Path, required=True)
            a.add_argument("--out-dir", type=Path, required=True)
        else:
            a.add_argument("--input", type=Path, required=True)
            a.add_argument("--model-dir", type=Path, required=True)
            a.add_argument("--output", type=Path, required=True)
        if name == "watch":
            a.add_argument("--duration-seconds", type=int, default=3600)
            a.add_argument("--dashboard-port", type=int)
    a = p.parse_args()
    if a.stage == "fit":
        result = train(a.baseline, a.calibration, a.out_dir, a.site, a.operator_authorized)
        print(json.dumps({k: result[k] for k in ("site", "fit_rows", "calibration_rows",
                "calibration_alerts", "freeze_sha256", "policy")}, indent=2))
    elif a.stage == "evaluate":
        result = evaluate(a.input, a.model_dir, a.output, a.site, a.operator_authorized)
        print(json.dumps(result, indent=2))
    else:
        result = watch(a.input, a.model_dir, a.output, a.site, a.operator_authorized,
                       a.duration_seconds, a.dashboard_port)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
