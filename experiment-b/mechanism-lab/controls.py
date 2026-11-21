"""Positive and negative controls for the mechanism-lab campaign.

Positive control: inject a fault mode, publish the revocation, take no action,
and read the oracle every second for the control window. This measures
whether the fault persists past the campaign's measurement window or heals by
itself (for example when a cache entry expires and refreshes).

Negative control: no fault (mode "none"), same revocation and schedule. The
oracle, the gateway verifier and operator telemetry must all show revoked
access denied; anything else means the probes or the lab create false
failures.

At the end of the campaign window each run also records the verifier's
scope verdict and operator telemetry, so controls add labelled cases to
verifier_scoring.py.

Usage, inside experiment-b/mechanism-lab, with the Compose lab running:
  python controls.py --execute-lab --output reports/controls.json
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import defaultdict
from pathlib import Path

from pilot import (gateway_probes, gateway_scope_evidence, operator_telemetry,
                   oracle_snapshot, setup_fault, wait_ready)
from verifier_scoring import wilson

PREREG = json.loads((Path(__file__).resolve().parent / "PREREGISTRATION.json").read_text())
CONTROLS = PREREG["controls"]
CAMPAIGN_WINDOW = CONTROLS["campaign_window_seconds"]
CONTROL_WINDOW = CONTROLS["control_window_seconds"]
FAULT_MODES = ("loss", "delay", "duplicate", "reorder")
GRID = tuple((ttl, delay) for ttl in (2500, 15000) for delay in (0, 2500))
RUNS_PER_CELL = 2
PERSIST_MIN = CONTROLS["persist_min_runs"]
TARGET = "enforcer-b"


def schedule() -> list[dict]:
    """The fixed list of control runs, in execution order."""
    runs = []
    for mode in ("none",) + FAULT_MODES:
        for ttl, delay in GRID:
            for r in range(RUNS_PER_CELL):
                runs.append({"control_id": f"{mode}-ttl{ttl}-d{delay}-{r}", "fault_mode": mode,
                             "kind": "negative" if mode == "none" else "positive",
                             "cache_ttl_ms": ttl, "event_delay_ms": delay})
    return runs


def classify(run: dict) -> str:
    """Outcome of one control run from its oracle readings.

    Positive: NOT_EXERCISED (denied at the first read), PERSISTED (still
    exposed at the end of the campaign window), or SELF_HEALED (exposed at
    first, denied by the end of the campaign window).
    Negative: HEALTHY (denied at every read, verifier not reporting exposure)
    or FALSE_FAILURE.
    """
    reads = run["oracle_reads"]
    in_window = [r for r in reads if r["t"] <= CAMPAIGN_WINDOW + 0.5]
    end = run["end_of_campaign_window"]
    if run["kind"] == "negative":
        exposed = (any(r["denied"] is not True for r in reads)
                   or end.get("gateway_exposure_observed")
                   or end.get("verifier_scope") == "NOT VERIFIED")
        return "FALSE_FAILURE" if exposed else "HEALTHY"
    if not reads or reads[0]["denied"] is True:
        return "NOT_EXERCISED"
    return "SELF_HEALED" if in_window and in_window[-1]["denied"] is True else "PERSISTED"


def heal_time(run: dict) -> float | None:
    """Seconds until the oracle first reads denied, within the control window."""
    for r in run["oracle_reads"]:
        if r["denied"] is True:
            return r["t"]
    return None


def summarise(runs: list[dict]) -> dict:
    by_mode: dict[str, list[dict]] = defaultdict(list)
    for run in runs:
        by_mode[run["fault_mode"]].append(run)
    out = {}
    for mode, members in by_mode.items():
        outcomes = defaultdict(int)
        for m in members:
            outcomes[m["outcome"]] += 1
        cells = defaultdict(lambda: defaultdict(int))
        for m in members:
            cells[f"ttl{m['cache_ttl_ms']}-d{m['event_delay_ms']}"][m["outcome"]] += 1
        entry = {"runs": len(members), "outcomes": dict(outcomes),
                 "by_cell": {k: dict(v) for k, v in sorted(cells.items())}}
        if mode == "none":
            entry["verdict"] = "VALID" if outcomes["FALSE_FAILURE"] == 0 else "INVALIDATES_CAMPAIGN"
        else:
            exercised = len(members) - outcomes["NOT_EXERCISED"]
            entry["self_heal_rate_when_exercised"] = (outcomes["SELF_HEALED"] / exercised) if exercised else None
            entry["self_heal_wilson_95"] = wilson(outcomes["SELF_HEALED"], exercised)
            entry["heal_seconds_within_control_window"] = sorted(
                t for t in (heal_time(m) for m in members) if t is not None)
            entry["verdict"] = ("PERSISTENT" if outcomes["PERSISTED"] >= PERSIST_MIN
                                else "SELF_HEALING_OR_NOT_EXERCISED")
        out[mode] = entry
    return out


def run_one(spec: dict, control_token: str, oracle_token: str) -> dict:
    setup_fault(control_token, ttl_ms=spec["cache_ttl_ms"], delay_ms=spec["event_delay_ms"],
                fault_target=TARGET, fault_mode=spec["fault_mode"], oracle_token=oracle_token)
    start = time.monotonic()
    reads, end = [], None
    next_read = 0.0
    while True:
        t = time.monotonic() - start
        if t > CONTROL_WINDOW:
            break
        if end is None and t >= CAMPAIGN_WINDOW:
            probes = gateway_probes(count=8)
            scope = gateway_scope_evidence(control_token, probes)
            telemetry = operator_telemetry(control_token)
            truth = oracle_snapshot(oracle_token)
            end = {"t": round(time.monotonic() - start, 3),
                   "verifier_scope": scope.get("status"),
                   "gateway_exposure_observed": any(p["http_status"] == 200 for p in probes),
                   "operator_telemetry": telemetry,
                   "oracle_denied": truth["all_revoked_access_denied"]}
        if t >= next_read:
            truth = oracle_snapshot(oracle_token)
            reads.append({"t": round(time.monotonic() - start, 3),
                          "denied": truth["all_revoked_access_denied"]})
            next_read += 1.0
        time.sleep(0.05)
    run = {**spec, "oracle_reads": reads, "end_of_campaign_window": end or {}}
    run["outcome"] = classify(run)
    return run


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--execute-lab", action="store_true", required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    control_token = os.environ.get("LAB_CONTROL_TOKEN")
    oracle_token = os.environ.get("LAB_ORACLE_TOKEN")
    if not control_token or not oracle_token or control_token == oracle_token:
        raise SystemExit("Require distinct LAB_CONTROL_TOKEN and LAB_ORACLE_TOKEN")
    wait_ready()
    runs = []
    for spec in schedule():
        runs.append(run_one(spec, control_token, oracle_token))
        print(spec["control_id"], runs[-1]["outcome"], flush=True)
    from prereg_gate import current_state
    report = {
        "schema": "predict-shield/mechanism-controls/1",
        "lock_state_sha256": current_state()["lock_sha256"],
        "campaign_window_seconds": CAMPAIGN_WINDOW,
        "control_window_seconds": CONTROL_WINDOW,
        "fault_target": TARGET,
        "grid": [{"cache_ttl_ms": t, "event_delay_ms": d} for t, d in GRID],
        "summary": summarise(runs),
        "runs": runs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
