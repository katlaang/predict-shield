"""Compact per-trial table of the scored mechanism-lab campaign, for the showcase.

Reads the full records (the campaign's run artifact) and the regenerated plan
v3.1, and writes one row per trial with the fields the verifier replay needs.
Every outcome field comes from the same functions the locked analysis used.

  python export_trials.py --plan PLAN_DIR --records RECORDS_DIR --output trials.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[2] / "experiment-b" / "mechanism-lab"
sys.path.insert(0, str(LAB))

from collect import load_plan  # noqa: E402
from outcome_report import trial_row  # noqa: E402
from verifier_scoring import dual_verdict, telemetry_reading  # noqa: E402

STREAMS = ("verification", "oracle", "operations")


def export(plan_dir: Path, records: Path) -> list[dict]:
    configs, trials = load_plan(plan_dir)
    by_id = {c["configuration_id"]: c for c in configs}
    rows = []
    for t in trials:
        files = {s: records / s / (t["run_id"] + ".json") for s in STREAMS}
        if not all(f.is_file() for f in files.values()):
            raise SystemExit(f"incomplete trial {t['run_id']}")
        rec = {s: json.loads(f.read_text()) for s, f in files.items()}
        cfg = by_id[t["configuration_id"]]
        r = trial_row(cfg, rec)
        v = rec["verification"]
        telemetry = telemetry_reading(v.get("operator_observations_after"))
        dual, reason = dual_verdict(v["outcome"], telemetry)
        rows.append({
            "run": r["run_id"], "cfg": r["configuration_id"], "fault": r["fault_mode"],
            "cls": r["control_class"], "action": r["action"], "target": cfg.get("fault_target"),
            "hidden_routed": cfg.get("gateway_includes_hidden"), "ttl_ms": cfg.get("cache_ttl_ms"),
            "delay_ms": cfg.get("event_delay_ms"), "rps": cfg.get("requested_rps"),
            "restart_ok": cfg.get("restart_permitted"),
            "oracle_denied": r["remediated"], "scope": v["outcome"], "telemetry": telemetry,
            "dual": dual, "dual_reason": reason,
            "exp_lo": round(r["exposure_lower"], 3), "exp_hi": round(r["exposure_upper"], 3),
            "window_s": r["window_seconds"], "failed": r["failed_requests"], "observed": r["observed_requests"],
            "errors": [k for k, hit in r["errors"].items() if hit],
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", type=Path, required=True)
    ap.add_argument("--records", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    rows = export(a.plan, a.records)
    if len(rows) != 1200:
        raise SystemExit(f"expected 1200 trials, got {len(rows)}")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps({"schema": "predict-shield/showcase-trials/1",
                                    "source": "mechanism-lab scored campaign, CI run 44879497946",
                                    "trials": rows}, separators=(",", ":")) + "\n")
    print(len(rows), "trials written")


if __name__ == "__main__":
    main()
