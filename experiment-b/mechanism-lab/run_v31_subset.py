"""Run a bounded, predeclared subset v3.1 physical pilot in disposable Compose.

Five independent configurations x two repetitions x four actual actions.
Authority-outage arms are NOT supported by current full-state oracle and are
explicitly excluded. Output cannot authorize the 150-group campaign.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from audit import inspect_trial
from campaign import exclusive_lock, register_plan, register_source
from collect import separate_records, source_commit, write_trial_records
from feasibility_v31 import evaluate
from export_v31_pilot import export
from pilot import ACTIONS, ENFORCERS, request, run_case, wait_ready
from pilot_v31_plan import create, save


def resume_all(token: str, *, timeout_seconds: float = 15) -> None:
    """Clean up any previously paused physical Kafka listener containers."""
    for node in ENFORCERS:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result, _, _ = request(node, "/admin/consumer/resume",
                                   method="POST", token=token, timeout=1.5)
            if result == 200:
                status, state, _ = request(
                    node, "/admin/consumer/status", token=token, timeout=1.5)
                if status == 200 and state.get("container_paused") is False:
                    break
            time.sleep(0.35)
        else:
            raise RuntimeError("Failed to physically resume Kafka consumer " + node)


def execute(token: str, oracle_token: str, root: Path) -> dict:
    if len(token) < 24 or len(oracle_token) < 24 or token == oracle_token:
        raise ValueError("Distinct disposable experiment credentials required")
    configs, trials = create()
    # Registered plan and source cannot be silently changed or overwritten.
    plan_dir = root / "plan"
    records = root / "records"
    plan_dir.mkdir(parents=True, exist_ok=True)
    save(plan_dir)
    with exclusive_lock(records):
        plan_sha = register_plan(records, configs, trials)
        source = source_commit()
        register_source(records, source)
        wait_ready()
        completed = 0
        for trial in trials:
            status, reason = inspect_trial(trial, records)
            if status != "missing":
                raise RuntimeError("Pilot run would overwrite or mask a prior record: " + reason)
            config = next(c for c in configs
                          if c["configuration_id"] == trial["configuration_id"])
            resume_all(token)
            try:
                observation = run_case(
                    trial["action_id"], token, oracle_token,
                    ttl_ms=config["cache_ttl_ms"], rps=config["requested_rps"],
                    fault_mode=config["fault_mode"], fault_target=config["fault_target"],
                    delay_ms=config["event_delay_ms"],
                    duration_seconds=config["measurement_seconds"],
                    gateway_includes_hidden=config["gateway_includes_hidden"],
                    routing_profile=config["routing_profile"],
                    complexity_stratum=config["complexity_stratum"],
                    node_service_latency_ms=tuple(config["node_service_latency_ms"]))
                split = separate_records(config, trial, observation)
                write_trial_records(records, split)
                state, why = inspect_trial(trial, records)
                if state != "complete":
                    raise RuntimeError("Measured pilot failed four-stream audit: " + why)
                completed += 1
            finally:
                resume_all(token)
        rows = export(configs, trials, records)
        gate = evaluate(rows, fixed_action="resync_policy")
        # This pilot excludes the sixth family (authority_outage), and its
        # group sample is small. It must never be used to declare final
        # preregistered v3.1 feasibility, even if numeric diagnostics pass.
        gate["final_v31_feasibility_evaluated"] = False
        gate["status"] = "EXPLORATORY_SUBSET_INCONCLUSIVE"
        gate["exclusion"] = "authority_outage not supported by full-state oracle"
        gate["registered_plan_sha256"] = plan_sha
        gate["executed_physical_replays"] = completed
        gate["registered_fault_families"] = sorted(set(c["fault_mode"] for c in configs))
        gate["research_protocol_status"] = "V3_1_DRAFT_NOT_FROZEN"
        gate["no_trained_model_evaluated"] = True
        return gate


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--execute-lab", action="store_true")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not args.execute_lab:
        p.error("Physical mutation requires --execute-lab")
    report = execute(os.getenv("LAB_CONTROL_TOKEN",""),
                     os.getenv("LAB_ORACLE_TOKEN",""), args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        json.dump(report, output, sort_keys=True, indent=2)
        output.write("\n")
    print(json.dumps({"status": report["status"],
                      "physical_replays": report["executed_physical_replays"],
                      "configuration_groups": report["pilot_configuration_groups"],
                      "diversity": report["decision_diversity"],
                      "reasons": report["failures"],
                      "final_v31_feasibility_evaluated": False}))


if __name__ == "__main__":
    main()
