"""Opt-in real Docker authority outage with privileged pre-outage witness.

Only observed direct target behavior is measured during an external outage.
Never treats a historical policy witness as live authoritative verification.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from authority_outage_witness import capture_witness, observe_offline
from physical_faults import compose_command, wait_authority_unavailable
from pilot import request, setup_fault, wait_ready


def run(control: str, oracle: str, compose_dir: Path) -> dict:
    if (len(control) < 24 or len(oracle) < 24 or control == oracle):
        raise ValueError("Distinct disposable lab credentials required")
    wait_ready()
    # An actual missed revocation event is injected before the authority
    # goes offline. The observer has access to the current desired revision
    # ONLY before the external service is physically stopped.
    setup_fault(control, ttl_ms=30000, delay_ms=0,
                fault_target="enforcer-b", fault_mode="loss",
                oracle_token=oracle)
    pre_status, pre, _ = request("oracle", "/oracle/observe", oracle=oracle, timeout=5)
    if pre_status != 200:
        raise RuntimeError("Could not independently witness pre-outage policy")
    witness = capture_witness(pre, observed_at=datetime.now(timezone.utc))
    stopped = False
    try:
        compose_command(["stop", "authority"], cwd=compose_dir)
        stopped = True
        wait_authority_unavailable()
        offline_http, offline, _ = request("oracle", "/oracle/observe",
                                           oracle=oracle, timeout=5)
        if offline_http != 200:
            raise RuntimeError("Independent oracle unavailable during authority outage")
        result = observe_offline(offline, witness)
        if (result["verification_status"] == "VERIFIED"
                or result["authority_truth_status"] != "UNKNOWN"):
            raise RuntimeError("Offline observation fabricated verified policy truth")
        result["physical_authority_stop_observed"] = True
        result["physical_kafka_loss_injected_before_outage"] = True
        result["experiment_type"] = "mechanism_witness_smoke_only"
        return result
    finally:
        if stopped:
            compose_command(["start", "authority"], cwd=compose_dir)
            wait_ready()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    opts = parser.parse_args()
    if not opts.execute_lab:
        parser.error("Requires --execute-lab for disposable Docker mutation")
    result = run(os.getenv("LAB_CONTROL_TOKEN", ""),
                 os.getenv("LAB_ORACLE_TOKEN", ""),
                 Path(__file__).resolve().parent)
    opts.output.parent.mkdir(parents=True, exist_ok=True)
    with opts.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
