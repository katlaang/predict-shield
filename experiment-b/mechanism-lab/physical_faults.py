"""Opt-in physical authority-outage mechanism smoke test.

Run ONLY in the disposable localhost-bound Experiment B Compose lab.
This does not change frozen v3 trial definitions or claim AI efficacy.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

from pilot import request, wait_ready, wait_for_target


def compose_command(args: list[str], *, cwd: str | Path) -> None:
    """Fail closed on an allowlisted Docker Compose lifecycle operation."""
    if args not in (["stop", "authority"], ["start", "authority"],
                    ["restart", "enforcer-b"], ["pause", "authority"],
                    ["unpause", "authority"]):
        raise ValueError("Unexpected Docker Compose operation")
    result = subprocess.run(["docker", "compose", *args], cwd=cwd, check=False,
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Docker Compose operation failed: " + result.stderr[-600:])


def wait_authority_unavailable(*, attempts: int = 10, sleep_seconds: float = 0.5) -> None:
    for _ in range(attempts):
        code, _, _ = request("authority", "/healthz", timeout=0.5)
        if code is None:
            return
        time.sleep(sleep_seconds)
    raise RuntimeError("Authority remains reachable; physical stop not established")


def run_outage(control_token: str, *, compose_dir: str | Path,
               oracle_token: str | None = None) -> dict:
    """Physically stop the authority, attempt resync and local restart.

    Resync must not publish through an unavailable HTTP endpoint. A local
    restart must not bring back an externally stopped authority. This test
    does not assert eventual remediation, fault prevalence, or optimal action.
    """
    if not control_token or len(control_token) < 24:
        raise ValueError("Disposable lab control token required")
    wait_ready()
    before, _, _ = request("authority", "/healthz")
    if before != 200:
        raise RuntimeError("Authority not healthy at baseline")
    stopped = False
    observations = {"schema": "physical-authority-outage-smoke-v1",
                    "executed_against_real_compose": True, "baseline_authority_status": before}
    try:
        compose_command(["stop", "authority"], cwd=compose_dir)
        stopped = True
        wait_authority_unavailable()
        # A real HTTP resync request cannot publish while authority is down.
        resync_http, resync_payload, _ = request(
            "authority", "/control/resync", method="POST", token=control_token, timeout=1.0)
        observations["resync_http_status"] = resync_http
        observations["resync_unavailable"] = resync_http is None
        if not observations["resync_unavailable"]:
            raise RuntimeError("Resync unexpectedly reached stopped authority")
        # Restart local enforcer separately; this cannot start the authority.
        compose_command(["restart", "enforcer-b"], cwd=compose_dir)
        observations["enforcer_restart_ready_seconds"] = wait_for_target("enforcer-b")
        authority_http, _, _ = request("authority", "/healthz", timeout=0.5)
        observations["authority_after_enforcer_restart_status"] = authority_http
        observations["authority_still_unavailable"] = authority_http is None
        if not observations["authority_still_unavailable"]:
            raise RuntimeError("Authority unexpectedly recovered during local restart")
        if oracle_token is not None:
            if len(oracle_token) < 24 or oracle_token == control_token:
                raise ValueError("Independent lab oracle credential required")
            # A physically stopped authority must not be reclassified as
            # VERIFIED merely because all direct target probes answer.
            observer_http, observer, _ = request(
                "oracle", "/oracle/observe", oracle=oracle_token, timeout=5)
            if (observer_http != 200 or
                    observer.get("authority_truth_available") is not False or
                    observer.get("inventory_complete") is not False or
                    observer.get("all_revoked_access_denied") is not None):
                raise RuntimeError("Oracle invented authority truth during real outage")
            observations["oracle_authority_truth_available"] = False
            observations["oracle_scope_complete"] = False
            observations["oracle_policy_verdict"] = "UNKNOWN"
            observations["direct_target_observations_complete"] = observer.get(
                "direct_target_observations_complete") is True
        observations["outcome"] = "MECHANISM_CONSTRAINT_OBSERVED"
    finally:
        if stopped:
            compose_command(["start", "authority"], cwd=compose_dir)
            wait_ready()
    return observations


def main() -> None:
    parser = argparse.ArgumentParser(description="Physical authority stop/restart smoke")
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--output", required=True)
    options = parser.parse_args()
    if not options.execute_lab:
        parser.error("Physical mutation requires --execute-lab")
    token = os.getenv("LAB_CONTROL_TOKEN", "")
    outcome = run_outage(
        token, compose_dir=Path(__file__).resolve().parent,
        oracle_token=os.getenv("LAB_ORACLE_TOKEN", ""))
    Path(options.output).parent.mkdir(parents=True, exist_ok=True)
    Path(options.output).write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
