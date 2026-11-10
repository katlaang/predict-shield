"""Opt-in Experiment B localhost data collector, never a production action runner.

Reads a generated 100x4x3 manifest. Executes selected candidate actions from
fresh scenario resets in the Java laboratory. Persists four distinct artifacts:

  pre_action.jsonl : observed pre-action probe inputs; NO oracle labels
  verification.jsonl: external authorization check outcome (not global truth)
  operations.jsonl: measured legitimate-traffic HTTP failures/latency
  oracle/private.jsonl: lab-only internal truth from a separate oracle token

The present Java fixture puts the oracle in the SAME process as the targets.
This is controlled laboratory truth, not an independently hosted oracle.
Its records must never be fed into model prediction inputs or validation
features. All configuration samples and actions remain synthetic laboratory
scenarios. Results are real HTTP observations of those simulated mechanisms,
not evidence about operational systems.

Example:
    export LAB_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
    export LAB_ORACLE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
    docker compose up --build -d
    python generate_manifest.py --out generated
    python collect_training_data.py --execute-lab --manifest generated --out results
"""
from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import time
import urllib.error
import urllib.request
from pathlib import Path

from generate_manifest import ACTIONS, validate_plan

BASE_URL = "http://127.0.0.1:18081"
MEASUREMENT_REQUESTS = 40


def http_request(path: str, *, method: str = "GET", token: str | None = None,
                 oracle_token: str | None = None, payload: dict | None = None) -> tuple[int, dict, float]:
    """Make a bounded localhost-only HTTP request and measure elapsed latency."""
    if not path.startswith("/lab/scenario/") or "?" in path or "#" in path:
        raise ValueError("Only fixed lab scenario paths are allowed")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Lab-Token"] = token
    if oracle_token:
        headers["X-Oracle-Token"] = oracle_token
    data = json.dumps(payload).encode("utf-8") if payload is not None else (
        b"" if method == "POST" else None
    )
    request = urllib.request.Request(
        BASE_URL + path, method=method, headers=headers, data=data
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            body = response.read(65536)
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read(65536)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    try:
        content = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        content = {"unparseable": True}
    return status, content, elapsed_ms


def lab_scenario(configuration: dict, trial: dict) -> dict:
    """Map a reproducible trial manifest into the Java scenario DTO."""
    return {
        "runId": trial["run_id"],
        "faultFamily": configuration["fault_family"],
        "enforcementPoints": configuration["enforcement_points"],
        "stalePoints": configuration["stale_points"],
        "cacheTtlMs": configuration["cache_ttl_ms"],
        "propagationDelayMs": configuration["propagation_delay_ms"],
        "trafficRps": configuration["traffic_rps"],
        "dependencyDepth": configuration["dependency_depth"],
        "redundancy": configuration["redundancy"],
        "seed": trial["trial_seed"],
    }


def probe_all(count: int) -> tuple[list[dict], str]:
    """Check every declared logical target; never use the fixture's oracle."""
    observations = []
    for point in range(count):
        try:
            status, _, ms = http_request("/lab/scenario/probe/" + str(point))
            observations.append({"target": point, "http_status": status,
                                 "latency_ms": ms})
        except (OSError, TimeoutError, ValueError) as error:
            observations.append({"target": point, "http_status": None,
                                 "error": type(error).__name__})
    if any(o.get("http_status") == 200 for o in observations):
        return observations, "NOT VERIFIED"
    # The declared number of targets is supplied by the generator, not
    # reconciled from two independent inventory sources. Even when every
    # declared target returns 403, global VERIFIED is not warranted.
    return observations, "INDETERMINATE"


def measure_legitimate_requests() -> dict:
    """Measure 40 actual HTTP responses; retain latency and failure counts.

    This initial fixture does not reproduce the configured target traffic_rps
    exactly. Record observed request rate rather than treating the requested
    load parameter as a measured workload.
    """
    latencies_ms = []
    failed = 0
    started = time.perf_counter()
    for _ in range(MEASUREMENT_REQUESTS):
        try:
            status, _, latency = http_request("/lab/scenario/legitimate")
            latencies_ms.append(latency)
            if status != 200:
                failed += 1
        except (OSError, TimeoutError, ValueError):
            failed += 1
    elapsed = max(time.perf_counter() - started, 1e-9)
    latency_p95 = None
    if latencies_ms:
        ordered = sorted(latencies_ms)
        latency_p95 = ordered[math.ceil(0.95 * len(ordered)) - 1]
    return {
        "requests_attempted": MEASUREMENT_REQUESTS,
        "failed_or_non_200_requests": failed,
        "observed_requests_per_second": MEASUREMENT_REQUESTS / elapsed,
        "latency_p95_ms": latency_p95,
        "measurement_complete": len(latencies_ms) == MEASUREMENT_REQUESTS,
        "measurement_source": "external_python_http_requests",
        "planned_traffic_rps_not_enforced": True,
    }


def execute_trial(configuration: dict, trial: dict, lab_token: str,
                  oracle_token: str) -> dict[str, dict]:
    """Run one isolated controlled action and gather separately typed records.

    An oracle result is retrieved only after normal verification and service
    measurement. It does not influence the action or the verifier. The runner
    may see the oracle token, so a future revision must move the collector to
    a separately administered identity and process.
    """
    scenario = lab_scenario(configuration, trial)
    status, _, _ = http_request("/lab/scenario/reset", method="POST",
                                token=lab_token, payload=scenario)
    if status != 200:
        raise RuntimeError("Lab reset rejected")
    before, before_assessment = probe_all(configuration["enforcement_points"])
    status, ack, action_latency = http_request(
        "/lab/scenario/action/" + trial["action_id"], method="POST", token=lab_token
    )
    if status != 200:
        raise RuntimeError("Lab action rejected; result must not be labeled")
    after, after_assessment = probe_all(configuration["enforcement_points"])
    health = measure_legitimate_requests()
    oracle_status, oracle_state, _ = http_request(
        "/lab/scenario/oracle", oracle_token=oracle_token
    )
    if oracle_status != 200 or oracle_state.get("run_id") != trial["run_id"]:
        raise RuntimeError("Oracle truth unavailable or does not match run ID")
    common = {
        "run_id": trial["run_id"],
        "configuration_id": trial["configuration_id"],
        "repeat": trial["repeat"],
        "split": trial["split"],
        "action_id": trial["action_id"],
        "trial_seed": trial["trial_seed"],
    }
    return {
        "pre_action": {
            **common, "features": configuration,
            "external_deny_observations": before,
            "pre_action_assessment": before_assessment,
            "model_prediction_recorded": False,
        },
        "verification": {
            **common, "post_action_external_deny_observations": after,
            "outcome": after_assessment,
            "scope_inventory_reconciled": False,
            "reason": ("Current declared-scope refutation" if after_assessment == "NOT VERIFIED"
                       else "Two-source inventory completeness not established"),
            "status": "LAB_PROBE_ASSESSMENT_NOT_FULL_ASSURANCE",
        },
        "operations": {
            **common, "action_acknowledged": bool(ack.get("acknowledged")),
            "action_latency_ms": action_latency,
            "service_health": health, "measured_not_predicted": True,
        },
        "oracle": {
            **common, "scope": oracle_state.get("scope"),
            "actual_authorization_allowed": oracle_state.get("authorization_allowed"),
            "all_revoked_access_denied": oracle_state.get("all_revoked_access_denied"),
            "oracle_kind": "internal_java_fixture_separately_credentialed_same_process",
            "not_independently_hosted": True,
        },
    }


def write_records(output: Path, values: dict[str, dict]) -> None:
    """Create per-run JSON records, with separate private oracle permissions."""
    for kind, value in values.items():
        directory = output / ("oracle" if kind == "oracle" else kind)
        directory.mkdir(parents=True, exist_ok=True)
        if kind == "oracle":
            directory.chmod(0o700)
        destination = directory / (value["run_id"] + ".json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(destination, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")


def load_manifest(path: Path) -> tuple[list[dict], list[dict]]:
    """Read, validate and refuse malformed configuration/trial plans."""
    configs = [json.loads(line) for line in (path / "configurations.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]
    trials = [json.loads(line) for line in (path / "trials.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]
    validate_plan(configs, trials)
    return configs, trials


def main() -> None:
    """Require explicit opt-in, scoped credentials and a bounded trial count."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--manifest", type=Path, default=Path("experiment-b/generated"))
    parser.add_argument("--out", type=Path, default=Path("experiment-b/results"))
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=4)
    args = parser.parse_args()
    if not args.execute_lab:
        parser.error("No actions executed; --execute-lab is mandatory")
    if args.offset < 0 or args.limit < 1 or args.limit > 1200:
        parser.error("Invalid trial offset or limit")
    token = os.environ.get("LAB_TOKEN")
    oracle_token = os.environ.get("LAB_ORACLE_TOKEN")
    if not token or not oracle_token or token == oracle_token:
        parser.error("Provide distinct nonempty LAB_TOKEN and LAB_ORACLE_TOKEN")
    configs, trials = load_manifest(args.manifest)
    config_by_id = {c["configuration_id"]: c for c in configs}
    batch = trials[args.offset:args.offset + args.limit]
    if not batch:
        parser.error("No planned trials at this offset")
    completed = 0
    for trial in batch:
        records = execute_trial(config_by_id[trial["configuration_id"]],
                                trial, token, oracle_token)
        write_records(args.out, records)
        completed += 1
    print(json.dumps({
        "status": "LAB_TRIALS_EXECUTED",
        "completed": completed,
        "disclaimer": "Fixture-derived labels, not real-world efficacy",
        "output": str(args.out),
    }, indent=2))


if __name__ == "__main__":
    main()
