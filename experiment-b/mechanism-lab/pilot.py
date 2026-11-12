"""Execute a real, disposable Experiment B pilot against separate Docker processes.

Four candidate actions: resync_policy, restart_enforcer, gateway_restrict,
monitor_only. Resynchronization uses Kafka, restart uses Docker Compose,
gateway restriction changes a real reverse-proxy rule, and monitoring makes
no correction. The testbed is designed to exhibit actual network/uptime/TTL
effects rather than return labels from predefined failure-count formulas.

A fifth regression phase reintroduces a stale cache without a Kafka event.
The gateway verifier and separately deployed oracle take different paths.

This is a *mechanism-based pilot*, not a full scientific evaluation, trained
AI decision loop, authoritative production security service, or a claim that
all 1,200 planned trials have executed.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request

HOST = {
    "gateway": "http://127.0.0.1:18280",
    "authority": "http://127.0.0.1:18281",
    "enforcer-a": "http://127.0.0.1:18282",
    "enforcer-b": "http://127.0.0.1:18283",
    "enforcer-c": "http://127.0.0.1:18284",
    "enforcer-hidden": "http://127.0.0.1:18286",
    "oracle": "http://127.0.0.1:18285",
}
ENFORCERS = ("enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden")
ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")


def request(name: str, path: str, *, method: str = "GET",
            token: str | None = None, oracle: str | None = None,
            timeout: float = 1.5) -> tuple[int | None, dict, float]:
    """Issue an actual HTTP request and preserve failures and measured latency."""
    if name not in HOST or not path.startswith("/") or "://" in path:
        raise ValueError("Unexpected fixture destination")
    headers = {}
    if token:
        headers["X-Lab-Control"] = token
    if oracle:
        headers["X-Lab-Oracle"] = oracle
    begin = time.perf_counter()
    try:
        with urllib.request.urlopen(
            urllib.request.Request(HOST[name] + path, method=method, headers=headers,
                                   data=b"" if method == "POST" else None),
            timeout=timeout,
        ) as response:
            status, raw = response.status, response.read(16384)
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read(16384)
    except (OSError, TimeoutError):
        return None, {"error": "upstream unreachable"}, (time.perf_counter() - begin) * 1000
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError):
        payload = {"unparseable_response": True}
    return status, payload, (time.perf_counter() - begin) * 1000


def wait_ready(timeout: float = 150) -> None:
    """Wait for separate JVMs, gateway and oracle to become responsive."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        statuses = [request(name, "/healthz")[0] for name in (*ENFORCERS, "gateway", "oracle", "authority")]
        if all(value == 200 for value in statuses):
            return
        time.sleep(2)
    raise RuntimeError("Mechanism lab failed readiness; inspect docker compose logs")


def wait_for_target(name: str, timeout_seconds: float = 90) -> float:
    """Wait for an actual restarted JVM to serve readiness after measured downtime.

    Returns the time needed for the separately observed restart to recover.
    This delay is retained as an operational outcome and never discarded or
    silently represented as zero service disruption.
    """
    if name not in ENFORCERS:
        raise ValueError("Readiness target outside the declared lab inventory")
    started = time.perf_counter()
    while time.perf_counter() - started < timeout_seconds:
        status, _, _ = request(name, "/healthz")
        if status == 200:
            return time.perf_counter() - started
        time.sleep(0.5)
    raise RuntimeError("Enforcement process did not recover in declared window")


def setup_fault(control_token: str, *, ttl_ms: int, delay_ms: int,
                fault_target: str = "enforcer-b",
                fault_mode: str = "loss",
                oracle_token: str | None = None) -> None:
    """Reset all JVMs and inject a configured actual Kafka consumer fault.

    Faults are set on a named process before the policy event is published.
    Every execution must start from a clean state. Delayed callbacks from
    older trials are a known contamination risk until isolated group restarts
    and event quiescence are introduced; the collector flags affected runs.
    """
    status, _, _ = request("gateway", "/admin/restore", method="POST", token=control_token)
    if status != 200:
        raise RuntimeError("Gateway restore failed")
    for node in ENFORCERS:
        status, _, _ = request(node, f"/admin/reset/{ttl_ms}", method="POST", token=control_token)
        if status != 200:
            raise RuntimeError("Enforcer reset failed: " + node)
    status, _, _ = request("authority", "/control/reset", method="POST", token=control_token, timeout=10)
    if status != 202:
        raise RuntimeError("Authority reset was not acknowledged (HTTP " + str(status) + ")")
    # Each JVM reset advances its local epoch. Delayed callbacks from prior
    # trials are rejected under the same synchronized monitor. The oracle
    # then verifies that all four JVMs reached the same authority revision
    # before a new fault is injected. Quiescence checks below ensure that no
    # current-epoch callback is still scheduled at the start of measurement.
    if oracle_token is not None:
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            try:
                baseline = oracle_snapshot(oracle_token)
                desired = baseline["authority"]
                if (desired.get("revoked") is False
                        and all(t["admin"]["revision"] == desired["revision"]
                                and t["admin"]["revoked"] is False
                                and t["admin"].get("pending_scheduled_callbacks") == 0
                                and isinstance(t["admin"].get("experiment_epoch"), int)
                                for t in baseline["targets"])):
                    break
            except (RuntimeError, KeyError, TypeError):
                pass
            time.sleep(0.3)
        else:
            raise RuntimeError("No converged clean reset; abort before injecting fault")
    else:
        # Retained only for manually controlled legacy pilot callers.
        time.sleep(1.5)
    if fault_target not in ENFORCERS:
        raise ValueError("Unexpected fault target")
    if fault_mode not in {"loss", "delay", "duplicate", "reorder"}:
        raise ValueError("Unsupported Kafka fault mode")
    status, _, _ = request(fault_target, f"/admin/fault/{fault_mode}/{delay_ms}",
                           method="POST", token=control_token)
    if status != 200:
        raise RuntimeError("Consumer fault setup failed")
    status, _, _ = request("authority", "/control/revoke", method="POST", token=control_token, timeout=10)
    if status != 202:
        raise RuntimeError("Policy revocation rejected")
    time.sleep(1.2)


def gateway_probes(count: int = 3) -> list[dict]:
    """Record externally visible authorization decisions through the gateway."""
    return [
        {"http_status": status, "result": response}
        for status, response, _ in (request("gateway", "/protected") for _ in range(count))
    ]


def oracle_snapshot(oracle_token: str) -> dict:
    """Fetch restricted separately collected direct-cache and direct-probe truth."""
    status, payload, _ = request("oracle", "/oracle/observe", oracle=oracle_token, timeout=5)
    if status != 200 or not payload.get("inventory_complete"):
        safe_details = {
            "oracle_http": status,
            "authority_http": payload.get("authority_http"),
            "targets": [
                {"node": item.get("node"),
                 "admin_http": item.get("admin_http"),
                 "probe_http": item.get("direct_probe_http")}
                for item in payload.get("targets", [])
            ],
        }
        raise RuntimeError("No complete oracle snapshot: " + json.dumps(safe_details))
    return payload


def perform_action(action: str, control_token: str,
                   fault_target: str = "enforcer-b") -> None:
    """Execute exactly one allowlisted action without consulting oracle outcomes."""
    if fault_target not in ENFORCERS:
        raise ValueError("Unrecognized laboratory fault target")
    if action == "resync_policy":
        request(fault_target, "/admin/fault/none/0", method="POST", token=control_token)
        status, _, _ = request("authority", "/control/resync", method="POST", token=control_token, timeout=10)
        if status != 202:
            raise RuntimeError("Resynchronization not published")
    elif action == "restart_enforcer":
        completed = subprocess.run(
            ["docker", "compose", "restart", fault_target],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            check=False
        )
        if completed.returncode != 0:
            raise RuntimeError("Real Docker restart failed: " + completed.stderr[-500:])
    elif action == "gateway_restrict":
        status, _, _ = request("gateway", "/admin/restrict", method="POST", token=control_token)
        if status != 200:
            raise RuntimeError("Gateway restriction failed")
    elif action == "monitor_only":
        return
    else:
        raise ValueError("Unrecognized corrective action")


def measure_under_load(action: str, control_token: str, *,
                       requests_per_second: int = 30, duration_seconds: float = 5,
                       fault_target: str = "enforcer-b") -> dict:
    """Apply the action during sustained, concurrent real HTTP request traffic.

    Uses a monotonic request schedule and a thread pool. The measured rate,
    observed HTTP errors, and request latencies are retained independently
    from the operator's requested load. Never invent failure counts from
    configuration variables.
    """
    if not 1 <= requests_per_second <= 100 or not 2 <= duration_seconds <= 30:
        raise ValueError("Pilot workload outside declared safe limits")
    start = time.perf_counter()
    outcomes = []
    future_action = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        scheduled = []
        count = int(requests_per_second * duration_seconds)
        for i in range(count):
            if i == count // 4:
                future_action = pool.submit(perform_action, action, control_token, fault_target)
            deadline = start + i / requests_per_second
            delay = deadline - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            scheduled.append(pool.submit(request, "gateway", "/legitimate"))
        for result in scheduled:
            status, _, latency = result.result(timeout=20)
            outcomes.append({"http_status": status, "latency_ms": latency})
        if future_action is not None:
            future_action.result(timeout=125)
    elapsed = time.perf_counter() - start
    failures = sum(item["http_status"] != 200 for item in outcomes)
    latencies = sorted(item["latency_ms"] for item in outcomes)
    return {
        "requested_rps": requests_per_second,
        "measured_rps": len(outcomes) / elapsed,
        "duration_seconds": elapsed,
        "attempts": len(outcomes),
        "non_200_requests": failures,
        "latency_p95_ms": latencies[max(0, int(0.95 * len(latencies)) - 1)],
        "request_source": "concurrent_external_gateway_http",
    }


def run_case(action: str, control_token: str, oracle_token: str,
             *, ttl_ms: int = 30000, rps: int = 30,
             fault_mode: str = "loss", fault_target: str = "enforcer-b",
             delay_ms: int = 200, duration_seconds: float = 5) -> dict:
    """Reset all processes, inject event loss and measure one candidate action."""
    setup_fault(control_token, ttl_ms=ttl_ms, delay_ms=delay_ms,
                fault_target=fault_target, fault_mode=fault_mode,
                oracle_token=oracle_token)
    before_probes = gateway_probes()
    before_truth = oracle_snapshot(oracle_token)
    operations = measure_under_load(action, control_token, requests_per_second=rps,
                                    duration_seconds=duration_seconds,
                                    fault_target=fault_target)
    time.sleep(0.7)
    after_probes = gateway_probes()
    recovery_wait_seconds = (
        wait_for_target(fault_target) if action == "restart_enforcer" else 0.0
    )
    after_truth = oracle_snapshot(oracle_token)
    return {
        "case": "experiment-b-kafka-revocation",
        "fault_mode": fault_mode,
        "fault_target": fault_target,
        "cache_ttl_ms": ttl_ms,
        "event_delay_ms": delay_ms,
        "action": action,
        "before": {"verifier_gateway_probes": before_probes,
                   "oracle": before_truth},
        "after": {"verifier_gateway_probes": after_probes,
                  "oracle": after_truth},
        "operations": {**operations, "post_window_recovery_wait_seconds": recovery_wait_seconds},
        "evaluation_only": True,
        "no_ai_model_invoked": True,
        "verification_scope_complete": False,
        "limitations": [
            "Three actual enforcement processes; no independent production inventory",
            "Gateway probes are intentionally partial and cannot certify global VERIFIED",
            "Admin state is reported by the target; direct active oracle probes corroborate it",
        ],
    }


def run_regression(control_token: str, oracle_token: str) -> dict:
    """Inject a silent cache regression and compare observer paths after a clean fix."""
    setup_fault(control_token, ttl_ms=30000, delay_ms=0,
                oracle_token=oracle_token)
    request("enforcer-b", "/admin/fault/none/0", method="POST", token=control_token)
    request("authority", "/control/resync", method="POST", token=control_token, timeout=10)
    time.sleep(0.7)
    first = oracle_snapshot(oracle_token)
    status, _, _ = request("enforcer-b", "/admin/silent-regression",
                           method="POST", token=control_token)
    if status != 200:
        raise RuntimeError("Silent regression injection failed")
    time.sleep(0.15)
    return {
        "pre_regression_oracle": first,
        "post_regression_gateway_probes": gateway_probes(),
        "post_regression_oracle": oracle_snapshot(oracle_token),
        "fault_triggered_without_authority_change_event": True,
    }



def run_hidden_target_case(control_token: str, oracle_token: str) -> dict:
    """Show that gateway-only checks miss an enforcement point outside the route.

    The shadow process is in the oracle's independently declared inventory but
    deliberately not included in the gateway's upstream list. A lost policy
    event in that process leaves revoked access permitted despite all three
    normal gateway paths denying it. Proper assurance must abstain without
    independent inventory reconciliation.
    """
    setup_fault(control_token, ttl_ms=30000, delay_ms=0,
                fault_target="enforcer-hidden", oracle_token=oracle_token)
    gateway = gateway_probes(count=6)
    oracle = oracle_snapshot(oracle_token)
    return {
        "gateway_observations": gateway,
        "oracle": oracle,
        "gateway_only_looks_clean": all(o["http_status"] == 403 for o in gateway),
        "full_scope_verification_status": "INDETERMINATE",
        "reason": "Gateway route omits a known enforcement process",
    }

def main() -> None:
    """Run an explicitly opted-in disposable pilot and retain real observations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--actions", nargs="+", choices=ACTIONS, default=list(ACTIONS))
    parser.add_argument("--rps", type=int, default=30)
    parser.add_argument("--output", type=Path, default=Path("reports/mechanism-pilot.json"))
    args = parser.parse_args()
    if not args.execute_lab:
        parser.error("Laboratory mutation requires --execute-lab")
    control = os.getenv("LAB_CONTROL_TOKEN")
    oracle = os.getenv("LAB_ORACLE_TOKEN")
    internal = os.getenv("LAB_INTERNAL_TOKEN")
    if not control or not oracle or not internal or len({control, oracle, internal}) != 3:
        parser.error("Set three distinct nonempty disposable laboratory credentials")
    wait_ready()
    result = {
        "schema_version": "experiment-b-mechanism-pilot/1",
        "cases": [run_case(action, control, oracle, rps=args.rps)
                  for action in args.actions],
        "silent_regression": run_regression(control, oracle),
        "omitted_enforcement_point": run_hidden_target_case(control, oracle),
        "not_a_trained_ai_experiment": True,
        "not_full_1200_trial_dataset": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print("Collected real multi-process pilot observations:", args.output)


if __name__ == "__main__":
    main()
