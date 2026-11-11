"""Collect measured, separately stored Experiment B mechanism-lab outcomes.

This is not the old single-process formula fixture. Every executed trial
calls the real Kafka-backed authority/enforcers/gateway/oracle pilot. Planned
trials are never treated as completed observations. The collector does not
train a model and never passes oracle state to a pre-action predictor.

Example, from the mechanism-lab directory, with Compose already running:
  python plan.py --output plans/mechanism
  python collect.py --execute-lab --manifest plans/mechanism \
      --output results/mechanism --limit 4

A full 1,200-run campaign is expensive, requires manual experiment supervision,
and must not be represented as performed until all records have been collected
and reviewed for delayed-event carryover and scope completeness.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from plan import ACTIONS, create_plan, validate_plan
from pilot import run_case, wait_ready


def load_plan(directory: Path) -> tuple[list[dict], list[dict]]:
    """Read the complete plan and verify configuration and action partition integrity."""
    configs = [json.loads(v) for v in (directory / "configurations.jsonl").read_text(
        encoding="utf-8").splitlines() if v.strip()]
    trials = [json.loads(v) for v in (directory / "trials.jsonl").read_text(
        encoding="utf-8").splitlines() if v.strip()]
    validate_plan(configs, trials)
    return configs, trials


def assess_gateway(probes: list[dict]) -> tuple[str, str]:
    """Assess only externally exercised gateway paths, without oracle leakage.

    A direct HTTP 200 for revoked access refutes correct authorization.
    A set of HTTP 403 responses is insufficient to establish the completeness
    of the four-process inventory because the gateway omits one process.
    Timeout and unexplained response codes require indeterminacy.
    """
    codes = [item.get("http_status") for item in probes]
    if 200 in codes:
        return "NOT VERIFIED", "Revoked access was actually allowed"
    return "INDETERMINATE", "Gateway coverage does not include the full inventory"


def source_commit() -> str:
    """Resolve the exact reviewed source revision; never invent provenance.

    GitHub Actions supplies GITHUB_SHA. A local clone uses git rev-parse HEAD.
    If neither is available, collection stops rather than claiming results
    without a reproducible version identifier.
    """
    source = os.environ.get("GITHUB_SHA")
    if source:
        return source
    repository = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=5, check=True,
    ).stdout.strip()
    if len(result) != 40 or any(char not in "0123456789abcdef" for char in result):
        raise ValueError("Could not establish a valid source commit")
    return result


def separate_records(config: dict, trial: dict, observed: dict) -> dict[str, dict]:
    """Partition one executed trial into four independently meaningful records.

    Pre-action features contain only trial settings and gateway-observable
    security data; the oracle is never copied into them. Oracle truth includes
    separately collected direct target probes plus cache state and must be
    protected from feature generation. The measured operational outcome
    includes actual HTTP status counts rather than a formula-defined label.
    """
    if observed["action"] != trial["action_id"] or observed["fault_mode"] != config["fault_mode"]:
        raise ValueError("Collected case does not match the registered action/fault")
    before = observed["before"]
    after = observed["after"]
    health = observed["operations"]
    oracle = after["oracle"]
    if not oracle.get("inventory_complete") or oracle.get("all_revoked_access_denied") is None:
        raise ValueError("Oracle cannot establish complete applicable scope")
    if health.get("attempts", 0) <= 0 or not (0 <= health.get("non_200_requests", -1) <= health["attempts"]):
        raise ValueError("Actual measured service-health denominator is missing")
    verification, reason = assess_gateway(after["verifier_gateway_probes"])
    base = {
        "run_id": trial["run_id"],
        "configuration_id": trial["configuration_id"],
        "partition": trial["partition"],
        "action_id": trial["action_id"],
        "repeat": trial["repeat"],
        "initial_state_seed": trial["initial_state_seed"],
        "experiment_type": "real_kafka_multijvm_lab",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": source_commit(),
    }
    return {
        "pre_action": {
            **base,
            "features": {k: config[k] for k in (
                "fault_mode", "fault_target", "cache_ttl_ms", "event_delay_ms",
                "requested_rps", "measurement_seconds", "visible_enforcement_processes",
                "oracle_inventory_processes",
            )},
            "external_deny_observations": before["verifier_gateway_probes"],
            "model_prediction_recorded": False,
            "oracle_features_excluded": True,
        },
        "verification": {
            **base,
            "outcome": verification,
            "reason": reason,
            "observations": after["verifier_gateway_probes"],
            "independent_inventory_reconciled": False,
            "verification_did_not_read_oracle": True,
        },
        "operations": {
            **base,
            "health": health,
            "failed_requests": health["non_200_requests"],
            "observed_requests": health["attempts"],
            "observed_rps": health["measured_rps"],
            "latency_p95_ms": health["latency_p95_ms"],
            "post_window_recovery_wait_seconds": health["post_window_recovery_wait_seconds"],
            "label_source": "measured_concurrent_http",
        },
        "oracle": {
            **base,
            "before": before["oracle"],
            "after": oracle,
            "actual_revoked_access_denied": oracle["all_revoked_access_denied"],
            "target_direct_probes": oracle["targets"],
            "oracle_role": "separate_process_admin_plus_direct_probe",
            "not_cryptographically_attested": True,
        },
    }


def write_trial_records(output: Path, records: dict[str, dict]) -> None:
    """Write four non-overwriting files and use owner-only oracle permissions.

    This is a research artifact boundary, not a transactional distributed
    write. A crash after writing some records leaves an incomplete trial;
    downstream training must reject that incomplete trial rather than impute
    any missing labels. Existing run IDs are never silently overwritten.
    """
    run_id = records["pre_action"]["run_id"]
    if any(record["run_id"] != run_id for record in records.values()):
        raise ValueError("Mismatched run IDs")
    paths = [output / name / (run_id + ".json") for name in records]
    if any(path.exists() for path in paths):
        raise FileExistsError("Partial or completed record already exists: " + run_id)
    for kind, data in records.items():
        folder = output / kind
        folder.mkdir(parents=True, exist_ok=True)
        if kind == "oracle":
            folder.chmod(0o700)
        path = folder / (run_id + ".json")
        file_descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")


def collect_batch(configs: list[dict], trials: list[dict], output: Path,
                  control: str, oracle: str, *, offset: int, limit: int) -> dict:
    """Perform only a caller-selected bounded batch of real laboratory replays."""
    if offset < 0 or not 1 <= limit <= 1200 or offset + limit > len(trials):
        raise ValueError("Requested experiment range outside preregistered manifest")
    by_id = {c["configuration_id"]: c for c in configs}
    completed = []
    wait_ready()
    for trial in trials[offset:offset + limit]:
        conf = by_id[trial["configuration_id"]]
        measured = run_case(
            trial["action_id"], control, oracle,
            ttl_ms=conf["cache_ttl_ms"],
            rps=conf["requested_rps"],
            fault_mode=conf["fault_mode"],
            fault_target=conf["fault_target"],
            delay_ms=conf["event_delay_ms"],
            duration_seconds=conf["measurement_seconds"],
        )
        records = separate_records(conf, trial, measured)
        write_trial_records(output, records)
        completed.append(trial["run_id"])
    return {"executed_count": len(completed), "run_ids": completed,
            "partial_campaign": len(completed) < len(trials),
            "generated_from_actual_http": True, "model_trained": False}


def main() -> None:
    """Require explicit opt-in, distinct credentials and a bounded execution range."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=4)
    args = parser.parse_args()
    if not args.execute_lab:
        parser.error("No laboratory changes allowed without --execute-lab")
    tokens = [os.environ.get(key) for key in (
        "LAB_CONTROL_TOKEN", "LAB_ORACLE_TOKEN", "LAB_INTERNAL_TOKEN")]
    if not all(tokens) or len(set(tokens)) != 3:
        parser.error("Require three distinct nonempty disposable laboratory tokens")
    configs, trials = load_plan(args.manifest)
    result = collect_batch(configs, trials, args.output, tokens[0], tokens[1],
                           offset=args.offset, limit=args.limit)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
