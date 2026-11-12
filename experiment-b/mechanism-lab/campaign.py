"""Controlled, resumable Experiment B collection on the real Kafka/JVM laboratory.

A research campaign is a sequence of *measured* actions, not a JSON manifest.
This runner never manufactures labels, replays a completed trial, skips a
partial record, or silently changes a registered experiment. A maximum of
twelve trials can be executed per explicit invocation. Complete four-stream
records are reused only after independent integrity validation.

Usage, inside experiment-b/mechanism-lab:
  python plan.py --output plans/mechanism
  python campaign.py --plan plans/mechanism --records results/mechanism --audit
  python campaign.py --plan plans/mechanism --records results/mechanism \
      --execute-lab --start 0 --max-trials 4
  python campaign.py --plan plans/mechanism --records results/mechanism \
      --execute-lab --resume --max-trials 4

This module does not run in the background. It never uploads oracle data to
GitHub or interprets a successful action acknowledgment as verification.
"""
from __future__ import annotations

import argparse
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from audit import audit_campaign, inspect_trial, plan_fingerprint
from collect import load_plan, separate_records, source_commit, write_trial_records
from pilot import run_case, wait_ready

FINGERPRINT = "registered-plan.sha256"
SOURCE_REVISION = "registered-source.sha"
LOCK_NAME = ".campaign.lock"


@contextmanager
def exclusive_lock(root: Path):
    """Prevent two concurrent writers from operating on the same lab outputs.

    Lock creation is atomic. A crash leaves a lock that must be investigated
    manually, not silently broken. This prevents simultaneous trial resets
    and split observations. A lock file is a process-exclusivity aid, not a
    cryptographic attestation or external distributed lock.
    """
    root.mkdir(parents=True, exist_ok=True)
    path = root / LOCK_NAME
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "pid": os.getpid(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }) + "\n")
        yield
    finally:
        path.unlink(missing_ok=True)


def register_plan(root: Path, configs: list[dict], trials: list[dict]) -> str:
    """Pin the exact plan digest before any observed trial is written.

    An existing digest must match exactly. A different seed, split, or
    registered configuration requires a new output directory, not an
    in-place overwrite or attempt to reinterpret old measurements.
    """
    fingerprint = plan_fingerprint(configs, trials)
    file = root / FINGERPRINT
    if file.exists():
        if file.read_text(encoding="ascii").strip() != fingerprint:
            raise ValueError("Registered experiment plan differs from existing campaign")
    else:
        fd = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(fingerprint + "\n")
    return fingerprint


def register_source(root: Path, revision: str) -> None:
    """Require every experiment in this campaign to use one fixed source commit.

    This prevents a resumed experiment from silently mixing different
    deployed enforcement, collector or oracle logic after a code update.
    A genuine protocol revision needs a new result directory, not an
    in-place continuation masquerading as the same trial campaign.
    """
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError("Source revision must be an exact Git commit hash")
    file = root / SOURCE_REVISION
    if file.exists():
        if file.read_text(encoding="ascii").strip() != revision:
            raise ValueError("Source revision changed; start a new experimental campaign")
    else:
        fd = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(revision + "\n")


def next_trials(trials: list[dict], records: Path, *, start: int = 0,
                max_trials: int = 4, resume: bool = False) -> list[dict]:
    """Choose a limited set of missing runs without accepting partial records.

    A requested resume scans from the specified first index and skips only
    records verified complete by the four-stream integrity audit. Without
    resume, encountering an already executed run fails rather than overwrites
    it. Invalid or partial runs always stop the campaign for investigation.
    """
    if not 0 <= start < len(trials) or not 1 <= max_trials <= 12:
        raise ValueError("Invalid registered start index or per-invocation bound")
    selected = []
    for trial in trials[start:]:
        status, reason = inspect_trial(trial, records)
        if status in ("partial", "invalid"):
            raise RuntimeError(f"Cannot continue at {trial['run_id']}: {reason}")
        if status == "complete":
            if resume:
                continue
            raise FileExistsError("Run already complete: " + trial["run_id"])
        selected.append(trial)
        if len(selected) == max_trials:
            break
    return selected


def run_batch(configs: list[dict], trials: list[dict], records: Path,
              control_token: str, oracle_token: str, *,
              start: int = 0, max_trials: int = 4,
              resume: bool = False) -> dict:
    """Execute and immediately validate each bounded Kafka/JVM replay.

    The same plan and output directory are locked before a test starts.
    Each run sets the actual JVM fault, initiates the action, observes HTTP
    effects, collects the separate oracle, writes distinct streams, and
    verifies their metadata. Results are retained on the caller's machine,
    never generated inside this module or uploaded to source control.
    """
    with exclusive_lock(records):
        digest = register_plan(records, configs, trials)
        register_source(records, source_commit())
        audit = audit_campaign(configs, trials, records)
        if (audit["partial"] or audit["invalid"] or audit["unexpected_files"]
                or not audit["single_source_revision"]):
            raise RuntimeError("Existing campaign records fail independent integrity audit")
        work = next_trials(trials, records, start=start,
                           max_trials=max_trials, resume=resume)
        by_id = {cfg["configuration_id"]: cfg for cfg in configs}
        completed = []
        if work:
            wait_ready()
        for trial in work:
            cfg = by_id[trial["configuration_id"]]
            observation = run_case(
                trial["action_id"], control_token, oracle_token,
                ttl_ms=cfg["cache_ttl_ms"], rps=cfg["requested_rps"],
                fault_mode=cfg["fault_mode"], fault_target=cfg["fault_target"],
                delay_ms=cfg["event_delay_ms"],
                duration_seconds=cfg["measurement_seconds"],
                gateway_includes_hidden=cfg.get("gateway_includes_hidden", True),
            )
            records_by_stream = separate_records(cfg, trial, observation)
            write_trial_records(records, records_by_stream)
            status, explanation = inspect_trial(trial, records)
            if status != "complete":
                raise RuntimeError("Written run failed independent audit: " + explanation)
            completed.append(trial["run_id"])
        after = audit_campaign(configs, trials, records)
        return {
            "plan_sha256": digest,
            "newly_executed_trials": len(completed),
            "new_run_ids": completed,
            "campaign_complete": after["ready_for_training"],
            "total_completed": after["complete"],
            "total_remaining": after["missing"],
            "partial": after["partial"],
            "invalid": after["invalid"],
            "scientific_result_established": False,
        }


def main() -> None:
    """Run a read-only audit by default or an explicitly authorized small batch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--audit", action="store_true",
                        help="Read-only status; never run any Docker actions")
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--max-trials", type=int, default=4)
    args = parser.parse_args()
    configs, trials = load_plan(args.plan)
    if args.audit and args.execute_lab:
        parser.error("--audit and --execute-lab are mutually exclusive")
    if not args.execute_lab:
        result = audit_campaign(configs, trials, args.records)
        print(json.dumps(result, indent=2))
        return
    credentials = [os.environ.get(name) for name in (
        "LAB_CONTROL_TOKEN", "LAB_ORACLE_TOKEN", "LAB_INTERNAL_TOKEN"
    )]
    if not all(credentials) or len(set(credentials)) != len(credentials):
        parser.error("Require three distinct nonempty disposable lab credentials")
    result = run_batch(configs, trials, args.records, credentials[0],
                       credentials[1], start=args.start,
                       max_trials=args.max_trials, resume=args.resume)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
