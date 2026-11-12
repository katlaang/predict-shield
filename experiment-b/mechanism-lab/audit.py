"""Read-only progress and integrity audit of measured Experiment B trials.

An experiment plan is NOT an observed outcome. This audit distinguishes
missing, complete, partially written, corrupt, and incompatible trial records
without making security or model-performance claims. It does not read model
predictions, run Docker, query the oracle endpoint, or mutate source files.

Usage, from experiment-b/mechanism-lab:
    python audit.py --manifest plans/mechanism --records results/mechanism
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from collect import load_plan

STREAMS = ("pre_action", "verification", "operations", "oracle")
SCHEMA = "predict-shield/mechanism-campaign-audit/1"


def plan_fingerprint(configurations: list[dict], trials: list[dict]) -> str:
    """Hash exact registered configurations and trials, including split assignments.

    This digest can be retained with completed batches. It identifies the
    intended experiment protocol and prevents resumption against a silently
    modified plan. It does not attest that any action has been performed.
    """
    payload = json.dumps({"configurations": configurations, "trials": trials},
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def inspect_trial(trial: dict, record_root: Path) -> tuple[str, str]:
    """Classify one trial by four matching, independently recorded artifacts.

    Returns (status, non-sensitive explanation). A complete record must
    match its registered run ID, configuration group, partition, action,
    repeat number and initial-state seed in every stream. Missing or
    contradictory oracle truth, invalid HTTP denominators, or unexpected
    experimental source causes an invalid classification. This function
    never emits oracle target state in diagnostic messages.
    """
    items: dict[str, dict] = {}
    found = 0
    for stream in STREAMS:
        path = record_root / stream / (trial["run_id"] + ".json")
        if not path.is_file():
            continue
        found += 1
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            return "invalid", f"{stream} is unreadable or not valid JSON"
        expected = {
            "run_id": trial["run_id"],
            "configuration_id": trial["configuration_id"],
            "partition": trial["partition"],
            "action_id": trial["action_id"],
            "repeat": trial["repeat"],
            "initial_state_seed": trial["initial_state_seed"],
            "experiment_type": "real_kafka_multijvm_lab",
        }
        if any(value.get(key) != expected_value
               for key, expected_value in expected.items()):
            return "invalid", f"{stream} record provenance disagrees with the manifest"
        items[stream] = value
    if found == 0:
        return "missing", "no measured records"
    if found != len(STREAMS):
        return "partial", "incomplete four-stream trial; do not rerun without repair"
    pre, verification, operations, oracle = (items[k] for k in STREAMS)
    if pre.get("oracle_features_excluded") is not True or pre.get(
            "model_prediction_recorded") is not False:
        return "invalid", "pre-action feature boundary was violated"
    if verification.get("outcome") not in ("INDETERMINATE", "NOT VERIFIED"):
        return "invalid", "unjustified gateway assurance verdict"
    after = oracle.get("after")
    if (oracle.get("oracle_role") != "separate_process_admin_plus_direct_probe"
            or not isinstance(after, dict) or not after.get("inventory_complete")
            or type(after.get("all_revoked_access_denied")) is not bool):
        return "invalid", "no complete independent lab oracle observation"
    n = operations.get("observed_requests")
    failed = operations.get("failed_requests")
    if (type(n) is not int or n <= 0 or type(failed) is not int
            or not 0 <= failed <= n):
        return "invalid", "service-health count/denominator invalid"
    commits = {items[s].get("source_commit") for s in STREAMS}
    if len(commits) != 1 or not next(iter(commits)):
        return "invalid", "source revision mismatch between trial streams"
    return "complete", "four measured streams with coherent provenance"


def audit_campaign(configurations: list[dict], trials: list[dict],
                   record_root: Path) -> dict:
    """Return independent counts by status and split, without revealing oracle data.

    The report can support checkpoints and controlled resumption. It does not
    claim that training can start unless every registered trial is complete
    and there are no unknown records. False positives are avoided by checking
    both the declared 1,200 run IDs and any extra records.
    """
    known = {trial["run_id"] for trial in trials}
    summaries = Counter()
    by_split: dict[str, Counter] = {split: Counter()
                                    for split in ("train", "calibration", "test")}
    problems: list[dict] = []
    observed_source_revisions: set[str] = set()
    for trial in trials:
        status, why = inspect_trial(trial, record_root)
        summaries[status] += 1
        by_split[trial["partition"]][status] += 1
        if status == "complete":
            metadata = json.loads((record_root / "pre_action" /
                                   (trial["run_id"] + ".json")).read_text(encoding="utf-8"))
            observed_source_revisions.add(metadata["source_commit"])
        if status in ("partial", "invalid") and len(problems) < 25:
            problems.append({"run_id": trial["run_id"], "status": status, "reason": why})
    unknown = []
    for stream in STREAMS:
        for file in (record_root / stream).glob("*.json"):
            if file.stem not in known:
                unknown.append({"stream": stream, "record_name": file.name})
    return {
        "schema": SCHEMA,
        "plan_sha256": plan_fingerprint(configurations, trials),
        "planned_trials": len(trials),
        "complete": summaries["complete"],
        "missing": summaries["missing"],
        "partial": summaries["partial"],
        "invalid": summaries["invalid"],
        "unexpected_files": len(unknown),
        "distinct_source_revisions": len(observed_source_revisions),
        "single_source_revision": len(observed_source_revisions) <= 1,
        "by_split": {
            split: {k: count[k] for k in
                    ("complete", "missing", "partial", "invalid")}
            for split, count in by_split.items()
        },
        "sample_problems": problems,
        "sample_unexpected_files": unknown[:10],
        "ready_for_training": (
            summaries["complete"] == len(trials)
            and not any(summaries[status] for status in ("missing", "partial", "invalid"))
            and not unknown
            and len(observed_source_revisions) == 1
        ),
        "caution": "Completed laboratory records do not establish real-world model efficacy",
    }


def main() -> None:
    """Validate an existing plan, audit records, and optionally write a report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    config, trials = load_plan(args.manifest)
    report = audit_campaign(config, trials, args.records)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    if (report["partial"] or report["invalid"] or report["unexpected_files"]
            or not report["single_source_revision"]):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
