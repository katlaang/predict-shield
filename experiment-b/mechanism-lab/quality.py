"""Read-only experiment-quality report for mechanism-based Experiment B.

This report evaluates whether the collected experiment actually produced
variation in independent oracle and service-health measurements. It never
creates a label, replays a trial, trains a model or claims an AI improvement.
The report is only available after the four record streams have passed
load_executed_dataset(), including the full 1,200-trial completeness check.

It distinguishes repeat-level variability from variation in operating
configurations. Deterministic outcomes alone do not prove a flawed model,
but a near-zero within-condition variation rate must be explained before
predictive effectiveness claims are submitted for review.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from train import ACTIONS, load_executed_dataset
from plan import FAULTS_V31


def quality_summary(rows: list[dict]) -> dict:
    """Summarize observed fault variation with configuration-level grouping.

    For each (configuration, action), exactly three repetitions are required.
    Their security and service-health labels are examined independently.
    Fault families and partitions are represented using observed full groups,
    not synthetic placeholders or copied generator formulas.

    @param rows Complete joined measured trial rows from load_executed_dataset.
    @return Auditable quality metadata and possible limitations.
    """
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    by_fault = defaultdict(list)
    for item in rows:
        grouped[(item["group"], item["action"])].append(item)
        by_fault[item["fault"]].append(item)
    if len(grouped) != 100 * len(ACTIONS) or set(by_fault) != set(FAULTS_V31):
        raise ValueError("Missing configuration/action groups or injected fault families")
    variable_exposure = 0
    variable_disruption = 0
    distinct_health_fractions = []
    for key, repeats in grouped.items():
        if len(repeats) != 3:
            raise ValueError(f"Expected three observed repetitions in {key}")
        risks = {r["label_security_exposure"] for r in repeats}
        errors = {r["label_service_failure_fraction"] for r in repeats}
        variable_exposure += len(risks) > 1
        variable_disruption += len(errors) > 1
        distinct_health_fractions.append(len(errors))
    fault_strata = {}
    for fault, samples in sorted(by_fault.items()):
        strata = Counter((r["partition"], r["action"]) for r in samples)
        fault_strata[fault] = {
            "measured_trials": len(samples),
            "distinct_configurations": len({r["group"] for r in samples}),
            "action_counts": {action: sum(r["action"] == action for r in samples)
                              for action in ACTIONS},
            "split_counts": {split: sum(r["partition"] == split for r in samples)
                             for split in ("train", "calibration", "test")},
            "oracle_exposure_rate": sum(
                r["label_security_exposure"] for r in samples) / len(samples),
            "mean_legitimate_request_failure_fraction": sum(
                r["label_service_failure_fraction"] for r in samples) / len(samples),
        }
    return {
        "schema": "predict-shield/mechanism-data-quality/1",
        "measured_trials": len(rows),
        "unique_configuration_action_groups": len(grouped),
        "security_labels_vary_across_repeats": variable_exposure,
        "service_failure_labels_vary_across_repeats": variable_disruption,
        "mean_distinct_failure_fractions_within_three_repeats": sum(
            distinct_health_fractions) / len(distinct_health_fractions),
        "fault_strata": fault_strata,
        "ai_effectiveness_validated": False,
        "review_flags": [
            "Fault duplication may be correctly ignored by revision-based idempotence",
            "Reorder faults require multiple distinct revisions to demonstrate reordering",
            "Measured event and workload timing may be partially confounded with cache TTL",
            "Three repeats in one configuration are correlated, not independent systems",
            "Real authorization changes are not tested on production services",
        ],
    }


def main() -> None:
    """Write the read-only complete-campaign quality report without oracle details."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    rows = load_executed_dataset(args.records)
    report = quality_summary(rows)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as out:
        json.dump(report, out, sort_keys=True, indent=2)
        out.write("\n")
    print("Measured Experiment B quality report:", args.report)


if __name__ == "__main__":
    main()
