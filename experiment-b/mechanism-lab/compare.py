"""Pre-registered paired-action outcome comparisons using observed lab results.

This is an *observational comparison within a controlled replay*, not a
randomized clinical-style causal-effect claim. The experiment pairs four
candidate actions under each same registered configuration and repeat.
Action order is randomized in the manifest, but residual Kafka state and
system load can still create carryover. The status report must preserve
this limitation and refrain from asserting model advantage.

No model is invoked by this comparison. The 'monitor_only' replay is the
untreated reference. Group-resampled bootstrap intervals account for
dependency among repeats of the same operating configuration.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from train import ACTIONS, load_executed_dataset

REFERENCE = "monitor_only"
PARTITIONS = ("train", "calibration", "test")


def paired_differences(rows: list[dict], partition: str) -> dict:
    """Compute observed action-minus-monitor outcomes for complete paired runs.

    A negative exposure difference indicates fewer persistently exposed
    enforcement configurations; a positive service-failure difference
    indicates more unintended disruption. Input rows must come from the
    independently validated executed-record join, never a manifest alone.
    """
    if partition not in PARTITIONS:
        raise ValueError("Invalid registered evaluation partition")
    rows = [r for r in rows if r["partition"] == partition]
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["group"]].append(row)
    paired = {action: [] for action in ACTIONS if action != REFERENCE}
    for group_id, members in groups.items():
        indexed: dict[str, list[dict]] = defaultdict(list)
        for row in members:
            indexed[row["action"]].append(row)
        if set(indexed) != set(ACTIONS) or any(len(v) != 3 for v in indexed.values()):
            raise ValueError(f"Unpaired configuration group: {group_id}")
        ref_security = sum(r["label_security_exposure"] for r in indexed[REFERENCE]) / 3
        ref_errors = sum(r["label_service_failure_fraction"] for r in indexed[REFERENCE]) / 3
        for action in paired:
            security = sum(r["label_security_exposure"] for r in indexed[action]) / 3
            failures = sum(r["label_service_failure_fraction"] for r in indexed[action]) / 3
            paired[action].append({
                "configuration_group": group_id,
                "exposure_difference": security - ref_security,
                "service_failure_difference": failures - ref_errors,
            })
    return {"partition": partition, "configuration_groups": len(groups), "paired": paired}


def confidence_intervals(comparisons: dict, *, replicates: int = 1000,
                         seed: int = 20261111) -> dict:
    """Estimate exploratory 95% intervals by resampling whole configurations.

    Repeats sharing a configuration are first averaged. Entire groups are then
    resampled so the three repeats do not count as independent deployment
    environments. Intervals describe the tested fixture and are not service
    safety guarantees or proof of generalization under distribution shift.
    """
    if not 100 <= replicates <= 5000:
        raise ValueError("Bootstrap replicate count outside registered bounds")
    rng = random.Random(seed)
    results = {}
    for action, entries in comparisons["paired"].items():
        if not entries:
            raise ValueError("No registered measured outcomes")
        by_metric = {}
        for metric in ("exposure_difference", "service_failure_difference"):
            values = [float(item[metric]) for item in entries]
            n = len(values)
            samples = []
            for _ in range(replicates):
                samples.append(sum(values[rng.randrange(n)] for _ in range(n)) / n)
            samples.sort()
            by_metric[metric] = {
                "observed_mean_difference": sum(values) / n,
                "cluster_bootstrap_lower_95": samples[int(.025 * (replicates - 1))],
                "cluster_bootstrap_upper_95": samples[int(.975 * (replicates - 1))],
                "configuration_groups": n,
            }
        results[action] = by_metric
    return {
        "schema": "predict-shield/experiment-b-action-comparison/1",
        "partition": comparisons["partition"],
        "reference_action": REFERENCE,
        "bootstrap_replicates": replicates,
        "action_comparisons": results,
        "limitations": [
            "Real controlled Kafka/JVM lab behavior, not external deployment",
            "Measured outcomes may contain workload, order and stale-event carryover",
            "Group resampling does not guarantee individual service safety",
            "No trained model selected an action in these replay comparisons",
            "Causal claims require stronger independence and timing controls",
        ],
    }


def main() -> None:
    """Require actual full measured data before post-hoc held-out comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--partition", choices=PARTITIONS, default="test")
    args = parser.parse_args()
    rows = load_executed_dataset(args.records)
    report = confidence_intervals(paired_differences(rows, args.partition))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print("Saved measured, paired action comparison:", args.report)


if __name__ == "__main__":
    main()
