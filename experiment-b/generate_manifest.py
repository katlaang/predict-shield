"""Generate reproducible Experiment B manifests, not training labels or results.

Creates exactly 100 independent configuration groups x 4 candidate actions x
3 repeats = 1,200 planned trials. Data are organized as configuration-level
60/20/20 train/calibration/test splits. Actual action outcomes, independent
oracle labels, verifier outcomes and service-health measurements are recorded
only *after* execution by separate collectors.

Usage:
    python experiment-b/generate_manifest.py --out experiment-b/generated
    python -m unittest discover -s experiment-b -p 'test_*.py' -v
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

SCHEMA_VERSION = "experiment-b-manifest/1.0"
ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
FAULTS = (
    "stale_cache", "lost_event", "delayed_event",
    "duplicate_event", "silent_rebuild", "reordered_event",
)
SPLITS = {"train": 60, "calibration": 20, "test": 20}
CONFIGURATIONS = 100
REPEATS = 3
DEFAULT_SEED = 20261110


def stable_id(prefix: str, *parts: object) -> str:
    """Compute a stable short identifier without using runtime hash randomization."""
    content = ":".join(str(part) for part in parts).encode("utf-8")
    return prefix + "-" + hashlib.sha256(content).hexdigest()[:14]


def generate_configurations(seed: int = DEFAULT_SEED) -> list[dict]:
    """Sample 100 reproducible combinations with disjoint configuration splits.

    The split is fixed at the configuration level; all actions and repeats for
    any configuration belong to only one partition. Continuous input ranges
    are sampled using a seeded PRNG. Numbers are *design parameters*, not
    measured deployment values or actual operating distributions.
    """
    rng = random.Random(seed)
    ordered_splits = [
        split for split, count in SPLITS.items() for _ in range(count)
    ]
    rng.shuffle(ordered_splits)
    configurations = []
    for i in range(CONFIGURATIONS):
        point_count = rng.randint(2, 8)
        stale_count = rng.randint(1, point_count - 1)
        configuration = {
            "schema_version": SCHEMA_VERSION,
            "configuration_id": f"cfg-{i:03d}",
            "split": ordered_splits[i],
            "fault_family": FAULTS[i % len(FAULTS)],
            "enforcement_points": point_count,
            "stale_points": stale_count,
            "cache_ttl_ms": rng.randint(50, 5000),
            "propagation_delay_ms": rng.randint(0, 5000),
            "traffic_rps": rng.randint(1, 1000),
            "dependency_depth": rng.randint(1, 6),
            "redundancy": rng.randint(1, point_count),
            "seed": rng.getrandbits(63),
        }
        configurations.append(configuration)
    return configurations


def generate_plan(seed: int = DEFAULT_SEED) -> tuple[list[dict], list[dict]]:
    """Create paired candidate-action trials without materializing any outcomes.

    Each repeat has a seed shared across the four candidate actions so that
    trial conditions can be replayed from clean resets. Different repeats have
    different seeds. The generator does not compute post-action measurements,
    ground truth, or predicted risk.
    """
    configs = generate_configurations(seed)
    trials = []
    for config in configs:
        for repeat in range(REPEATS):
            repeat_seed = int(stable_id("0", config["seed"], repeat)[2:], 16)
            for action in ACTIONS:
                trials.append({
                    "schema_version": SCHEMA_VERSION,
                    "run_id": stable_id("run", config["configuration_id"], repeat, action),
                    "configuration_id": config["configuration_id"],
                    "split": config["split"],
                    "repeat": repeat,
                    "action_id": action,
                    "trial_seed": repeat_seed,
                    "oracle_record_id": None,
                    "verification_record_id": None,
                    "operational_outcome_record_id": None,
                    "pre_action_prediction_record_id": None,
                    "status": "PLANNED_NOT_EXECUTED",
                })
    validate_plan(configs, trials)
    return configs, trials


def validate_plan(configurations: list[dict], trials: list[dict]) -> None:
    """Fail generation when counts, pairings, configuration isolation or IDs drift."""
    if len(configurations) != 100 or len(trials) != 1200:
        raise ValueError("Expected exactly 100 configurations and 1,200 trials")
    if Counter(c["split"] for c in configurations) != SPLITS:
        raise ValueError("Configuration split must be 60/20/20")
    if len({c["configuration_id"] for c in configurations}) != 100:
        raise ValueError("Duplicate configuration identifiers")
    if len({t["run_id"] for t in trials}) != 1200:
        raise ValueError("Duplicate trial identifiers")
    grouped: dict[tuple[str, int], list[dict]] = {}
    configs_by_id = {c["configuration_id"]: c for c in configurations}
    for trial in trials:
        config = configs_by_id[trial["configuration_id"]]
        if trial["split"] != config["split"]:
            raise ValueError("Trial crosses a configuration split")
        if trial["status"] != "PLANNED_NOT_EXECUTED":
            raise ValueError("Generator must not claim completed experiments")
        grouped.setdefault((trial["configuration_id"], trial["repeat"]), []).append(trial)
    if len(grouped) != 300:
        raise ValueError("Expected 300 paired configuration/repeat groups")
    for group in grouped.values():
        if {item["action_id"] for item in group} != set(ACTIONS):
            raise ValueError("Each pairing must contain all four candidate actions")
        if len({item["trial_seed"] for item in group}) != 1:
            raise ValueError("Paired actions must share an initial-condition seed")


def write_jsonl(path: Path, values: list[dict]) -> None:
    """Write a deterministic UTF-8 JSON Lines file with no runtime timestamps."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def write_manifest(output: Path, seed: int = DEFAULT_SEED) -> dict:
    """Write reproducible manifest artifacts and return their non-outcome metadata."""
    output.mkdir(parents=True, exist_ok=True)
    configurations, trials = generate_plan(seed)
    write_jsonl(output / "configurations.jsonl", configurations)
    write_jsonl(output / "trials.jsonl", trials)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generator_seed": seed,
        "configuration_count": len(configurations),
        "trial_count": len(trials),
        "actions": list(ACTIONS),
        "repeats": REPEATS,
        "configuration_splits": SPLITS,
        "status": "PLAN_ONLY_NO_ACTIONS_EXECUTED",
        "measurements_generated": False,
        "oracle_labels_generated": False,
        "notes": [
            "All numbers are experimental configuration values, not observed outcomes.",
            "The test partition must never influence feature selection, training or calibration.",
            "Running all actions requires clean lab resets and safety authorization.",
            "Oracle and measured outcomes belong to separately protected output streams.",
        ],
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    """Parse the generator CLI and write a manifest in the selected directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("experiment-b/generated"))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    print(json.dumps(write_manifest(args.out, args.seed), indent=2))


if __name__ == "__main__":
    main()
