"""Preregistered Experiment B mechanism-lab plan with configuration-level partitions.

The plan is strictly a manifest, not measured data. It is intentionally
compatible with the *four physical JVM* topology currently present, and does
not pretend to instantiate the old generator's 2-8 enforcement processes.
The current mechanism test supports four distinct policy-event mechanisms:
loss, delay, duplicate and reorder. Action replay order is randomized within
each configuration/repeat to reduce fixed-order confounding. No result is
forced by the planner. Train, calibration and test configuration groups never overlap.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
FAULTS = ("loss", "delay", "duplicate", "reorder")
PARTITIONS = {"train": 60, "calibration": 20, "test": 20}
REPEATS = 3
CONFIG_COUNT = 100
SEED = 20261110
SCHEMA = "predict-shield/mechanism-experiment-plan/1"


def digest(*parts: object) -> str:
    """Derive stable manifest IDs without dependence on Python hash seeds."""
    return hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]


def create_plan(seed: int = SEED) -> tuple[list[dict], list[dict]]:
    """Generate precisely 100 disjoint cases and 1,200 paired action replays.

    Inputs are constrained to the operational envelope of the existing three
    gateway-visible JVMs and one gateway-hidden JVM. The plan does not vary
    the *number* of physical enforcers or interpret a requested load as a
    measured throughput value. Each configuration/repeat uses one shared seed
    for all four action replays.
    """
    rng = random.Random(seed)
    splits = [label for label, count in PARTITIONS.items() for _ in range(count)]
    rng.shuffle(splits)
    configs = []
    trials = []
    for i in range(CONFIG_COUNT):
        fault = FAULTS[i % len(FAULTS)]
        conf = {
            "schema": SCHEMA,
            "configuration_id": f"mechanism-{i:03d}",
            "partition": splits[i],
            "fault_mode": fault,
            "fault_target": rng.choice(("enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden")),
            "cache_ttl_ms": rng.randint(2500, 15000),
            "event_delay_ms": rng.randint(0, 2500),
            "requested_rps": rng.randint(10, 65),
            "measurement_seconds": 4,
            "gateway_includes_hidden": i % 2 == 0,
            "visible_enforcement_processes": (4 if i % 2 == 0 else 3),
            "oracle_inventory_processes": 4,
            "scenario_seed": rng.getrandbits(63),
        }
        configs.append(conf)
        for repeat in range(REPEATS):
            seed_for_repeat = int(digest(seed, i, repeat), 16)
            # Randomize replay order within each matched group to avoid
            # systematically favoring the first action after a clean setup.
            # The action IDs and shared starting-condition seed stay fixed.
            order = list(ACTIONS)
            random.Random(seed_for_repeat).shuffle(order)
            for action in order:
                trials.append({
                    "schema": SCHEMA,
                    "run_id": "mechanism-run-" + digest(seed, i, repeat, action),
                    "configuration_id": conf["configuration_id"],
                    "partition": conf["partition"],
                    "action_id": action,
                    "repeat": repeat,
                    "initial_state_seed": seed_for_repeat,
                    "execution_status": "PLANNED_NOT_EXECUTED",
                })
    validate_plan(configs, trials)
    return configs, trials


def validate_plan(configs: list[dict], trials: list[dict]) -> None:
    """Reject altered partitions, missing replays or unsupported mechanisms."""
    if len(configs) != CONFIG_COUNT or len(trials) != CONFIG_COUNT * len(ACTIONS) * REPEATS:
        raise ValueError("Expected 100 configurations and 1,200 planned trials")
    if Counter(item["partition"] for item in configs) != PARTITIONS:
        raise ValueError("Expected 60/20/20 independent configuration partitions")
    config_by_id = {item["configuration_id"]: item for item in configs}
    if len(config_by_id) != CONFIG_COUNT or len({t["run_id"] for t in trials}) != len(trials):
        raise ValueError("Duplicate configuration or run identifiers")
    grouped = {}
    for t in trials:
        conf = config_by_id.get(t["configuration_id"])
        if conf is None or t["partition"] != conf["partition"]:
            raise ValueError("Unknown or cross-partition experiment")
        if t["action_id"] not in ACTIONS or conf["fault_mode"] not in FAULTS:
            raise ValueError("Unsupported action/fault")
        if t["execution_status"] != "PLANNED_NOT_EXECUTED":
            raise ValueError("Manifests must not claim completed experiments")
        grouped.setdefault((t["configuration_id"], t["repeat"]), []).append(t)
    if len(grouped) != CONFIG_COUNT * REPEATS:
        raise ValueError("Incomplete paired repeat grouping")
    for group in grouped.values():
        if {t["action_id"] for t in group} != set(ACTIONS):
            raise ValueError("Each repeat must include exactly four actions")
        if len({t["initial_state_seed"] for t in group}) != 1:
            raise ValueError("Paired conditions must share a seed")


def save_plan(folder: Path, seed: int = SEED) -> None:
    """Write reproducible JSON Lines without producing any training labels."""
    configs, trials = create_plan(seed)
    folder.mkdir(parents=True, exist_ok=True)
    for name, rows in (("configurations.jsonl", configs), ("trials.jsonl", trials)):
        with (folder / name).open("w", encoding="utf-8") as file:
            for item in rows:
                file.write(json.dumps(item, sort_keys=True) + "\n")
    (folder / "protocol.json").write_text(json.dumps({
        "schema": SCHEMA, "configurations": 100, "planned_trials": 1200,
        "splits": PARTITIONS, "seed": seed, "repeats": REPEATS,
        "physical_enforcers": 4, "gateway_visible_enforcers": "3_or_4_by_scenario",
        "outcomes_collected": False, "model_trained": False,
        "limitations": [
            "The physical topology has four JVMs and cannot realize the earlier 2-8 node claim",
            "The requested RPS is a workload target, not observed throughput",
            "Only actual executed replays can supply oracle and service-health labels",
            "Delay/duplication/reordering are consumer-level faults, not network partitions",
        ],
    }, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    """Expose an idempotent, local-only manifest-generation CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("plans/mechanism"))
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    save_plan(args.output, args.seed)
    print("Generated 100 grouped configurations and 1,200 PLANNED mechanism replays")


if __name__ == "__main__":
    main()
