"""PROPOSED v3.1 configuration manifest generator, not an execution runner.

This module intentionally refuses to emit the v3 plan schema. The existing
v3 campaign runner must never execute these configurations without separately
reviewed v3.1 mechanism adapters, safety checks and protocol freeze.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

SEED = 20261112
COUNT = 150
REPEATS = 2
ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
FAULTS = ("loss", "delay", "duplicate", "reorder",
          "authority_outage", "consumer_paused")
STRATA = ("SIMPLE", "INTERACTION", "PARTIAL_VISIBILITY")
ROUTES = ("balanced", "skewed_a", "skewed_hidden")
SPLITS = {"train": 90, "calibration": 30, "test": 30}
SCHEMA = "predict-shield/mechanism-v31-proposed/1"


def stable_id(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def build(seed: int = SEED) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    # Stratify by fault and difficulty. Each combination repeats 8 or 9 times.
    cells = [(fault, level) for fault in FAULTS for level in STRATA]
    assigned = (cells * (COUNT // len(cells))) + cells[:COUNT % len(cells)]
    rng.shuffle(assigned)
    # Three independent, balanced traffic-profile assignments for 150 groups.
    routes = list(ROUTES) * (COUNT // len(ROUTES))
    rng.shuffle(routes)
    splits = [split for name, n in SPLITS.items() for split in [name] * n]
    rng.shuffle(splits)
    configs, trials = [], []
    for i, ((fault, stratum), route, split) in enumerate(zip(assigned, routes, splits)):
        conf_id = f"mechanism-v31-{i:03d}"
        config = {
            "schema": SCHEMA,
            "configuration_id": conf_id,
            "partition": split,
            "fault_mode": fault,
            "complexity_stratum": stratum,
            "routing_profile": route,
            "fault_target": rng.choice(("enforcer-a", "enforcer-b",
                                         "enforcer-c", "enforcer-hidden")),
            "cache_ttl_ms": rng.randint(2500, 15000),
            "requested_rps": rng.randint(10, 65),
            "measurement_seconds": 4,
            "restart_permitted": bool(rng.getrandbits(1)),
            "gateway_includes_hidden": bool(rng.getrandbits(1)),
            "absolute_error_budget_requests": 25,
            "initial_state_seed": rng.getrandbits(63),
            "node_service_latency_ms": ([15] * 4 if stratum == "SIMPLE" else
                                         [rng.choice((0, 15, 50, 100))
                                          for _ in range(4)]),
            "execution_status": "PLANNED_NOT_EXECUTED",
            "registered_fault_recovery_contract": "PROTOCOL_V3_1_FEASIBILITY_DRAFT.md",
        }
        configs.append(config)
        for repetition in range(REPEATS):
            order = list(ACTIONS)
            random.Random(int(stable_id(seed, conf_id, repetition), 16)).shuffle(order)
            for action in order:
                trials.append({
                    "schema": SCHEMA,
                    "configuration_id": conf_id,
                    "partition": split,
                    "run_id": "v31-" + stable_id(seed, conf_id, repetition, action),
                    "action_id": action,
                    "repeat": repetition,
                    "initial_state_seed": stable_id(config["initial_state_seed"], repetition),
                    "execution_status": "PLANNED_NOT_EXECUTED",
                })
    validate(configs, trials)
    return configs, trials


def validate(configs: list[dict], trials: list[dict]) -> None:
    if len(configs) != COUNT or len(trials) != COUNT * len(ACTIONS) * REPEATS:
        raise ValueError("Expected 150 independent groups and 1,200 planned trials")
    if Counter(c["partition"] for c in configs) != SPLITS:
        raise ValueError("90/30/30 group split required")
    if Counter(c["fault_mode"] for c in configs) != dict.fromkeys(FAULTS, 25):
        raise ValueError("All six fault families must have 25 configurations")
    if Counter(c["complexity_stratum"] for c in configs) != dict.fromkeys(STRATA, 50):
        raise ValueError("All difficulty strata must have 50 configurations")
    if Counter(c["routing_profile"] for c in configs) != dict.fromkeys(ROUTES, 50):
        raise ValueError("All routing profiles must have 50 configurations")
    by_id = {c["configuration_id"]: c for c in configs}
    if len(by_id) != COUNT or len({t["run_id"] for t in trials}) != len(trials):
        raise ValueError("Duplicate configuration or trial")
    grouped = {}
    for t in trials:
        c = by_id.get(t["configuration_id"])
        if not c or t["partition"] != c["partition"] or t["schema"] != SCHEMA:
            raise ValueError("Cross-partition or unsupported-schema trial")
        if t["execution_status"] != "PLANNED_NOT_EXECUTED":
            raise ValueError("Plan must contain no measured outcomes")
        grouped.setdefault((t["configuration_id"], t["repeat"]), []).append(t["action_id"])
    if len(grouped) != COUNT * REPEATS or any(
            len(v) != len(ACTIONS) or set(v) != set(ACTIONS) for v in grouped.values()):
        raise ValueError("Each group and repetition requires four actions")
    if any(c["schema"] != SCHEMA or
           c["execution_status"] != "PLANNED_NOT_EXECUTED" for c in configs):
        raise ValueError("Unsupported or falsely executed configuration")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=SEED)
    a = parser.parse_args()
    configs, trials = build(a.seed)
    dest = Path(a.output)
    dest.mkdir(parents=True, exist_ok=True)
    for filename, items in (("configurations.jsonl", configs), ("trials.jsonl", trials)):
        file = dest / filename
        if file.exists():
            raise FileExistsError("Refusing overwrite of existing plan " + str(file))
        file.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in items))
    print(json.dumps({"schema": SCHEMA, "configurations": len(configs),
                      "planned_trials": len(trials),
                      "warning": "NOT APPROVED FOR EXECUTION; V3.1 NOT FROZEN"}))


if __name__ == "__main__":
    main()
