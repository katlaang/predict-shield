"""Prospective six-family *feasibility design*, not an authorized experiment.

18 independent configurations, three per physical fault, two repeats, and
four replay arms. This is not the 150-group main experiment. The current
outage observations do not support final scalar v3.1 cost scoring.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

SEED = 20261114
SCHEMA = "predict-shield/v31-six-family-prospective-feasibility-design/1"
ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
FAULTS = ("loss", "delay", "duplicate", "reorder",
          "consumer_paused", "authority_outage")
STRATA = ("SIMPLE", "INTERACTION", "PARTIAL_VISIBILITY")
TARGETS = ("enforcer-a", "enforcer-b", "enforcer-hidden")


def stable_id(*values: object) -> str:
    return hashlib.sha256("|".join(map(str, values)).encode()).hexdigest()[:24]


def build(seed: int = SEED) -> tuple[list[dict], list[dict]]:
    """Predeclare balanced fault-by-stratum structure without any outcomes."""
    rng = random.Random(seed)
    cells = [(fault, stratum, variant)
             for fault in FAULTS for variant, stratum in enumerate(STRATA)]
    rng.shuffle(cells)
    configs, trials = [], []
    for i, (fault, stratum, variant) in enumerate(cells):
        ident = f"v31-feasibility-{i:03d}"
        config = {
            "schema": SCHEMA,
            "configuration_id": ident,
            "partition": "independent_feasibility_pilot",
            "fault_mode": fault,
            "complexity_stratum": stratum,
            "fault_target": TARGETS[(i + variant) % 3],
            "cache_ttl_ms": (4000, 9000, 16000)[variant],
            "requested_rps": (20, 40, 60)[variant],
            "measurement_seconds": 6,
            "routing_profile": ("balanced", "skewed_a", "skewed_hidden")[variant],
            "gateway_includes_hidden": variant != 2,
            "restart_permitted": variant != 1,
            "absolute_error_budget_requests": 25,
            "initial_state_seed": int(stable_id(seed, ident), 16),
            "policy_semantics": (
                "HISTORICAL_WITNESS_INTERVAL_UNKNOWN_LIVE_AUTHORITY"
                if fault == "authority_outage" else
                "LIVE_AUTHORITY_SEPARATE_ORACLE"),
            "execution_status": "NOT_AUTHORIZED_NOT_EXECUTED",
            "protocol_status": "DRAFT_AWAITING_SCIENTIFIC_REVIEW",
        }
        configs.append(config)
        for rep in (0, 1):
            order = list(ACTIONS)
            random.Random(int(stable_id(seed, ident, rep), 16)).shuffle(order)
            for action in order:
                trials.append({
                    "schema": SCHEMA,
                    "configuration_id": ident,
                    "partition": "independent_feasibility_pilot",
                    "run_id": "v31-feas-" + stable_id(seed, ident, rep, action),
                    "repeat": rep,
                    "action_id": action,
                    "initial_state_seed": stable_id(config["initial_state_seed"], rep),
                    "execution_status": "NOT_AUTHORIZED_NOT_EXECUTED",
                })
    validate(configs, trials)
    return configs, trials


def validate(configs: list[dict], trials: list[dict]) -> None:
    if len(configs) != 18 or len(trials) != 144:
        raise ValueError("Expected 18 configuration groups and 144 proposed action replays")
    if Counter(c["fault_mode"] for c in configs) != dict.fromkeys(FAULTS, 3):
        raise ValueError("Exactly three configurations per physical fault required")
    if Counter(c["complexity_stratum"] for c in configs) != dict.fromkeys(STRATA, 6):
        raise ValueError("Six configurations per complexity level required")
    if len({c["configuration_id"] for c in configs}) != 18:
        raise ValueError("Duplicate configuration")
    if len({t["run_id"] for t in trials}) != 144:
        raise ValueError("Duplicate replay")
    lookup = {c["configuration_id"]: c for c in configs}
    for c in configs:
        if (c["schema"] != SCHEMA or c["partition"] != "independent_feasibility_pilot"
                or c["execution_status"] != "NOT_AUTHORIZED_NOT_EXECUTED"):
            raise ValueError("Invalid protocol or fabricated execution state")
    for t in trials:
        c = lookup.get(t["configuration_id"])
        if (c is None or t["schema"] != SCHEMA or
                t["partition"] != "independent_feasibility_pilot" or
                t["execution_status"] != "NOT_AUTHORIZED_NOT_EXECUTED"):
            raise ValueError("Unregistered or falsely executed trial")
    for config in configs:
        for repetition in (0, 1):
            arm = [t for t in trials if (
                t["configuration_id"] == config["configuration_id"] and
                t["repeat"] == repetition)]
            if (len(arm) != 4 or set(t["action_id"] for t in arm) != set(ACTIONS)
                    or len({t["initial_state_seed"] for t in arm}) != 1):
                raise ValueError("Incomplete or unmatched four-action replay set")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seed", type=int, default=SEED)
    args = p.parse_args()
    configs, trials = build(args.seed)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, rows in (("configurations.jsonl", configs), ("trials.jsonl", trials)):
        with (args.output / name).open("x", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(json.dumps({"configuration_groups": 18, "proposed_action_replays": 144,
                      "authorized": False, "executed": False,
                      "not_confirmatory": True}))


if __name__ == "__main__":
    main()
