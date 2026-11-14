"""Predeclared *exploratory subset* v3.1 pilot, not the 150-group study.

Five physically supported fault families; authority outage is excluded because
the current full-state oracle requires live authority availability. This subset
can test integrity/headroom mechanics but cannot pass final v3.1 feasibility.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from plan import ACTIONS

SCHEMA = "predict-shield/v31-physical-pilot-plan/1"
SEED = 20261114
# Chosen before recording this pilot's independent observations. The already
# inspected single-condition smoke used enforcer-b / rps25 / ttl30000;
# none of these pilot configurations reproduces that setup.
SPEC = (
    ("loss", "SIMPLE", "enforcer-b", 7500, 0, 30, "balanced", True, True),
    ("delay", "INTERACTION", "enforcer-a", 14000, 1600, 50, "skewed_a", True, True),
    ("duplicate", "PARTIAL_VISIBILITY", "enforcer-c", 12000, 0, 35, "skewed_a", True, False),
    ("reorder", "PARTIAL_VISIBILITY", "enforcer-hidden", 15000, 0, 45, "skewed_hidden", False, True),
    ("consumer_paused", "PARTIAL_VISIBILITY", "enforcer-a", 17000, 0, 40, "balanced", True, False),
)


def digest(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def create() -> tuple[list[dict], list[dict]]:
    configs, trials = [], []
    for i, (fault, level, target, ttl, delay, rps, route, include_hidden, restart) in enumerate(SPEC):
        name = f"v31-pilot-{i:03d}"
        configuration = {
            "schema": SCHEMA,
            "configuration_id": name,
            "partition": "pilot",
            "fault_mode": fault,
            "fault_target": target,
            "cache_ttl_ms": ttl,
            "event_delay_ms": delay,
            "requested_rps": rps,
            "measurement_seconds": 5,
            "routing_profile": route,
            "complexity_stratum": level,
            "node_service_latency_ms": [15,15,15,15] if level == "SIMPLE" else [0,15,50,100],
            "restart_permitted": restart,
            "gateway_includes_hidden": include_hidden,
            "visible_enforcement_processes": 4 if include_hidden else 3,
            "oracle_inventory_processes": 4,
            "absolute_error_budget_requests": 25,
            "initial_state_seed": int(digest(SEED,name),16),
            "execution_status": "PLANNED_NOT_EXECUTED",
        }
        configs.append(configuration)
        for repeat in (0,1):
            order = list(ACTIONS)
            random.Random(int(digest(SEED,name,repeat),16)).shuffle(order)
            for action in order:
                trials.append({
                    "schema": SCHEMA,
                    "run_id": "v31-pilot-run-" + digest(SEED,name,repeat,action),
                    "configuration_id": name, "partition": "pilot",
                    "action_id": action, "repeat": repeat,
                    "initial_state_seed": digest(SEED,name,repeat),
                    "execution_status": "PLANNED_NOT_EXECUTED",
                })
    validate(configs, trials)
    return configs, trials


def validate(configs: list[dict], trials: list[dict]) -> None:
    if len(configs) != len(SPEC) or len(trials) != len(SPEC)*2*len(ACTIONS):
        raise ValueError("Five groups, two repeats, four actions required")
    if len({c["configuration_id"] for c in configs}) != len(configs):
        raise ValueError("Duplicate pilot configuration")
    if len({t["run_id"] for t in trials}) != len(trials):
        raise ValueError("Duplicate pilot run ID")
    lookup = {c["configuration_id"]:c for c in configs}
    for config in configs:
        if (config["schema"] != SCHEMA or config["partition"] != "pilot"
                or config["fault_mode"] == "authority_outage"
                or config["execution_status"] != "PLANNED_NOT_EXECUTED"):
            raise ValueError("Unregistered or falsely executed pilot configuration")
    for config in configs:
        for repeat in (0,1):
            subset=[t for t in trials if (t["configuration_id"],t["repeat"]) ==
                    (config["configuration_id"],repeat)]
            if (len(subset)!=4 or {t["action_id"] for t in subset}!=set(ACTIONS)
                    or len({t["initial_state_seed"] for t in subset})!=1
                    or any(t["partition"]!="pilot" or
                           t["execution_status"]!="PLANNED_NOT_EXECUTED" for t in subset)):
                raise ValueError("Incomplete or misregistered paired action group")
    if any(t["configuration_id"] not in lookup for t in trials):
        raise ValueError("Unregistered trial group")


def save(directory: Path) -> None:
    configs, trials = create()
    directory.mkdir(parents=True, exist_ok=True)
    for name, rows in (("configurations.jsonl", configs), ("trials.jsonl", trials)):
        with (directory/name).open("x",encoding="utf-8") as file:
            file.write("".join(json.dumps(item,sort_keys=True)+"\n" for item in rows))


if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    save(args.output)
    print("PLANNED: five exploratory physical groups; not final feasibility evidence")
