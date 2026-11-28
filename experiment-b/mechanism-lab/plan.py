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

# Version 3.1, revised after the first control run (CONTROLS_RESULT_2026_11_21.md):
# duplicate and reorder never exposed revoked access without action, delay
# healed in about 2 s, and loss persisted past the 6 s window only when the
# cache TTL was longer than the window. Version 3.1 uses two fault modes that
# persist past the window (loss and a physically paused Kafka listener, each
# with TTL 10-30 s) in 70 configurations, and keeps 30 configurations whose
# fault heals within the window (delay 2-3 s; loss with TTL 2.5-4 s), where
# doing nothing is a legitimate outcome.
SCHEMA_V31 = "predict-shield/mechanism-experiment-plan/3.1"
# Withheld publication is supported by the newer confirmatory registration
# generator only; the original v3.1 generator's 1,200 trials remain unchanged.
FAULTS_V31 = ("loss", "consumer_paused", "delay", "withheld_publication")
SEED_V31 = 20261121
# 20-configuration cycle: 7 persistent loss, 7 persistent listener pause,
# 3 self-healing delay, 3 self-healing short-TTL loss.
V31_CYCLE = (("loss", "persistent"), ("consumer_paused", "persistent"),
             ("loss", "persistent"), ("consumer_paused", "persistent"),
             ("delay", "self_healing"), ("loss", "persistent"),
             ("consumer_paused", "persistent"), ("loss", "self_healing"),
             ("loss", "persistent"), ("consumer_paused", "persistent"),
             ("loss", "persistent"), ("consumer_paused", "persistent"),
             ("delay", "self_healing"), ("loss", "persistent"),
             ("consumer_paused", "persistent"), ("loss", "self_healing"),
             ("loss", "persistent"), ("consumer_paused", "persistent"),
             ("delay", "self_healing"), ("loss", "self_healing"))


def digest(*parts: object) -> str:
    """Derive stable manifest IDs without dependence on Python hash seeds."""
    return hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]


def v31_fault_settings(i: int, seed: int) -> dict:
    """Fault mode, control class, TTL and delay for version 3.1 configuration i.

    Drawn from a separate generator so the version 3 plan stays byte-identical."""
    mode, control_class = V31_CYCLE[i % len(V31_CYCLE)]
    rng = random.Random(int(digest("v3.1", seed, i), 16))
    if control_class == "persistent":
        ttl, delay = rng.randint(10000, 30000), 0
    elif mode == "delay":
        # Delays under about 1.2 s are delivered before the first read after
        # setup and expose nothing (second control run), so 2-3 s.
        ttl, delay = rng.randint(10000, 30000), rng.randint(2000, 3000)
    else:
        ttl, delay = rng.randint(2500, 4000), 0
    return {"fault_mode": mode, "control_class": control_class,
            "cache_ttl_ms": ttl, "event_delay_ms": delay}


def create_plan(seed: int | None = None, version: str = "v3") -> tuple[list[dict], list[dict]]:
    """Generate precisely 100 disjoint cases and 1,200 paired action replays.

    Inputs are constrained to the operational envelope of the existing three
    gateway-visible JVMs and one gateway-hidden JVM. The plan does not vary
    the *number* of physical enforcers or interpret a requested load as a
    measured throughput value. Each configuration/repeat uses one shared seed
    for all four action replays.
    """
    if version not in ("v3", "v3.1"):
        raise ValueError("Unknown plan version")
    if seed is None:
        seed = SEED if version == "v3" else SEED_V31
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
            # Fault and routing profile are assigned on different cycles;
            # each fault family occurs under balanced and skewed traffic.
            "routing_profile": ("balanced", "skewed_a", "skewed_hidden")[
                (i // 4) % 3
            ],
            # Values affect actual JVM handler execution, not generated
            # result labels. SIMPLE has uniform service time; harder strata
            # vary independent per-node latency for each configuration.
            "node_service_latency_ms": (
                [15, 15, 15, 15] if (i // 12) % 3 == 0
                else [rng.choice((0, 10, 25, 55, 100, 140)) for _ in range(4)]
            ),
            # Complexity uses a 12-case block, independent of the
            # 4-case routing-profile cycle. Every 12-case block contains
            # all three routing profiles and every fault family, so
            # stratum is not merely another name for traffic weighting.
            "complexity_stratum": ("SIMPLE", "INTERACTION",
                                   "PARTIAL_VISIBILITY")[(i // 12) % 3],
            # Decision-policy eligibility is not a fault-injection feature.
            # Replays still execute every candidate in a disposable lab to
            # estimate counterfactual outcomes; an offline policy must never
            # select a prohibited restart.
            "restart_permitted": (i // 8) % 2 == 0,
            # Absolute failure allowance is held fixed as requested RPS
            # varies. This is a lab decision threshold, not a measured
            # remaining SLO budget or a production safety guarantee.
            "absolute_error_budget_requests": 25,
            # Each four-scenario block includes every fault family. Alternate
            # topology only between blocks, avoiding deterministic confounding
            # between fault type and whether the hidden target is routable.
            "gateway_includes_hidden": (i // 4) % 2 == 0,
            "visible_enforcement_processes": (4 if (i // 4) % 2 == 0 else 3),
            "oracle_inventory_processes": 4,
            "scenario_seed": rng.getrandbits(63),
        }
        if version == "v3.1":
            conf.update(v31_fault_settings(i, seed))
            conf["schema"] = SCHEMA_V31
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
                    "schema": conf["schema"],
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
        allowed = FAULTS_V31 if conf.get("schema") == SCHEMA_V31 else FAULTS
        if t["action_id"] not in ACTIONS or conf["fault_mode"] not in allowed:
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


def save_plan(folder: Path, seed: int | None = None, version: str = "v3") -> None:
    """Write reproducible JSON Lines without producing any training labels."""
    configs, trials = create_plan(seed, version)
    if seed is None:
        seed = SEED if version == "v3" else SEED_V31
    folder.mkdir(parents=True, exist_ok=True)
    for name, rows in (("configurations.jsonl", configs), ("trials.jsonl", trials)):
        with (folder / name).open("w", encoding="utf-8") as file:
            for item in rows:
                file.write(json.dumps(item, sort_keys=True) + "\n")
    (folder / "protocol.json").write_text(json.dumps({
        "schema": configs[0]["schema"], "version": version, "configurations": 100, "planned_trials": 1200,
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
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--version", choices=("v3", "v3.1"), default="v3")
    args = parser.parse_args()
    save_plan(args.output, args.seed, args.version)
    print("Generated 100 grouped configurations and 1,200 PLANNED mechanism replays")


if __name__ == "__main__":
    main()
