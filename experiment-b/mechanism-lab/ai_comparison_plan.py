"""Pre-outcome registration for a *new* physically measured AI selector pilot.

24 independently configured lab conditions from the already-frozen v3 100-group
generator, balanced 2 per fault/stratum cell; 12/6/6 train/calibration/test.
One repeat x four real actions = 96 physical trials. This is a NEW exploratory
study, not a substitute for the frozen 1,200-run v3 protocol.
"""
from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path

from plan import ACTIONS, FAULTS, create_plan

SEED = 20261114_51
SCHEMA = "predict-shield/physical-ai-comparison-pilot-plan/1"
STRATA = ("SIMPLE", "INTERACTION", "PARTIAL_VISIBILITY")
PARTITIONS = ("train", "calibration", "test")
COUNTS = {"train": 12, "calibration": 6, "test": 6}


def build() -> tuple[list[dict], list[dict]]:
    original, original_trials = create_plan()
    rng = random.Random(SEED)
    chosen = []
    for fault in FAULTS:
        for stratum in STRATA:
            candidates = [x for x in original
                          if x["fault_mode"] == fault and
                          x["complexity_stratum"] == stratum]
            if len(candidates) < 2:
                raise ValueError("Insufficient diverse configurations")
            selected = rng.sample(candidates, 2)
            chosen.extend(selected)
    rng.shuffle(chosen)
    assignments = [p for p, n in COUNTS.items() for _ in range(n)]
    rng.shuffle(assignments)
    original_by_group = {}
    for row in original_trials:
        if row["repeat"] == 0:
            original_by_group.setdefault(row["configuration_id"], []).append(row)
    configs, trials = [], []
    for row, partition in zip(chosen, assignments):
        cfg = {**row, "partition": partition,
               "pilot_registration_schema": SCHEMA,
               "pilot_seed": SEED,
               "independently_configured_operating_condition": True}
        configs.append(cfg)
        for original_trial in original_by_group[row["configuration_id"]]:
            trials.append({**original_trial, "partition": partition,
                           "pilot_registration_schema": SCHEMA})
    validate(configs, trials)
    return configs, trials


def validate(configs: list[dict], trials: list[dict]) -> None:
    if len(configs) != 24 or len(trials) != 96:
        raise ValueError("Expected 24 physical configurations and 96 four-action replays")
    if Counter(c["partition"] for c in configs) != COUNTS:
        raise ValueError("The independent group split was changed")
    if Counter((c["fault_mode"], c["complexity_stratum"]) for c in configs) != {
            (f, s): 2 for f in FAULTS for s in STRATA}:
        raise ValueError("Fault/stratum balance was altered")
    if len({c["configuration_id"] for c in configs}) != 24 or len({
            t["run_id"] for t in trials}) != 96:
        raise ValueError("Duplicate registered trial/configuration")
    lookup = {c["configuration_id"]: c for c in configs}
    for cfg in configs:
        if cfg.get("pilot_registration_schema") != SCHEMA:
            raise ValueError("Unregistered pilot configuration")
        arms = [t for t in trials if t["configuration_id"] == cfg["configuration_id"]]
        if (len(arms) != 4 or {t["action_id"] for t in arms} != set(ACTIONS)
                or {t["repeat"] for t in arms} != {0}
                or len({t["initial_state_seed"] for t in arms}) != 1):
            raise ValueError("Incomplete matched physical action group")
    if any(t.get("partition") != lookup[t["configuration_id"]]["partition"]
           or t.get("execution_status") != "PLANNED_NOT_EXECUTED"
           or t.get("pilot_registration_schema") != SCHEMA for t in trials):
        raise ValueError("Manifest falsely reports executed or cross-group trials")


def digest(configs: list[dict], trials: list[dict]) -> str:
    raw = json.dumps({"configurations": configs, "trials": trials},
                     sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def save(path: Path) -> None:
    configs, trials = build()
    if path.exists():
        raise FileExistsError("Never overwrite registered pilot plan")
    path.mkdir(parents=True)
    for name, rows in (("configurations.jsonl", configs),
                       ("trials.jsonl", trials)):
        with (path / name).open("x", encoding="utf8") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
    (path / "registration.json").write_text(json.dumps({
        "schema": SCHEMA, "seed": SEED,
        "independent_configuration_groups": len(configs),
        "splits": COUNTS, "physical_replays_planned": len(trials),
        "repeats_per_configuration": 1,
        "plan_sha256": digest(configs, trials),
        "status": "PROSPECTIVE_EXPLORATORY_NOT_EXECUTED",
        "not_confirmatory_v31_or_full_v3_protocol": True,
        "no_preexisting_results_reclassified_as_heldout": True,
    }, indent=2) + "\n", encoding="utf8")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    save(a.output)
    print("Registered 24 new physical configs, 96 planned action trials; NO DATA GENERATED")
