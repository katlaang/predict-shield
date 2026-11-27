"""Frozen five-family / restart-authorization-crossed physical cohort generator.

Protocol is registered by merged PR #196, commit fbbbe898a0e1a0a37db6e5d973a2f148bcd5b320.
Only the sixteen predeclared pilot test configurations may be executed in pilot.
Later main configurations use deterministic, distinct shard namespaces.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
from pathlib import Path
from plan import (ACTIONS, SCHEMA_V31, create_plan, validate_plan,
                  v31_fault_settings)

REGISTRATION_COMMIT = "fbbbe898a0e1a0a37db6e5d973a2f148bcd5b320"
REGISTERED_SEED = int(REGISTRATION_COMMIT[:8], 16)
FAMILIES = (
    ("persistent_loss", "loss", "persistent"),
    ("persistent_paused_consumer", "consumer_paused", "persistent"),
    ("self_healing_delay", "delay", "self_healing"),
    ("self_healing_short_ttl", "loss", "self_healing"),
    ("withheld_publication", "withheld_publication", "withheld"),
)
PILOT_INDEXES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 18)
PREVIOUS_SEEDS = (20261128, 20261129, 20261130, 20261201)


def digest(*parts):
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def operational_identity(c):
    """Exclude equality of the whole experimental setup, not arbitrary IDs."""
    return tuple(json.dumps(c[k], sort_keys=True) for k in (
        "fault_mode", "fault_target", "cache_ttl_ms", "event_delay_ms",
        "requested_rps", "routing_profile", "node_service_latency_ms",
        "gateway_includes_hidden", "restart_permitted"))


def make_plan(*, phase: str, shard: int = 0):
    if phase not in ("pilot", "main") or type(shard) is not int or not 0 <= shard < 10:
        raise ValueError("Unknown registered cohort stage/shard")
    if phase == "pilot" and shard:
        raise ValueError("Pilot is exactly one locked cohort")
    effective_seed = REGISTERED_SEED + (0 if phase == "pilot" else 100000 + shard * 1009)
    configs, trials = create_plan(seed=effective_seed, version="v3.1")
    previous = {operational_identity(c) for seed in PREVIOUS_SEEDS
                for c in create_plan(seed=seed, version="v3.1")[0]}
    trial_cursor = 0
    for i, c in enumerate(configs):
        family, fault, control = FAMILIES[(i // 2) % len(FAMILIES)]
        authorization = i % 2 == 0
        rng = random.Random(int(digest("confirm-196", phase, shard, effective_seed, i), 16))
        c.update(
            schema=SCHEMA_V31,
            configuration_id=f"conf196-{phase}-{shard:02d}-{i:03d}",
            partition=("test" if i < 20 else "train" if i < 80 else "calibration"),
            fault_mode=fault,
            control_class=control,
            restart_permitted=authorization,
            cache_ttl_ms=rng.randint(11000, 28000) if control != "self_healing" or fault == "delay"
                         else rng.randint(2500, 4000),
            event_delay_ms=rng.randint(2000, 3000) if fault == "delay" else 0,
            fault_target=rng.choice(("enforcer-a","enforcer-b","enforcer-c","enforcer-hidden")),
            requested_rps=rng.randint(10, 55),
            measurement_seconds=4,
            routing_profile=rng.choice(("balanced","skewed_a","skewed_hidden")),
            node_service_latency_ms=[rng.choice((0, 15, 25, 55, 80)) for _ in range(4)],
            complexity_stratum="INTERACTION",
            gateway_includes_hidden=True,
            visible_enforcement_processes=4,
            oracle_inventory_processes=4,
            absolute_error_budget_requests=25,
            scenario_seed=rng.getrandbits(63),
            confirmatory_registration_sha=REGISTRATION_COMMIT,
            confirmatory_family=family,
        )
        if operational_identity(c) in previous:
            raise ValueError("A registered configuration repeats an earlier physical setup")
        for repeat in range(3):
            order = list(ACTIONS)
            init_seed = int(digest("196", phase, shard, i, repeat, effective_seed), 16)
            random.Random(init_seed).shuffle(order)
            for action in order:
                trial = trials[trial_cursor]
                trial.update(
                    schema=SCHEMA_V31,
                    run_id="confirm-196-" + digest(phase, shard, i, repeat, action,
                                                   effective_seed),
                    configuration_id=c["configuration_id"],
                    partition=c["partition"],
                    action_id=action,
                    repeat=repeat,
                    initial_state_seed=init_seed,
                )
                trial_cursor += 1
    validate_plan(configs, trials)
    if len({operational_identity(c) for c in configs}) != len(configs):
        raise ValueError("Duplicated physical setup in new cohort")
    return configs, trials


def selected(configs, *, phase):
    if phase == "pilot":
        result = [configs[i] for i in PILOT_INDEXES]
    elif phase == "main":
        result = [c for c in configs if c["partition"] == "test"]
    else:
        raise ValueError("Unknown cohort phase")
    if len(result) != (16 if phase == "pilot" else 20):
        raise ValueError("Wrong selected group count")
    pairs = {(c["confirmatory_family"], c["restart_permitted"]) for c in result}
    if len(pairs) != 10:
        raise ValueError("Five fault families x two restart-permission strata missing")
    return result


def save(path: Path, *, phase: str, shard: int):
    if path.exists():
        raise FileExistsError("Refuse to replace a frozen source plan")
    c,t=make_plan(phase=phase, shard=shard)
    chosen=selected(c,phase=phase)
    path.mkdir(parents=True)
    for name,rows in (("configurations.jsonl",c),("trials.jsonl",t)):
        (path/name).write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in rows))
    wanted={x["configuration_id"] for x in chosen}
    (path/"selected.json").write_text(json.dumps({
        "schema":"predict-shield/confirmatory-196-plan/1",
        "phase":phase,"shard":shard,
        "registration_commit_sha":REGISTRATION_COMMIT,
        "seed":REGISTERED_SEED,
        "selected":[{"id":x["configuration_id"],"family":x["confirmatory_family"],
                     "restart_permitted":x["restart_permitted"],
                     "start_index": next(i for i,y in enumerate(t)
                                      if y["configuration_id"]==x["configuration_id"])}
                    for x in chosen],
        "selected_arms":sum(y["configuration_id"] in wanted for y in t),
        "is_pilot_development_not_confirmatory":phase=="pilot",
        "outcomes_collected":False,
    },sort_keys=True,indent=2)+"\n")


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--phase",choices=("pilot","main"),required=True)
    p.add_argument("--shard",type=int,default=0)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    save(a.output,phase=a.phase,shard=a.shard)
    print("Frozen",a.phase,"plan at",a.output)
