"""Training-only Extra Trees stability: NEVER select using examined test outcomes.

Read actual measured and independently audited v3 shard archives. Use only
registered train rows. Five fixed group re-partition seeds x five held-out
training folds. All comparisons against fixed-monitor use measured outcomes.
This is iterative MODEL DEVELOPMENT, not independent superiority evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
SHARD_SCHEMA = "predict-shield/full-v3-exploratory-physical-shard/1"
SEEDS = (101, 202, 303, 404, 505)


def training_rows(archives: list[Path]) -> tuple[list[dict], dict]:
    if len(archives) != 5:
        raise ValueError("Exactly five audited physical shard archives required")
    rows, hashes, commits, shard_ids = [], [], set(), set()
    for archive in archives:
        with zipfile.ZipFile(archive) as z:
            candidates = [name for name in z.namelist() if name.endswith(".json")]
            if len(candidates) != 1:
                raise ValueError("Expected one complete measured shard JSON")
            shard = json.loads(z.read(candidates[0]))
        if (shard.get("schema") != SHARD_SCHEMA or
                shard.get("all_four_physical_record_streams_audited") is not True or
                shard.get("physical_replays_completed") != 240 or
                shard.get("raw_oracle_records_published") is not False):
            raise ValueError("Nonphysical or incomplete shard")
        sid = shard.get("shard_id")
        if type(sid) is not int or sid not in range(5) or sid in shard_ids:
            raise ValueError("Duplicate or unregistered physical shard")
        shard_ids.add(sid)
        original = shard.get("sanitized_measured_training_rows")
        if not isinstance(original, list) or len(original) != 240:
            raise ValueError("Incomplete physical action observations")
        encoded = json.dumps(original, sort_keys=True,
                             separators=(",", ":")).encode()
        sha = hashlib.sha256(encoded).hexdigest()
        if sha != shard.get("sanitized_rows_sha256"):
            raise ValueError("Measured shard integrity hash mismatch")
        hashes.append(sha)
        commits.add(shard["source_commit_sha"])
        # IMPORTANT: test and calibration labels are not returned or used.
        rows.extend(r for r in original if r.get("partition") == "train")
    if shard_ids != set(range(5)) or len(commits) != 1:
        raise ValueError("Missing independent shard or mixed source revisions")
    if len(rows) != 720 or len({x["group"] for x in rows}) != 60:
        raise ValueError("Expected 60 train groups, 3 repeats, 4 actions")
    grouping = defaultdict(set)
    for row in rows:
        if row.get("partition") != "train" or row.get("fault") == "authority_outage":
            raise ValueError("Unexpected partition or UNKNOWN truth")
        key = (row["group"], row["repeat"])
        if row["action"] in grouping[key]:
            raise ValueError("Duplicate measured action")
        grouping[key].add(row["action"])
    if len(grouping) != 180 or any(actions != set(ACTIONS) for actions in grouping.values()):
        raise ValueError("Incomplete training-only four-action repeats")
    return rows, {
        "source_commit_sha": next(iter(commits)),
        "original_physical_shard_sha256s": hashes,
        "training_only_rows": len(rows),
        "training_only_configurations": 60,
        "calibration_or_test_labels_used_for_selection": False,
    }


def grouped_stability(rows: list[dict], *, seeds=SEEDS,
                      estimators: int = 200, leaf: int = 5) -> dict:
    import numpy as np
    from sklearn.ensemble import ExtraTreesRegressor
    from sklearn.model_selection import GroupKFold
    from train import to_features
    from decision_eval import observed_utility

    if len({r["group"] for r in rows}) != 60 or any(
            r["partition"] != "train" for r in rows):
        raise ValueError("Only the independent 60 training groups are allowed")
    if estimators < 16 or leaf < 1 or len(set(seeds)) != len(seeds):
        raise ValueError("Unregistered model or repeated split settings")
    x = np.asarray([to_features(r) for r in rows], dtype=float)
    y = np.asarray([observed_utility(r) for r in rows], dtype=float)
    ids = np.asarray([r["group"] for r in rows])
    all_groups = sorted(set(ids))
    lookup = defaultdict(dict)
    for r in rows:
        key = (r["group"], r["repeat"])
        if r["action"] in lookup[key]:
            raise ValueError("Duplicate group action")
        lookup[key][r["action"]] = r
    if len(lookup) != 180 or any(set(arms) != set(ACTIONS) for arms in lookup.values()):
        raise ValueError("Missing measured action repeat")
    folds = []
    for split_seed in seeds:
        shuffled = all_groups.copy()
        random.Random(split_seed).shuffle(shuffled)
        numbered = {g: i for i, g in enumerate(shuffled)}
        fold_labels = np.asarray([numbered[g] for g in ids])
        for fold_id, (train_idx, val_idx) in enumerate(
                GroupKFold(n_splits=5).split(x, y, groups=fold_labels)):
            model = ExtraTreesRegressor(
                n_estimators=estimators, min_samples_leaf=leaf,
                random_state=20261114, n_jobs=1)
            model.fit(x[train_idx], y[train_idx])
            validation_groups = sorted(set(ids[val_idx]))
            requests = []
            keys = []
            for group in validation_groups:
                for rep in (0, 1, 2):
                    arms = lookup[(group, rep)]
                    ref = arms["monitor_only"]
                    eligible = [action for action in ACTIONS if
                                action != "restart_enforcer" or ref["restart_permitted"]]
                    for action in eligible:
                        keys.append((group, rep, action))
                        requests.append(to_features({**ref, "action": action}))
            predicted = dict(zip(keys, model.predict(np.asarray(requests, dtype=float))))
            ai_group, monitor_group = [], []
            choices = Counter()
            for group in validation_groups:
                ai_reps, monitor_reps = [], []
                for rep in (0, 1, 2):
                    arms = lookup[(group, rep)]
                    ref = arms["monitor_only"]
                    eligible = [a for a in ACTIONS if
                                a != "restart_enforcer" or ref["restart_permitted"]]
                    selected = min(eligible, key=lambda a: (predicted[(group, rep, a)], a))
                    choices[selected] += 1
                    measured = {a: observed_utility(arms[a]) for a in eligible}
                    optimal = min(measured.values())
                    ai_reps.append(measured[selected] - optimal)
                    monitor_reps.append(measured["monitor_only"] - optimal)
                ai_group.append(sum(ai_reps)/3)
                monitor_group.append(sum(monitor_reps)/3)
            ai_mean = sum(ai_group)/len(ai_group)
            monitor_mean = sum(monitor_group)/len(monitor_group)
            folds.append({
                "split_seed": split_seed, "fold": fold_id,
                "independent_validation_groups": len(validation_groups),
                "ai_mean_regret": ai_mean,
                "fixed_monitor_mean_regret": monitor_mean,
                "monitor_minus_ai_mean_regret": monitor_mean - ai_mean,
                "action_selection_counts": dict(choices),
            })
    better = sum(v["monitor_minus_ai_mean_regret"] > 1e-9 for v in folds)
    worse = sum(v["monitor_minus_ai_mean_regret"] < -1e-9 for v in folds)
    tied = len(folds)-better-worse
    return {
        "schema": "predict-shield/train-group-repeated-stability/1",
        "model": "ExtraTreesRegressor",
        "model_settings": {"n_estimators": estimators, "min_samples_leaf": leaf,
                           "random_state": 20261114},
        "train_only_independent_groups": 60,
        "group_repartition_seeds": list(seeds),
        "group_validation_folds": len(folds),
        "folds_ai_better_than_fixed_monitor": better,
        "folds_ai_worse_than_fixed_monitor": worse,
        "folds_tied": tied,
        "mean_regret_reduction": sum(v["monitor_minus_ai_mean_regret"] for v in folds)/len(folds),
        "positive_improvement_in_every_fold": worse == 0 and tied == 0,
        "test_or_calibration_used_for_training_selection": False,
        "confirmatory_superiority_established": False,
        "same_training_groups_reused_across_folds_not_25_independent_field_studies": True,
        "fold_details": folds,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--shard-zips", type=Path, nargs=5, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        raise FileExistsError("Never overwrite research output")
    rows, source = training_rows(args.shard_zips)
    result = grouped_stability(rows)
    result["provenance"] = source
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(json.dumps({
        "folds_ai_better": result["folds_ai_better_than_fixed_monitor"],
        "folds_ai_worse": result["folds_ai_worse_than_fixed_monitor"],
        "folds_tied": result["folds_tied"],
        "train_only": True,
        "superiority_established": False,
    }))


if __name__ == "__main__":
    main()
