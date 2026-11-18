"""Fit a local action-risk/disruption model from five original audited physical shards.

Train only on the original 60 train groups; calibrate only on the original
20 calibration groups.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from physical_shards import training_rows, SHARD_SCHEMA, ACTIONS
from train import train_evaluate


def measured_rows(archives: list[Path]) -> tuple[list[dict], dict]:
    train_rows, source = training_rows(archives)
    complete = []
    for archive in archives:
        with zipfile.ZipFile(archive) as package:
            names=[name for name in package.namelist() if name.endswith(".json")]
            if len(names) != 1:
                raise ValueError("One full measured JSON per shard required")
            shard=json.loads(package.read(names[0]))
        if (shard.get("schema") != SHARD_SCHEMA
                or shard.get("source_commit_sha") != source["source_commit_sha"]
                or shard.get("all_four_physical_record_streams_audited") is not True):
            raise ValueError("Unregistered or mixed-source physical dataset")
        rows=shard["sanitized_measured_training_rows"]
        digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        if digest != shard["sanitized_rows_sha256"]:
            raise ValueError("Physical shard digest mismatch")
        complete.extend(rows)
    if len(complete) != 1200:
        raise ValueError("Expected 1,200 real physical action measurements")
    parts={}
    arms=defaultdict(set)
    for row in complete:
        group, part, action, rep=row["group"],row["partition"],row["action"],row["repeat"]
        if part not in ("train","calibration","test") or action not in ACTIONS or rep not in (0,1,2):
            raise ValueError("Unregistered group/partition/action/repeat")
        if group in parts and parts[group] != part:
            raise ValueError("Group partition leakage")
        parts[group]=part
        key=(group,rep)
        if action in arms[key]:
            raise ValueError("Duplicate physical action")
        arms[key].add(action)
    if Counter(parts.values()) != {"train":60,"calibration":20,"test":20}:
        raise ValueError("Invalid group partition sizes")
    if len(arms)!=300 or any(set(actions)!=set(ACTIONS) for actions in arms.values()):
        raise ValueError("Missing paired physical outcomes")
    if len(train_rows)!=720:
        raise ValueError("Unreconciled original training observations")
    return complete, source


def train_physical(archives: list[Path], model_path: Path) -> dict:
    rows, source=measured_rows(archives)
    if model_path.exists():
        raise FileExistsError("Model artifact output already exists")
    report=train_evaluate(rows,export_path=model_path)
    report["measured_source"]=source
    report["actual_physical_measurements"]=1200
    report["original_train_groups"]=60
    report["original_calibration_groups"]=20
    report["previously_examined_test_groups"]=20
    report["new_independent_test_groups"]=0
    report["model_sha256"]=hashlib.sha256(model_path.read_bytes()).hexdigest()
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--shard-zips",nargs=5,type=Path,required=True)
    p.add_argument("--model",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    args=p.parse_args()
    if args.model.exists() or args.report.exists():
        p.error("Do not overwrite prior model or scientific report")
    args.model.parent.mkdir(parents=True,exist_ok=True)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    result=train_physical(args.shard_zips,args.model)
    args.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("Measured data model fitted; physical records:",result["actual_physical_measurements"],
          "; independently new test groups:",result["new_independent_test_groups"])


if __name__=="__main__":
    main()
