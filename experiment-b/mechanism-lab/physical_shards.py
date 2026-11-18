"""Load the five audited physical lab shard archives the lab action model is
trained from, verifying each archive's schema, completeness and checksum."""
from __future__ import annotations

import hashlib
import json
import zipfile
from collections import defaultdict
from pathlib import Path


ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")


SHARD_SCHEMA = "predict-shield/full-v3-exploratory-physical-shard/1"


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
