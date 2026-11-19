"""Fail-closed preflight for a prospective, independently labeled detection cohort.

This does not retrieve data, run an AI model, or estimate detection accuracy.
It prevents accidental reuse of registered recordings and group leakage.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = {"recording_id", "sha256", "publisher", "campaign_id",
            "environment_id", "label", "source_url", "reviewer_id"}
VALID_LABELS = {"attack", "benign"}


def validate(candidate: dict, historical: dict) -> dict:
    errors = []
    entries = candidate.get("recordings", [])
    if not isinstance(entries, list) or not entries:
        return {"eligible": False, "errors": ["nonempty recordings array required"],
                "fresh_model_performance_established": False}
    old = [item for group in ("development", "held_out", "holdout", "test")
           for item in historical.get(group, []) if isinstance(item, dict)]
    old_hashes = {item.get("sha256") for item in old}
    old_urls = {item.get("url") for item in old}
    old_files = {item.get("file") for item in old}
    seen_ids, seen_hashes, groups, labels = set(), set(), {}, set()
    for idx, item in enumerate(entries):
        if not isinstance(item, dict):
            errors.append(f"recording {idx}: expected object")
            continue
        missing = REQUIRED - set(item)
        if missing:
            errors.append(f"recording {idx}: missing {sorted(missing)}")
            continue
        rid = item["recording_id"]
        digest = item["sha256"]
        if not isinstance(rid, str) or not rid.strip() or rid in seen_ids:
            errors.append(f"recording {idx}: missing/duplicate ID")
        seen_ids.add(rid)
        if not isinstance(digest, str) or len(digest) != 64 or any(
                c not in "0123456789abcdef" for c in digest):
            errors.append(f"recording {idx}: malformed lowercase SHA256")
        if digest in old_hashes or item["source_url"] in old_urls or item.get("file") in old_files:
            errors.append(f"recording {idx}: already registered/scored historical source")
        if digest in seen_hashes:
            errors.append(f"recording {idx}: duplicate content")
        seen_hashes.add(digest)
        if item["label"] not in VALID_LABELS:
            errors.append(f"recording {idx}: unsupported label")
        labels.add(item["label"])
        if not all(isinstance(item[k], str) and item[k].strip() for k in
                   ("publisher", "campaign_id", "environment_id", "source_url", "reviewer_id")):
            errors.append(f"recording {idx}: empty provenance/reviewer")
        split = item.get("split")
        if split not in ("development", "test"):
            errors.append(f"recording {idx}: split must be development or test")
        group = (item["publisher"], item["campaign_id"], item["environment_id"])
        if group in groups and groups[group] != split:
            errors.append(f"recording {idx}: publisher/campaign/environment group crosses splits")
        groups[group] = split
        if item["label"] == "attack" and not item.get("attack_technique"):
            errors.append(f"recording {idx}: attack technique required")
        if item["label"] == "benign" and item.get("attack_technique"):
            errors.append(f"recording {idx}: benign example must not claim an attack technique")
    test = [x for x in entries if isinstance(x, dict) and x.get("split") == "test"]
    if not any(x.get("label") == "attack" for x in test):
        errors.append("test split has no independently labeled attacks")
    if not any(x.get("label") == "benign" for x in test):
        errors.append("test split has no independently labeled benign recordings")
    if not any(x.get("split") == "development" for x in entries if isinstance(x, dict)):
        errors.append("development split absent")
    if not candidate.get("independent_label_method") or not candidate.get("frozen_protocol_sha256"):
        errors.append("independent label method and frozen protocol fingerprint required")
    if candidate.get("model_has_access_to_test_content") is not False:
        errors.append("explicit test-content isolation declaration required")
    return {"eligible": not errors, "errors": errors,
            "recordings": len(entries), "test_recordings": len(test),
            "fresh_model_performance_established": False,
            "manual_source_authentication_required": True}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--historical", type=Path, default=Path(__file__).with_name("split.json"))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = validate(json.loads(args.candidate.read_text()),
                      json.loads(args.historical.read_text()))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    if not result["eligible"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
