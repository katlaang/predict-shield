"""Conservative P0/P1 admission and leakage audit for external cybersecurity cohorts.

Standard library only. Never downloads data, executes attacks, changes hosts,
loads untrusted model artifacts or treats scenario labels as event-level truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "predict-shield/research-cohort-manifest/1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLES = {"train", "calibration", "test"}
LABELS = {"attack", "benign", "unknown"}
BASES = {"independently_reviewed_event", "publisher_scenario", "unverified"}
RIGHTS = {"approved", "pending", "denied"}


def _valid_hash(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def audit(manifest: dict, *, dataset_root: Path | None = None) -> dict:
    """Fail closed on provenance/rights, repeated content and split leakage.

    A row marked attack by a publisher's scenario is NOT an independently
    reviewed event. Missing labels are always UNKNOWN, never benign.
    """
    errors: list[str] = []
    blockers: list[str] = []
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        return {"status": "REJECTED", "errors": ["unsupported manifest schema"],
                "blockers": [], "counts": {}}
    if not _valid_hash(manifest.get("protocol_sha256")):
        blockers.append("missing verified pre-test protocol SHA-256")
    sources = manifest.get("sources")
    rows = manifest.get("rows")
    if not isinstance(sources, list) or not sources:
        errors.append("sources must be a non-empty list")
        sources = []
    if not isinstance(rows, list) or not rows:
        errors.append("rows must be a non-empty list")
        rows = []

    source_by_id: dict[str, dict] = {}
    for s in sources:
        if not isinstance(s, dict):
            errors.append("source entry is not an object")
            continue
        sid = s.get("id")
        if not isinstance(sid, str) or not sid.strip() or sid in source_by_id:
            errors.append("missing or duplicate source ID")
            continue
        source_by_id[sid] = s
        url = s.get("official_url")
        if not isinstance(url, str) or not url.startswith("https://"):
            errors.append(f"{sid}: official HTTPS source URL required")
        rights = s.get("rights_status")
        if not isinstance(rights, str) or rights not in RIGHTS:
            errors.append(f"{sid}: invalid rights status")
        elif rights != "approved":
            blockers.append(f"{sid}: rights are {rights}, ingestion not authorized")
        if not s.get("rights_evidence"):
            blockers.append(f"{sid}: no documented permissions decision")
        expected = s.get("sha256")
        if not _valid_hash(expected):
            blockers.append(f"{sid}: source SHA-256 is not pinned")
        if dataset_root is None:
            blockers.append(f"{sid}: raw source bytes not checked in this run")
        elif not isinstance(s.get("relative_path"), str):
            blockers.append(f"{sid}: relative source file path missing")
        else:
            path = dataset_root / s["relative_path"]
            try:
                root = dataset_root.resolve(strict=True)
                real = path.resolve(strict=True)
                if not real.is_relative_to(root) or not real.is_file():
                    raise ValueError("path must refer to file inside dataset root")
                if _valid_hash(expected) and sha256_file(real) != expected:
                    raise ValueError("SHA-256 mismatch")
            except (OSError, ValueError) as exc:
                blockers.append(f"{sid}: source verification failed ({exc})")

    seen_ids: set[str] = set()
    by_hash: dict[str, str] = {}
    by_group: dict[tuple[str, str], str] = {}
    counts = Counter()
    truth = Counter()
    for idx, r in enumerate(rows):
        if not isinstance(r, dict):
            errors.append(f"row {idx} is not an object")
            continue
        uid, sid, group = r.get("id"), r.get("source_id"), r.get("capture_group")
        role, label, basis = r.get("role"), r.get("label"), r.get("truth_basis")
        digest = r.get("content_sha256")
        if not isinstance(uid, str) or not uid or uid in seen_ids:
            errors.append(f"row {idx}: duplicate/missing event ID")
        else:
            seen_ids.add(uid)
        if not isinstance(sid, str) or sid not in source_by_id:
            errors.append(f"row {idx}: unknown source")
            continue
        if not isinstance(group, str) or not group:
            errors.append(f"row {idx}: capture group missing")
            continue
        if not isinstance(role, str) or role not in ROLES or not isinstance(label, str) or label not in LABELS or not isinstance(basis, str) or basis not in BASES:
            errors.append(f"row {idx}: invalid role/label/truth basis")
            continue
        if label == "unknown" and basis == "independently_reviewed_event":
            errors.append(f"row {idx}: unknown cannot be independently confirmed benign/attack")
        if not _valid_hash(digest):
            errors.append(f"row {idx}: content SHA-256 missing")
            continue
        if digest in by_hash and by_hash[digest] != role:
            errors.append(f"row {idx}: identical content appears across splits")
        by_hash.setdefault(digest, role)
        key = (sid, group)
        if key in by_group and by_group[key] != role:
            errors.append(f"row {idx}: capture group leaks across splits")
        by_group.setdefault(key, role)
        counts[f"{role}_{label}"] += 1
        if role == "test":
            truth["test_independent_attack" if label == "attack" else
                  "test_independent_benign" if label == "benign" else
                  "test_unknown"] += int(basis == "independently_reviewed_event")
        if role == "calibration" and label == "benign" and basis == "independently_reviewed_event":
            truth["calibration_independent_benign"] += 1
        if label in ("attack", "benign") and basis != "independently_reviewed_event":
            counts["labeled_without_event_truth"] += 1

    if not counts["calibration_benign"]:
        blockers.append("no calibration benign rows")
    if truth["calibration_independent_benign"] < 1000:
        blockers.append("fewer than 1000 independently reviewed calibration benign rows")
    if truth["test_independent_attack"] < 30:
        blockers.append("fewer than 30 independently reviewed test attack events")
    if truth["test_independent_benign"] < 1000:
        blockers.append("fewer than 1000 independently reviewed test benign events")
    for part in ROLES:
        if not any(k.startswith(part + "_") for k in counts):
            blockers.append(f"missing {part} split")
    status = "REJECTED" if errors else "BLOCKED" if blockers else "READY_FOR_EVALUATION"
    return {
        "schema": "predict-shield/research-cohort-audit/1",
        "status": status,
        "errors": sorted(set(errors)),
        "blockers": sorted(set(blockers)),
        "counts": dict(sorted(counts.items())),
        "ground_truth_counts": dict(sorted(truth.items())),
        "metric_warning": "Never infer benign from not being in an attack scenario; no evaluation or scientific accuracy follows from this audit alone.",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("manifest", type=Path)
    p.add_argument("--data-root", type=Path, help="Local raw source files; optional but required to pass admission")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    result = audit(json.loads(a.manifest.read_text()), dataset_root=a.data_root)
    out = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if a.output:
        if a.output.exists():
            p.error("refusing to overwrite an earlier audit")
        a.output.write_text(out)
    print(out, end="")
    raise SystemExit(0 if result["status"] == "READY_FOR_EVALUATION" else 2)


if __name__ == "__main__":
    main()
