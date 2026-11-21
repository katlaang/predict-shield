"""Preregistration lock for the scored mechanism-lab campaign.

The lock hash covers PREREGISTRATION.json, the plan fingerprint and the code
that runs, records, audits, controls and scores the campaign. Once
PREREGISTRATION.lock.json says LOCKED, a scored campaign runs only while the
current hash equals the locked hash, or equals the new hash of a change
recorded in DEVIATIONS.md.

Usage, inside experiment-b/mechanism-lab:
  python prereg_gate.py status
  python prereg_gate.py check            # CI: fails on unrecorded change after locking
  python prereg_gate.py check --scored   # campaign: also fails while unlocked
  python prereg_gate.py lock             # writes the lock file; commit and tag it
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK_FILE = "PREREGISTRATION.lock.json"
DEVIATIONS_FILE = "DEVIATIONS.md"
COVERED_FILES = (
    "PREREGISTRATION.json", "plan.py", "pilot.py", "collect.py", "campaign.py",
    "audit.py", "scope.py", "controls.py", "verifier_scoring.py", "prereg_gate.py",
)
TAG = "mechanism-prereg-v1"
PLAN_VERSION = "v3.1"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_state(directory: Path = HERE) -> dict:
    """Hash every covered file and the generated plan; combine them."""
    sys.path.insert(0, str(directory))
    from audit import plan_fingerprint
    from plan import create_plan
    configs, trials = create_plan(version=PLAN_VERSION)
    state = {
        "files": {name: file_sha256(directory / name) for name in COVERED_FILES},
        "plan_fingerprint": plan_fingerprint(configs, trials),
    }
    state["lock_sha256"] = hashlib.sha256(
        json.dumps(state, sort_keys=True).encode()).hexdigest()
    return state


def recorded_deviation_hashes(text: str) -> list[str]:
    """New lock hashes declared in DEVIATIONS.md, in order."""
    return re.findall(r"^new_lock_sha256:\s*([0-9a-f]{64})\s*$", text, flags=re.M)


def evaluate(lock: dict, state: dict, deviations_text: str, *, scored: bool) -> tuple[bool, str]:
    """Decide whether the current code and protocol may run."""
    if lock.get("status") != "LOCKED":
        if scored:
            return False, "preregistration is not locked; a scored campaign cannot start"
        return True, "unlocked: changes are allowed until the lock is committed"
    if state["lock_sha256"] == lock.get("lock_sha256"):
        return True, "matches the locked preregistration"
    declared = recorded_deviation_hashes(deviations_text)
    if declared and declared[-1] == state["lock_sha256"]:
        return True, "differs from the lock; change recorded in DEVIATIONS.md"
    changed = sorted(name for name, digest in state["files"].items()
                     if lock.get("files", {}).get(name) != digest)
    if state["plan_fingerprint"] != lock.get("plan_fingerprint"):
        changed.append("plan fingerprint")
    return False, ("changed after locking without a DEVIATIONS.md entry: "
                   + ", ".join(changed))


def check(scored: bool, directory: Path = HERE) -> tuple[bool, str]:
    lock = json.loads((directory / LOCK_FILE).read_text())
    deviations = (directory / DEVIATIONS_FILE).read_text()
    return evaluate(lock, current_state(directory), deviations, scored=scored)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("status", "check", "lock"))
    parser.add_argument("--scored", action="store_true")
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps({"lock": json.loads((HERE / LOCK_FILE).read_text()),
                          "current": current_state()}, indent=1, sort_keys=True))
        return
    if args.command == "lock":
        lock = json.loads((HERE / LOCK_FILE).read_text())
        if lock.get("status") == "LOCKED":
            raise SystemExit("already locked; record changes in DEVIATIONS.md instead")
        state = current_state()
        (HERE / LOCK_FILE).write_text(json.dumps({
            "status": "LOCKED", "tag": TAG,
            "locked_at": datetime.now(timezone.utc).isoformat(), **state,
        }, indent=1, sort_keys=True) + "\n")
        print("locked", state["lock_sha256"], "- commit this file and tag the commit", TAG)
        return
    ok, reason = check(args.scored)
    print(("PASS: " if ok else "REFUSED: ") + reason)
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
