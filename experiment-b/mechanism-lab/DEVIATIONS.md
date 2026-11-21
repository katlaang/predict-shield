# Deviations from the mechanism-lab preregistration

Every change to the preregistration, the plan or the covered code after
`PREREGISTRATION.lock.json` says LOCKED is recorded here before the changed
code runs a scored trial. `prereg_gate.py` accepts the changed code only when
the last `new_lock_sha256` line below equals its current hash.

Each entry gives:

- **When:** UTC timestamp.
- **What changed:** files and the nature of the change.
- **Why:** the reason.
- **Results seen:** whether any scored result had been seen before the
  change, and which.
- **Automated:** whether an AI assistant wrote or tuned the change.
- `new_lock_sha256: <64 hex characters>` from `python prereg_gate.py status`.

Entries are appended, never edited or removed.

## Entries

None since locking (tag `mechanism-prereg-v1`). Changes made before locking, after the control runs, are described in `PREREGISTRATION.json` (plan.revision_reason) and `CONTROLS_RESULT_2026_11_21.md`.
