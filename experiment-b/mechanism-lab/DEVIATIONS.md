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

### 1. Outcome report added to the lock

- **When:** 2026-11-21T06:46:02Z
- **What changed:** new `outcome_report.py`, which computes Q1, Q2, the per-arm error counts and the cost-matrix comparison at the 1:1, 1:5 and 1:20 ratios. `prereg_gate.py` now also hashes it.
- **Why:** the preregistration requires analysis code to be hashed before scored results exist. Only `verifier_scoring.py` covered Q3. Q4 (estimator calibration) is not covered by this entry.
- **Results seen:** none from the scored campaign, which has not started. The only results seen were from controls and CI pilots, as recorded in `CONTROLS_RESULT_2026_11_21.md`.
- **Automated:** yes. An AI assistant wrote the file and tested it only on synthetic records.

new_lock_sha256: 9422667f129b2da8d1d121387f2f8dc0a2b0f40777d6f4b7c635bf39243f973b
