# Preregistration, controls and verifier scoring

This page covers the safeguards that must be in place before the scored
mechanism-lab campaign runs. The campaign uses plan v3.1: 100 configurations ×
4 actions × 3 repeats = 1,200 trials.

Plan v3.1 replaced v3 before locking. The first control run
(`CONTROLS_RESULT_2026_11_21.md`) showed that most v3 faults healed by
themselves. v3.1 is made of:

- 70 configurations whose fault persists past the 6 s window: 35 loss and
  35 physically paused listener, each with cache TTL 10 to 30 s.
- 30 self-healing configurations: 15 delay and 15 loss with TTL 2.5 to 4 s.
  For these, `monitor_only` is a legitimate outcome.

v3 stays available for the CI pilot.

## 1. Protocol lock

- `PREREGISTRATION.json` fixes the following before any scored trial:
  - the questions, the ground-truth label and the meaning of VERIFIED;
  - the metrics, cost matrix and sensitivity ratios;
  - the controls, the exclusion rules, the rerun rule and the stopping rule;
  - analysis isolation and the commitment to report null results.
- `prereg_gate.py` computes one hash. It covers that file, the plan
  fingerprint, and the code that runs, records, audits, controls and scores
  the campaign.
- `PREREGISTRATION.lock.json` stays `UNLOCKED` until the controls pass on the
  code to be locked. Then `python prereg_gate.py lock` records the hash. That
  commit is tagged `mechanism-prereg-v1`.
- `campaign.py --scored` refuses to start unless the gate passes. A scored
  records directory is bound to its lock hash, so pilot and scored records
  cannot mix.
- CI runs `prereg_gate.py check` on every change. Once the preregistration is
  locked, CI fails on any change to the covered files unless `DEVIATIONS.md`
  records it with its new hash.
- **Rerun rule:**
  - a trial that fails for an infrastructure reason is rerun once, after the
    lab is ready again;
  - a second failure excludes it;
  - every rerun and exclusion is appended to `reruns.jsonl` or
    `excluded.jsonl`;
  - the rerun budget counts across invocations;
  - validation errors are never rerun;
  - the campaign stops if exclusions exceed 5% of the plan.

## 2. Testbed controls (`controls.py`)

- **Positive controls:** ten registered cells, four runs each. Every cell sits
  at an end of a plan class's range.
  - Each run injects the fault on `enforcer-b`, publishes the revocation, and
    takes no action. The oracle is read every second for 36 s, long enough
    to see a 30 s cache expire.
  - Each run is NOT_EXERCISED, PERSISTED (still exposed at 6 s) or
    SELF_HEALED. Self-heal rate and heal times are reported.
  - A cell's plan class is confirmed only if all of its runs match. An
    unconfirmed cell blocks locking.
- **Negative control:** no fault, the same schedule. Any exposure seen by the
  oracle or the gateway verifier invalidates the campaign until the cause is
  recorded.
- **Faults the testbed cannot observe** are listed with reasons in
  `PREREGISTRATION.json`: network partition, broker outage, authority outage,
  more than four enforcers, and crash under load.

## 3. Verifier scoring (`verifier_scoring.py`)

- **The label** is the oracle's post-action reading. A separate process reads
  cache state and probes each target directly. The verifier never reads it.
- **Two verdicts are scored** per fault mode and action:
  - the gateway scope verdict;
  - a dual-evidence verdict that adds post-action operator telemetry and
    abstains when the two kinds of evidence disagree.
- **Reported** for each: sensitivity, specificity and abstain rate, with
  false VERIFIED (says fixed, actually exposed) counted on its own.
- **Sources:** CI scores the 40 pilot trials and the 40 control runs.

## Not covered here

- **Do-nothing share:** a minimum share of cases where doing nothing is the
  right answer is not set yet.
- **Cost reporting:** the cost-weighted report is not built yet; the cost
  matrix itself is fixed in the preregistration.
- **No AI-versus-rule comparison:** the campaign makes no comparison between
  the action-outcome estimator and any deterministic rule.
