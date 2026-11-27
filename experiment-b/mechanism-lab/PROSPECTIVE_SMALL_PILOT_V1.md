# Registered small NEW-CONFIGURATION physical adaptive-defense pilot (v1)

**Status:** PROTOCOL REGISTERED BEFORE MEASUREMENTS. Source code/tests and physical run results are separate. This is a new exploratory pilot, **not** a statistically powered prospective confirmation of AI superiority.

## Frozen procedure

- Generator: `experiment-b/mechanism-lab/plan.py::create_plan(seed=20261127, version="v3.1")`, deterministic output.
- Select **the first configuration by ascending index whose `partition` equals `test`**. Do not choose a favorable fault or response class after seeing results. This selection rule is committed before the run; no results have been seen.
- Execute exactly **four action arms × three repeat episodes = 12 physically measured trials** on the four-enforcer disposable Docker/Redpanda laboratory; action order is already randomly permuted per repeat by the plan. Do not substitute simulation labels.
- Training source: previously executed full 1,200-trial campaign, run ID `44879497946`, source artifact named `mechanism-scored-records`, pinned artifact ZIP SHA256 `08a8bb16ba3b50447510c15194acbb6a4c41534062c3fcf1aead626a9a7431e3`. Train model using historical 60 train/20 calibration configurations only.
- Freeze model before new configuration outcomes are visible; do not retrain or change thresholds after the pilot. Record local SHA256 of fitted model artifact and all new campaign records.
- Model sees ONLY the same monitor-only canonical pre-action telemetry and trial restrictions as the three fixed policies, never hidden injected fault or independent post-action oracle truth.
- Comparators: `monitor_only`, `resync_policy`, `restart_if_allowed`. The learned policy is a cost optimizer constrained by calibrated disruption bounds; abstentions and prohibited choices fall back to monitor-only and are counted.
- Primary descriptive cost = 0.50 × independently observed gateway exposure fraction upper bound + 0.25 × independently measured residual authorization exposure indicator + 0.25 × actual failed legitimate requests / declared allowed failures. These weights are inherited, not altered for this run.
- Show direct security resolved episodes, failed legitimate requests, actual disruption-budget breaches, false VERIFIED (if any) and abstentions. Never mask security resolution trade-offs behind a composite score.
- A real authority outage is **not** included in this pilot. In any unexpected outage that invalidates oracle truth, mark results **INDETERMINATE** and exclude incomplete episodes; do not force a label.
- Source commit is pinned by `campaign.py` and every run's four-stream provenance.
- Stopping: no replays are allowed over existing result IDs, at most one infrastructure rerun per episode, exclude rather than fabricate failed measurements, stop on unregistered errors. If incomplete, report `INCONCLUSIVE` and do not compare models.

## Results interpretation

A sample of one independent configuration group (three repeated action episodes) **cannot establish superiority, statistical significance, or cross-fault generalization**. It only checks that the frozen AI selector and fixed-policy comparators can be evaluated on new independently measured physical outcomes without reusing historical evaluation labels. Do not multiply by 12 to claim 12 independent configurations.

## Safeguards

Run only in disposable localhost-bound Docker Compose. No third-party sites, real customer systems, live denial-of-service traffic, production policy credentials or actual infrastructure allowed.

If the small pilot passes operational validation, register a **separate**, sufficiently powered disjoint physical campaign with new faults, hidden configurations, more independent configuration groups, no reuse of this pilot for confirmation, a fixed decision utility, primary superiority margin, grouped confidence intervals, and safety noninferiority threshold.

## Required artifact evidence

1. Actual plan JSONL and SHA256.
2. Training artifact hash and model SHA256, before outcomes.
3. New four-stream physical records (privileged oracle retained only as restricted GitHub Action artifact).
4. Per-action real request counts and independent authorization truth.
5. Small-pilot paired cost/success/failure report labelled `SMALL_NEW_CONFIGURATION_PILOT_NOT_SUPERIORITY_PROOF`.
6. CI run ID and evidence digest.
