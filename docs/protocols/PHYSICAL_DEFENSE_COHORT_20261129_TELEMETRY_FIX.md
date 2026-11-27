# Telemetry-corrected physical defense development pilot: seed 20261129

**Registered as a new exploratory development run before seeing its outcomes. This is not independent confirmatory AI superiority evidence.**

## Cause of previous invalid AI inference

During seed 20261128, the Java enforcer returned `observation_type=operator_pre_action_v2`, while `pilot.py::operator_telemetry` accepted only `operator_pre_action`. The Python collector categorized available v2 telemetry as absent, causing the trained model's out-of-training-bounds protection to abstain. The physical action outcomes remain valid observations to the extent their independent evidence is complete, but the learned policy comparison is confounded by broken pre-action telemetry. The original results must not be rewritten or counted as an AI choice among working defense options.

## Minimal repair and pre-run guard

1. Accept only the actual Java v2 operator telemetry schema, matching the node identity and checking required measured numeric and Boolean fields. Preserve missingness if any response is unavailable, malformed, mislabeled, or belongs to another node. Never infer broker lag from local revision/cache values.
2. Add a regression contract test verifying all four valid Java v2 responses are admitted, and that legacy/malformed responses fail.
3. A live physical preflight must observe all four JVM operator feeds before the experiment. Persist a preflight record. Absent observations are an **invalid decision-evaluation input**, not an AI choice to monitor.
4. The physical four-stream scorer rejects an action cohort if any pre-action v2 operator reading is missing or misidentified. Save partial records and report **INCONCLUSIVE** rather than scoring the model.
5. In addition to selection, record explicit abstention reasons (`FEATURE_OUTSIDE_TRAINING_BOUNDS`, `NO_ELIGIBLE_ACTION_WITHIN_CALIBRATED_BUDGET`, or inference failure) where available.

## Frozen development measurement configuration

- Cohort generator: `plan.py::create_plan(seed=20261129, version="v3.1")`.
- Selection: lexicographically first test configuration in that generated plan.
- Exactly one new configuration, three reset episodes, four physically executed action arms = 12 action measurements.
- Historical model: same 1,200-trial source; train/calibration partitions unchanged and model frozen *before* the new physical measurements.
- Compare learned AI policy against monitor-only, policy resynchronization, and restart-if-permitted. Retain unchanged historical cost function (0.50 path exposure, 0.25 oracle security exposure, 0.25 failures / budget).
- Report direct resolved security exposures, failed legitimate requests, disruption-budget breaches, eligibility, and abstentions separately. Disallowed actions are never considered deployment decisions.
- If the workflow or any independent data stream is incomplete, classify inconclusive and retain available records. GitHub green CI is not a cybersecurity success criterion.
- This is restricted to disposable Docker/Kafka/JVM lab infrastructure, not external networks or production credentials.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
