# Complete physical v3 AI-versus-rule campaign

## What actually happens

This workflow executes the original **100-configuration, four-fault-family, 3-repeat, four-action** physical Experiment B mechanism plan, exactly **1,200 real Docker/Kafka/Java action replays**. It reuses the originally specified seed, 60/20/20 configuration-level train/calibration/test partition, four measured fault families (loss, delay, duplicate, reorder), and unchanged v3 protocol blob SHA `3ac868036435720d6a809c3de3b3e265ea766fcf`.

It physically injects each registered fault, runs each registered defense action, independently observes the Java/JVM enforcers and Kafka effects, collects genuine before/after status and legitimate-request failures, and audits the four separate source-identified records per action. The executed lab must not use synthetic outcome generation.

Five isolated standard Linux GitHub-hosted runners each execute **20 configurations × 3 repeats × 4 actions = 240 physical actions**. They clean up their raw four-stream privileged data locally. Each uploads only audited, sanitized pre-action feature vectors, measured labels, source identity and a SHA-256 checksum. Raw oracle target snapshots, privileged credentials and unredacted service logs are not uploaded.

A sixth evaluator checks that the five independent shards represent exactly the 1,200 registered action IDs and 100 independent configurations with the correct partition memberships, no duplicate/omitted actions or hidden fault data in the model feature vector, and one source revision. Only then does it call the existing `train.train_evaluate` implementation.

## Deciding whether AI actually won

Four trained RandomForest action-effectiveness models predict future outcome components from pre-action operational telemetry and candidate-action identity. Pre-action features must not contain the injected hidden fault name/target or post-action oracle truth. Three physical action repeats in a configuration contribute observations but never count as three independent U.S. operators.

One deterministic-rule comparator is selected using **only the 20 calibration groups**, after rule-grid parameters have been tuned on the 60 training groups. The report compares the AI's actions with **all seven** predeclared deterministic alternative strategies on **20 untouched held-out configurations**. Its paired configuration bootstrap and one-sided multiple-baseline correction preserve uncertainty. If the AI loses, ties, or has a relative CI including no improvement, the full negative result remains in the artifact.

The existing `decision_superiority_audit` requires a positive baseline regret, 20 independently configured heldout groups and lower group-bootstrap relative-regret improvement greater than 10% against **each** of seven comparator policies under the declared Bonferroni-style conservative threshold. This is testbed-specific quantitative evidence, not proof of universally superior security, independent critical-infrastructure field performance, or production action authorization.

**Scientific limitations:** This campaign implements the original frozen four-family v3 framework. It is not the uncompleted six-family v3.1 plan that adds consumer-paused and physically stopped policy authority. Frozen v3 methods were designed before much of the subsequent exploratory engineering, but the v3 fault families have already been inspected during earlier pilot runs. Treat the campaign outcome with that awareness; do not reselect features, thresholds, config groups or outcomes after reading the held-out report. Follow-up prospective and external validation is required for stronger claims.

## Run

The GitHub Actions workflow `.github/workflows/full-v3-physical-ai.yml` runs all five physical shards, then the aggregate scorer only if each full physical shard passes. Its PR check executes actual measurements, not a mocked/test-fixture training run. It uploads:

- `v3-physical-measured-shard-0` through `-4`: reviewed sanitized real observations with exact hashes, **not raw oracle streams**.
- `v3-full-physical-ai-versus-seven-baselines-results`: measured 1,200-action study report, trained-model performance, locked-rule held-out comparison, bootstrap intervals, and a full limitations statement.

Each shard prints its count after every 12 actual actions, so partial activity is observable in CI. A failed shard does not claim successful full AI training.

## Separate field evidence

Even if the AI wins this physical research experiment, any claim of improving resilience in U.S. critical infrastructure requires separately documented independent real-operator evaluation. No artificial lab or Github Actions deployment can substitute for that.
