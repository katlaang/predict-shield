# Subsequent independent development cohort, seed 20261130

**Registered development protocol, not a preregistered independent confirmatory superiority study.** This new cohort has not been used in prior runs at the time its seed was committed.

The experiment uses the same protocol and safety limits as the previously registered [telemetry-corrected cohort 20261129](PHYSICAL_DEFENSE_COHORT_20261129_TELEMETRY_FIX.md), except its deterministic v3.1 plan uses seed **20261130** and therefore a new selected configuration. The last seed 20261129 has been consumed and must never be represented as fresh holdout evidence.

The fixed historical model is fitted on the 60 archived training groups and separately calibrated on 20 archived calibration groups **before** new physical action outcomes are visible. The lexicographically first test configuration from `create_plan(seed=20261130, version="v3.1")` is selected without inspecting outcomes. Four candidate action arms are separately reset and physically tested three times each, resulting in 12 measured action trials from **one independent configuration**.

All four pre-action JVM operator feeds must be valid v2 and observable. Invalid/missing telemetry makes the evaluation **INCONCLUSIVE** rather than creating artificial missingness features. Record the actual preflight as valid parseable JSON. Retain independently collected pre-action, verification, operations and oracle records even for negative or incomplete outcomes.

Report learned selector choices, explicit abstention reasons, the three unchanged fixed policies, direct verified security resolution, failed legitimate requests, measured budget breaches and the historical cost function. Do not modify the safety allowance or change utility weights to optimize an observed result.

Only disposable isolated Docker/Kafka/JVM laboratory infrastructure is in scope. A completed GitHub Actions run is not evidence of AI effectiveness.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
