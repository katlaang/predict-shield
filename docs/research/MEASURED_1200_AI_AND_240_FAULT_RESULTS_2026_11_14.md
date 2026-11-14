# Actual full AI evaluation and persistent-fault pilot outcomes, November 14, 2026

These are results of **actual physically executed disposable Kafka/Java/Docker laboratory trials**, not planned manifests, synthetic test data, U.S. operator field validation or evidence of production effectiveness.

## Study 1: Original frozen v3 physical AI-versus-rules evaluation

- Source: [GitHub Actions 43629488209](https://github.com/katlaang/predict-shield/actions/runs/43629488209), implementation merged in [PR #57](https://github.com/katlaang/predict-shield/pull/57)
- **1,200/1,200 physical action replays**: 100 independent configurations × 3 repeats × 4 actions. Five separate Docker worker shards individually passed. Source Git SHA `25f8710ee625f16ffdc288350c6e04865676ee2d`.
- Splits: 60 training configurations, 20 calibration configurations and 20 held-out configurations. A random-forest action-effectiveness selector was trained on actual observed security and service-health outcomes. Deterministic baseline was selected on calibration groups only.
- Locked strongest non-AI baseline: `fixed_monitor`. AI held-out mean hindsight regret **0.003291850218750362** versus **0.0027853271145825884** for fixed-monitor. Regret reduction (baseline minus AI) = **−0.0005065231041677737**, i.e. the AI was numerically **worse**.
- Configuration-cluster bootstrap 95% absolute interval for AI advantage **[−0.0015193520031266665, +0.000009410560520143607]**. Relative improvement interval **[−49.915%, +6.508%]**. The 10% minimum improved-regret claim was not supported, and not all seven predeclared non-AI comparators were beaten.
- The source-generated output explicitly reports `LAB_SUPERIORITY_NOT_ESTABLISHED` and `lab_superiority_supported_under_declared_test=false`. **Do not describe this as a successful AI model performance demonstration.**
- Full sanitized report artifact `v3-full-physical-ai-versus-seven-baselines-results`, source report SHA-256 `338e90cb58a65a3c9f775cba9ab3856a52598a79c5f8790f61a963b6468cc5e0`.

## Study 2: Five-family physically persistent fault action-headroom pilot

- Source: [GitHub Actions 43630571154](https://github.com/katlaang/predict-shield/actions/runs/43630571154), implementation merged in [PR #59](https://github.com/katlaang/predict-shield/pull/59).
- **240/240 physically executed action replays**, **30 independent operating configurations**, across five fault families (loss, delay, duplicate, reorder and consumer-paused): six configurations per family, two repeats, four physical actions. Independent four-stream integrity reported **0 missing, 0 invalid, 0 partial, 0 unexpected**.
- In **7/30 configurations (23.33%)**, fixed resynchronization was outside the predeclared near-optimal action set. Near-optimal singleton action counts: monitor-only **5**, restart-enforcer **2**, resync-policy **6**. Other configurations had ties or lacked a singleton optimum.
- Source Git SHA `b9ab517471d985f39758041927ded00d78acebe2d`, report SHA-256 `ae9f346d00f4f88d45f31171202800d9c1fda9ac8ba4b6ca6f482e199d3b0f2f`.
- This pilot **did not fit or test an AI model**. It tested whether different defensive actions can have measurably different outcomes under a physically witnessed persistent Kafka fault. Its results alone do not establish model value or v3.1 feasibility.

## Subsequent training-only research

To improve generalization without optimizing against the already-known held-out 20 groups, a separate training-only model development experiment in [PR #60](https://github.com/katlaang/predict-shield/pull/60) compared several candidates using the original 60 train groups. Extra Trees gave the lowest initial fivefold training-only regret among five candidates. Across 25 repeated development folds, the canonical repository run found **15 better, 9 worse and 1 tie** versus fixed monitoring. This is **not consistent superiority** and the 25 folds are dependent reuses of the same 60 configurations.

A conservative incremental-cost development model with a 0.03 minimum predicted benefit had **8 positive, 0 negative and 7 tied** folds across 15 training-only folds, but intervened only **28 times out of 540** development decisions. That margin was examined on development data, not predeclared as a confirmatory hypothesis. It must be frozen and independently tested on newly registered physical conditions before any advantage is claimed.

## Scientific gate

- Do **not** repeatedly evaluate already examined held-out groups until the model looks favorable. Their outcomes are now known and cannot be restored to uninspected confirmation by renaming splits.
- Freeze model, feature set, utility, action eligibility, uncertainty handling, fallback and analysis plan using training and calibration only.
- Collect **new** independently registered physical configurations. Measure intervention results and operational side effects with independent verified oracle scope, including persistent faults. Disallow unavailable actions, preserve UNKNOWN authority truth and operational safety limits.
- Report **all** fixed and telemetry-rule comparators, cluster/group-level uncertainty, negative cases and generalization limitations. The final six-family authority-outage study remains separately blocked by primary outcome semantics.
- Neither completed laboratory study measures actual U.S. critical-infrastructure operator resilience; independent field validation remains outstanding.
