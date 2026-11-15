# Prospective second physical validation of PREDICT-SHIELD action-value AI

**Registration date: November 15, 2026. This specification is committed before the new 480-action campaign is executed.**

This is a **single continuation of the AI decision-quality research**, not additional product features, an unrelated model benchmark or an exploratory CVE-version study. The goal is to check whether PREDICT-SHIELD's existing action-value model continues to make better decisions when observed under **more new operating conditions and one fault family never used to train the model**.

## Frozen model and historical results

- Source training experiment: [1,200 physically executed Kafka/JVM actions](https://github.com/katlaang/predict-shield/actions/runs/43629488209), 60 original train, 20 previously used calibration and 20 previously examined test configurations.
- Frozen action-value training: [run 43682077804](https://github.com/katlaang/predict-shield/actions/runs/43682077804), actual train-only matched-action HistGradientBoosting model. Model artifact `paired-real-physical-action-value-model-and-historical-validation`, frozen SHA-256 `35a040b26a935bfb529f6247dbd0be1a01288294f8fb7089d4de60366adf3f92`.
- Fixed decision threshold **0.01**: intervene only if predicted cost improvement over monitoring exceeds 0.01. Restart must be independently permitted. Every action is proposed from current pre-action operator-visible telemetry and candidate identity, not fault-injection labels or post-action oracles.
- The previous completely new 24-configuration/192-physical-action run ([43682440153](https://github.com/katlaang/predict-shield/actions/runs/43682440153)) gave AI regret 0.004285 vs monitor 0.020829, ~79.4% point regret reduction, but the paired 95% interval crossed no improvement and multiplicity-adjusted superiority was not established. **Those observations cannot be reused as a second confirmatory holdout or to retune the frozen model**. This new independent *configuration* registration is intended as replication within a still-shared lab topology.

## Frozen new registration

- Seed: **20261115312**, distinct from old v3 and prior fresh test. All selected configurations are named `new-five-family-###`, not any old `mechanism-`, `fresh-benefit-` or `v31-five-` ID.
- Exactly **60 new configurations**, across three predeclared complexity strata `SIMPLE`, `INTERACTION`, `PARTIAL_VISIBILITY` and five real physical fault mechanisms: `loss`, `delay`, `duplicate`, `reorder`, and **`consumer_paused`**. Four configurations per (fault, stratum) cell, 12 independent configurations per fault.
- The fifth family means **physically pausing a Java Spring Kafka listener container** while its HTTP endpoint remains healthy, not inventing a stalled or unavailable value in the JSON features. It requires a separate independently witnessed pause record and pre-action authorization exposure. Every trial explicitly resumes Kafka consumers before and after. The older six-family `authority_outage` condition is excluded because authoritative truth may be **UNKNOWN**; do not relabel UNKNOWN as either a successful or failed action.
- Two repetitions and exactly four distinct physically executed defenses per configuration: `resync_policy`, `restart_enforcer`, `gateway_restrict`, and `monitor_only`. Registered total: **60 × 2 × 4 = 480 actual independent action-replay observations**, yielding **120 AI-v-rule offline decision instances** but only 60 independent configured groups for uncertainty inference.
- Five separate GitHub-hosted disposable Kafka/JVM runners, one fault family each, 96 actions per runner. Every run's separate pre_action, verification, operations and independent oracle streams must pass the original per-action and full-campaign integrity checks. The private raw oracle output is deleted; only sanitized pre-action feature vectors, measured outcomes and immutable hashes are published.
- The same Java/Kafka four-enforcer testbed, fixed utility objective, approved action IDs, non-AI rules, model and source labels as earlier research. **This does not establish transfer to real critical-infrastructure operator facilities.**

## Preregistered policy and statistical rule

Before retrieving any new labels, freeze all decision policies:

1. The exact trained model SHA-256 above; original `HistGradientBoostingRegressor` settings and **0.01** action-selection margin. No tuning of weights, features, confidence threshold, test case membership or seed after seeing outcomes.
2. The strongest previous deterministic comparator `fixed_monitor`, and **all seven** previously registered conventional comparators: `observable_telemetry_rule`, `engineering_rule`, `train_tuned_rule`, `fixed_resync`, `fixed_restart_or_gateway`, `fixed_gateway`, `fixed_monitor`. The train-fitted deterministic rule parameters are frozen at `gateway_threshold_rps=55`, `load_threshold_rps=65`, `revision_spread_threshold=0`, `ttl_threshold_ms=10000`; never tune them from these new physical observations.
3. Primary outcome: **mean per-configuration hindsight decision regret** relative to the best allowed, independently measured physical action under the registered utility
   `0.50 × time-integrated gateway exposure fraction + 0.25 × remaining control exposure + 0.25 × failed legitimate requests / declared laboratory error allowance`.
   A smaller regret is better. Both AI and comparator receive identical observed action-outcome data, evaluated *after* choosing offline from a single pre-action snapshot.
4. Group-cluster paired bootstrap: **5,000** fixed-seed draws (`20261115321`), treating each of **60 configured cases** as independent and two repetitions as within-group dependent. Report ordinary two-sided 95% absolute improvement intervals and conservative one-sided Bonferroni-adjusted lower bounds at alpha `0.05/7` for the seven predeclared deterministic policies. Report all point regrets and the exact denominator.
5. **Strong superiority criterion, preregistered:** a familywise-adjusted lower bound exceeding **10% relative regret improvement against each of the seven conventional baselines**, **and zero AI-selected actions breaching the registered laboratory legitimate-request failure allowance**. If any policy ties, outperforms AI, or its CI includes no improvement, the all-comparator superiority verdict remains FALSE. Do not reduce alpha, replace fixed monitor, or choose only easy fault groups to support a positive claim.
6. Separately report descriptive AI/regret and change-budget metrics for each of the five actual physical fault families, especially the new consumer-paused mechanism. These small subgroups are **not** 12 independent operator sites or five independently powered hypothesis tests.

**No model receives permission to actuate in a real operator environment** from this evaluation. Physical action replays are testbed experiments, and model choices are compared offline to their independently recorded results. The laboratory error allowance is a research denominator, **not a real operator's signed remaining SLO budget**.

## Evidence and failure handling

All 480 real actions are required. An incomplete run, missing or invalid independent oracle, missing Kafka pause witness, failed assertion, duplicated case, mixed source commit, altered trained model fingerprint or absent model artifact **fails the campaign**. Partial data must not produce a positive model result. Negative comparisons, abstentions, service failures, controls exceeded and inconclusive uncertainty must remain in the immutable report.

The complete audit report, source hashes, actual model choices, five group diagnostics, all seven baseline comparisons and statistical criterion will be archived by `.github/workflows/frozen-five-family-physical-ai.yml` under the artifact `frozen-ai-five-fault-real-480-physical-actions-and-seven-rules`.

**Scientific limitation:** This is a second freshly generated set of configurations in the **same** four-JVM Kafka software laboratory, with consumer-pause added. It adds real **mechanism generalization** evidence, not independent operator-site transfer, independently signed third-party testing, a 99.9% cybersecurity accuracy claim, or guaranteed national infrastructure benefit. Those require separate authorized external evaluations.
