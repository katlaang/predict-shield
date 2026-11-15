# PREDICT-SHIELD: Second frozen-model physical replication, actual measured result

**Experiment date:** November 15, 2026. This report records results retrieved from a completed real GitHub Actions Java/Kafka experiment. Numbers are original measurements, not model forecasts, simulations or substituted source-claim labels.

## Source and immutable evidence

- [Physical execution and scoring, GitHub Actions run 43683855904](https://github.com/katlaang/predict-shield/actions/runs/43683855904): **SUCCESS** for registered-plan validation, all five independently isolated physical fault-family shards, and final score of the exact previously frozen model.
- Implementation and preregistered method: [merged PR #99](https://github.com/katlaang/predict-shield/pull/99), merge commit `35f309cd8a33bd5587f7188d541dcd318914e179`, protocol [SECOND_FROZEN_AI_FIVE_FAMILY_PROSPECTIVE_PROTOCOL.md](SECOND_FROZEN_AI_FIVE_FAMILY_PROSPECTIVE_PROTOCOL.md).
- Original recorded scoring artifact: `frozen-ai-five-fault-real-480-physical-actions-and-seven-rules`, GitHub Actions artifact ID **14149079269**, artifact ZIP SHA-256 `2c2bb327cc744105a22dae593ce24d61ad4a53f668969ba4dac749e9ca0a7f58`. Its report internal SHA-256: `a25660ca70f11d3897a4286dd681cc611bf0df2d5f8651ff09896e1ffb8d6223`.
- Five original physical measured evidence archives: `five-family-frozen-physical-shard-0` ZIP SHA-256 `77f917bbd17618db61005b71db73c5a3e8eb1abeaa4d11a2ef0e132a6279781e`; `-1` `b2dc2fa8c2d5cb27b7d2f8203b91ed643428899117c36fcad4496c1d4308379e`; `-2` `559c21aff54a18a4155b81a4424b7697284cbb27481fd23bc67ae540cc1a92bd`; `-3` `84161b028a006419ef4721b3e494b4b2dfa4dece50bd9c1f9becce5ce84df924`; `-4` `f7b984f7e76af36825c78e54ccd3bb4a5d270354abfa60c2e691d4722e00f7bc`.
- The physical source commit pinned within all five source records: `4a779e11839c211f37d6b925739fd52ace84e737`.
- **Frozen trained AI**, trained before these cases on the earlier real 1,200-action lab dataset: `HistGradientBoostingRegressor` with paired action-benefit supervision and intervention threshold **0.01**, model artifact file SHA-256 `35a040b26a935bfb529f6247dbd0be1a01288294f8fb7089d4de60366adf3f92`, [training workflow run 43682077804](https://github.com/katlaang/predict-shield/actions/runs/43682077804). No model weights, training features, threshold, or existing conventional rule were changed after inspecting the previously separate 192-action study or this newly executed 480-action test.

## Actual physical experimental scope

- **60 new configured test cases**, four independent configurations per each five-fault × three-stratum cell. Strata SIMPLE / INTERACTION / PARTIAL_VISIBILITY. Faults `loss`, `delay`, `duplicate`, `reorder`, and actual `consumer_paused` listener behavior.
- **Two measured repeats per case**, **four actual defensive alternatives per repeat**, **480 independently audited physical action replays** and **120 offline AI/rule decisions**. The 60 configuration groups, not 480 replays, are the analysis units for paired group-bootstrap uncertainty.
- The previously untrained **consumer-paused family** ran **96 physical replays** with all 96 separate Kafka listener-pause witnesses verified and archived. The fifth shard's original data was inspected after the run and has complete actual measurements and an independently marked four-stream audit.
- The model used only operator-observable pre-action features; private fault labels and outcome oracles remained excluded. The actions themselves were physically executed in a disposable four-JVM Kafka lab, but the learned policy selected and was scored **offline**, not by issuing autonomous production commands.
- Research utility stayed the previously declared `0.50 × time-integrated gateway exposure + 0.25 × unresolved control risk + 0.25 × (actual failed legitimate requests / declared lab error allowance)`. Hindsight regret is actual measured utility of selected action minus actual measured best eligible action within each matched physical replay.
- The previously strongest baseline was locked to `fixed_monitor` from historical calibration. Six other predeclared non-AI policies remained in the comparison. Familywise conservative one-sided adjusted lower confidence bound uses group bootstrap and alpha `0.05/7` with an improvement target of over 10%. The zero AI-selected legitimate-service failure-budget exceedance requirement also remained frozen.

## Complete observed outcome

| Policy | Measured mean hindsight regret | Model relative point regret reduction | Adjusted 10% improvement supported |
| --- | ---: | ---: | --- |
| **Frozen trained paired-action AI** | **0.0272149301** | Reference | Not a separate comparator |
| **Previously strongest fixed monitor** | **0.0303752694** | **10.4043%** | **NO** |
| Fixed resynchronization | 0.030561 (approximately) | 10.948% | **NO** |
| Original train-tuned rule | 0.088080 | 69.10% | YES |
| Engineering rule | 0.096408 | 71.77% | YES |
| Operator-telemetry rule | 0.106624 | 74.48% | YES |
| Fixed restart-or-gateway | 0.274756 | 90.10% | YES |
| Fixed gateway restriction | 0.361735 | 92.48% | YES |

- Paired absolute regret improvement versus monitor: **+0.0031603393**.
- Ordinary two-sided 95% configuration-cluster bootstrap for that difference: **[−0.00867941197, +0.01594441686]**, including zero and hence no established population advantage.
- Conservatively Bonferroni-adjusted one-sided **relative lower bound = −0.658088** versus the strongest monitor-only policy, far below the preregistered **+0.10** threshold.
- **Five of seven** rules satisfy the adjusted improvement test. The original strongest two, fixed monitor and fixed resync, **do not**.
- **Action choices:** monitor-only **98/120**, restart_enforcer **14/120**, resync_policy **8/120**, gateway_restrict **0/120**.

### Safety failure that cannot be discarded

**Exactly one AI-selected action exceeded the registered legitimate-service failure allowance.** In `new-five-family-053`, repetition 0, fault `consumer_paused`, stratum `INTERACTION`, the model chose `restart_enforcer`. That actual physical action caused **40 failed legitimate requests**, exceeding the predeclared **25-request laboratory allowance**.

This happened even though restart achieved the *lowest weighted overall utility for that replay*. A weighted cost alone therefore cannot enforce a hard service-continuity constraint. Treating a low total utility as approval to disrupt an essential service is an **unsafe category error**. The AI was scored offline and did not autonomously dispatch the action in a real organization.

This is the most important engineering inference from this second replication: **predicted action effectiveness must be accompanied by independently constrained, calibrated disruption bounds, and the policy must abstain or seek human approval if those bounds cannot be satisfied**. Such a future safety decision model must be trained and calibrated on historical training/calibration data, not fit to this newly observed violation and then retested on the same case as if independent.

### New mechanism-specific diagnostics (descriptive only)

| Fault family | AI mean regret | Fixed-monitor mean regret | AI chosen actions over error allowance |
| --- | ---: | ---: | ---: |
| Consumer paused | 0.053570 | 0.071620 | 1 |
| Loss | 0.080491 | 0.078171 | 0 |
| Delay | 0.001969 | 0.002026 | 0 |
| Duplicate | 0.0000223 | 0.0000342 | 0 |
| Reorder | 0.0000219 | 0.0000252 | 0 |

The frozen model's mean regret was **worse** than fixed monitor on the actual new *loss* cases; the new consumer-paused family had the only safety-budget exceedance. All per-fault comparisons contain only **12 configured groups**, so avoid separate categorical statistical superiority claims without additional preregistration/power.

## What the two distinct new physical studies together tell us

The first new 24-group / 192-action study reported AI point regret 0.004285 versus monitor 0.020829, a point reduction of **79.4%**, but the adjusted confidence bounds did not support superiority. The second **new 60-group, five-family, 480-action** study reports a much smaller point reduction, **10.4%**, and a real laboratory service-budget violation.

Therefore the favorable point benefit was **not stable across expanded configurations and a new physical fault family**. Both are legitimate, accurately recorded results; **do not average their percentages or report only the first successful point estimate**. Neither establishes statistically reliable AI superiority under its preregistered test.

**Official registered result** `lab_superiority_supported_under_all_predeclared_tests=false`.

## Current research evidence boundaries

Demonstrated: genuine offline learned-defense research, real physical Kafka/JVM action replays, independent measured security and authorized-service outcomes, frozen model provenance, two separate post-training new physical configuration studies, complete negative and positive evidence history.

**Not demonstrated**: policy-level statistical superiority over the strongest conventional rule, reliable hard service-continuity preservation, independent operators' critical infrastructure effectiveness, production-safe autonomous defense or 99.9% security decision accuracy. All testbeds reused the same four-JVM lab, not separate U.S. infrastructure sites. This remains a research objective, not a validated field claim.

Next defensible technical milestone: **train-only safety-constrained action-value learning**, predicting/interval-calibrating actual legitimate-service failures as a separately enforced hard bound *before* considering action utility; fail closed under model uncertainty. Test on **completely fresh** physical scenarios, and independently evaluate a strong policy baseline with the *same* service constraints. Never tune and reclassify the currently examined 60 groups as held-out.
