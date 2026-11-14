# Training-only model stability study, November 14, 2026

**Purpose:** Improve repeatability of PREDICT-SHIELD's learned defense choices without choosing a model based on the already-inspected 20 held-out configurations. This is research model development, **not** an independent effectiveness finding.

## Existing full physical result must remain unchanged

Completed original v3 physical experiment: 1,200 individually audited action replays, 100 operating configurations, 60 train / 20 calibration / 20 test. Model held-out regret **0.003291850218750362**; the strongest calibration-selected deterministic rule (fixed-monitor) regret **0.0027853271145825884**; paired model improvement **−0.0005065231041677737**, absolute 95% group bootstrap **[−0.0015193520031266665, +0.000009410560520143607]**. AI superiority **NOT ESTABLISHED**. See [GitHub Actions physical study](https://github.com/katlaang/predict-shield/actions/runs/43629488209).

## Actual training-only investigation

Using all five SHA-verified real lab shard artifacts from that run, we filtered the data to the **60 original training configuration groups only** (720 actual measured action records). None of the 20 calibration groups or 20 previously examined test groups contributed labels to model comparison or selection. Grouped fivefold cross-validation compared five prespecified engineering baselines:

| Model on original TRAIN groups | Mean fivefold physical hindsight regret | Folds better than fixed-monitor |
| --- | ---: | ---: |
| Extra Trees, 200 estimators, leaf 5 | 0.010875921 | 4/5 |
| HistGradientBoosting, conservative | 0.018148169 | 3/5 |
| Random Forest, conservative | 0.021437403 | 3/5 |
| Ridge with standardized features | 0.024305519 | 0/5 |
| Random Forest, regular | 0.027470849 | 2/5 |

The lowest development mean was Extra Trees. We evaluated its **unchanged** hyperparameters using five predeclared reshuffles of those same 60 training groups, five GroupKFold folds each, 25 group-fold evaluations in total. The model selected from pre-action telemetry only and action eligibility was enforced before choosing a defense.

| Stability check | Actual result |
| --- | ---: |
| Folds where AI beat fixed-monitor | 15/25 |
| Folds where AI lost to fixed-monitor | 9/25 |
| Folds tied | 1/25 |
| Average fold-level regret reduction (monitor minus AI), local prototype | +0.006059386 |\n| Average fold-level regret reduction, repository canonical feature encoder (CI) | +0.006099724 |
| Configurations ever used for this stability development | 60 train only |

**Conclusion: TRAINING IMPROVEMENT FOUND, CONSISTENT SUPERIORITY NOT FOUND.** These 25 folds reuse the same 60 independent operating configurations under different partitions, so they are **not 25 independent validation studies**. Selection of Extra Trees is already development tuning and cannot turn this into prospective confirmatory evidence. Do not choose a new fixed threshold or another random seed by inspecting previous TEST outcomes.

The independently retained local prototype JSON SHA-256 is `95e701024e786f8e40f02a7b99c13a30e373c7a237ce22c7cc0a2adb2fe6ad27`. The canonical repository workflow [43638583298](https://github.com/katlaang/predict-shield/actions/runs/43638583298) used `train.to_features` and produced an independently recorded result SHA-256 `472d46682856654dc35ab7d7b38411d064d8792d06751085bbef4898b21de521`; its 25-fold outcomes also show 15 improvements, 9 losses and 1 tie. Small numerical differences between the local prototype encoding and canonical repository feature encoder are not interpreted as evidence of a different scientific result. Exact physical source commit: `25f8710ee625f16ffdc288350c6e04865676ee2d`.

## Reproducibility

`train_group_stability.py` accepts the **five original GitHub Actions shard ZIPs** and verifies each measured-data digest, exact distinct shard identities, unchanged physical source revision, four-action repeated train group completeness, and strict exclusion of all calibration/test labels from the training-returned collection.

```bash
python train_group_stability.py \
  --shard-zips /secure/shard-0.zip /secure/shard-1.zip /secure/shard-2.zip \
               /secure/shard-3.zip /secure/shard-4.zip \
  --output /secure/new-training-only-stability.json
```

A failed script never implies that AI performed better. Published artifacts are numerical laboratory observations only, not authenticated external field results.

## Next empirical milestone

1. Freeze one candidate model and the deterministic safety gate from **training and calibration only**. Do not revise this model in response to old test data.
2. Prospectively register **new independent physical configurations** not already used in either the 1,200-action v3 experiment or the five-family 240-action headroom investigation. Replaying identical configurations with new seeds is a reproducibility check, not wholly independent fault diversity.
3. Collect matched genuine physical observations with at least two repetitions per configuration, separate test-only oracle truth, and the same predeclared utility for all action candidates. For stopped authority faults, preserve UNKNOWN intervals rather than fabricating scalar labels.
4. Evaluate the locked candidate against **fixed-monitor, fixed-resync, strong telemetry rules and other eligible policies**. Require an honest group-level uncertainty interval and meaningful improvement, repeatable across independent fault and load strata. If the result is negative, publish it.

The scientific goal is a stable improvement over **strong eligible non-AI baselines**, not indefinite random-seed tuning until one model appears to win.
