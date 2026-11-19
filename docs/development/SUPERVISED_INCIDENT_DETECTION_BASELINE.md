# First supervised incident-classification model

**Status: implemented as a constrained research baseline; no independently
verified operational attack-detection effectiveness is claimed.**

The current PREDICT-SHIELD detection-rule pipeline already runs bounded
LLM-assisted rule suggestions, then freezes accepted rules before evaluating
the held-out recordings. The present increment adds a *different* research
path: a supervised logistic classifier trained from independently reviewed
incident labels using the existing `incident_feedback.py` structural contract.

## What it does

- Accepts train/calibration/test partitions with distinct asset groups, plus
  independently reviewed ATTACK / BENIGN / UNKNOWN incident evidence.
- Excludes UNKNOWN from supervised training and refuses any mislabeled,
  duplicated, incomplete, post-action, or cross-partition input.
- Trains a real `sklearn.linear_model.LogisticRegression` on train groups
  only, requiring both classes with at least two training cases each.
- Keeps a predeclared 0.5 decision threshold. Calibration groups are
  **not used** for model fitting or threshold tuning. Model probabilities
  are **uncalibrated**.
- Scores exactly the held-out reviewed test population using TP/FP/FN/TN,
  recall, precision, and false-positive rate, with every test prediction
  tied to one incident ID. Stores the frozen model coefficients, training
  fingerprint and test-case probabilities.
- Has no method to dispatch actions or automatically retrain or deploy.
  Every artifact sets `production_deployable=false` and
  `decision_authorized=false`.

## How to test the implementation

The current unit test dataset is **entirely generated as a synthetic
fixture**. It checks whether the algorithm learns, partitions are isolated,
unknown cases are excluded, invalid inputs fail, and the output report is
complete. Its apparent detection score is *not a scientific or operator
finding*. No real incident ground truth is provided by these tests.

```bash
python -m pip install scikit-learn==1.7.2
PYTHONPATH=engine python -m unittest engine.tests.test_incident_feedback engine.tests.test_incident_detection_model -v
```

The separate GitHub Actions workflow
`.github/workflows/incident-detection-baseline.yml` runs these tests with
a version-pinned scikit-learn dependency.

## What must happen before claiming real attack detection

1. Collect enough **genuinely labeled attack and benign** telemetry with
   independent expert and operator evidence. Do not infer that every
   unmatched event in attack recordings is benign.
2. Validate provenance beyond hash-format and reviewer-identifier
   consistency: obtain the original captured evidence, independently verify
   reviewers, label quality, consent and source identities.
3. Split sites, hosts, incident campaigns and time periods to prevent
   leakage across training and test. Review the class base rate.
4. Train on actual pre-detection features available at inference time and
   freeze a model before the unseen evaluation.
5. Report recall, precision, misses, FPR, false alerts per host-day, latency,
   confidence intervals, class prevalence, calibration and failure-to-abstain.
6. Only after validation, integrate detection proposals with signed intake,
   threat correlation, risk assessment, the separate action gate, operator
   approvals, and independently observed post-action outcomes.
7. For electric-grid OT, begin in shadow/read-only mode and independently
   measure communications and electrical consequences in coupled simulation.

## Independent context

- `docs/development/INCIDENT_LEARNING_EVIDENCE_CONTRACT.md`: label
  provenance restrictions and operational learning requirements.
- `experiment-b/public-sources/ai_rules/`: different, bounded
  language-model **rule-generation** experiment on selected published
  recordings.
- `experiment-b/grid-lab/`: synthetic OT graph with a separate 33-bus
  AC feeder calculation, not yet a coupled grid simulation.

These activities demonstrate research progress, not field effectiveness.
