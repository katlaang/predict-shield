# Measured trained network-intrusion ML demo (November 26, 2026)

## What was actually trained

PREDICT-SHIELD's new **browser-only trained-model demonstration** uses a genuinely fitted scikit-learn `LogisticRegression` classifier, not a hand-weighted scenario formula. The input uses all **41 NSL-KDD network connection features**. Three categorical features (`protocol_type`, `service`, `flag`) use training-fitted one-hot categories with unseen-category handling. The remaining numeric features use a signed log1p transformation and training-fitted StandardScaler. The binary target is `normal` versus any labeled `attack`. This classifier is separate from the field-network detector and the DVWA v3 model.

Original publisher: University of New Brunswick / Canadian Institute for Cybersecurity, [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html). The publisher permits redistribution and mirrors with citation. Cite Mahbod Tavallaee, Ebrahim Bagheri, Wei Lu and Ali A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” CISDA, 2009. NSL-KDD derives from much older simulated DARPA/KDD traffic; it is **not modern live production telemetry**.

## Reproducible protocol and provenance

- Pinned source mirror: `https://github.com/Jehuty4949/NSL_KDD/tree/27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9`; Git blob SHA1 hashes for `KDDTrain+_20Percent.txt` and `KDDTest+.txt` respectively `74640e1046c65e3b9ff4e5fe1e5c11d6185429dc` and `b30e89605285a5ccd8cf8fd38dba72906c20d3dd`.
- Training code: `experiment-b/trained-demo/train_nslkdd.py`. scikit-learn **1.7.2**; seed 20261126. The source training file contains 25,192 examples, of which 18,894 fit the model and 6,298 are held for validation and threshold calibration.
- Model: logistic regression (`C=0.4`, `class_weight="balanced"`, `solver="liblinear"`), 38 numeric inputs and three categorical inputs, 117 fitted coefficients. Threshold selected from the 97th percentile of normal-validation scores, before test evaluation.
- The official test file contains **22,544** separate examples and was not used to fit coefficients, preprocessing or threshold. GitHub Actions training and first frozen evaluation: [run 45904634311](https://github.com/katlaang/predict-shield/actions/runs/45904634311).
- Frozen browser artifacts: `showcase/public/data/nslkdd-trained-model.json` (coefficients, training transforms, threshold, measured confusion matrix, 24 original test examples) and `showcase/public/ai-trained.html` (same embedded bundle, offline executable). No network requests are necessary during inference.

## Measured results

| Measure | Validation (6,298) | Official test (22,544) |
| --- | ---: | ---: |
| True attack detections (TP) | 2,921 | **8,207** |
| Missed attacks (FN) | 15 | **4,626** |
| Benign alerts (FP) | 101 | **797** |
| Correctly ignored benign (TN) | 3,261 | **8,914** |
| Attack recall | 99.49% | **63.95%** |
| Benign alert fraction | 3.00% | **8.21%** |
| Precision | 96.66% | **91.15%** |
| Balanced accuracy | 98.24% | **77.87%** |
| Overall accuracy | 98.16% | **75.94%** |

The official test contains 12,833 attack-labeled and 9,711 normal-labeled examples. These figures were calculated by the frozen pipeline on the official held-out test file, not a selection of successful demo examples.

## Demonstration behavior

The interface offers six held-out benchmark label categories: `normal`, `neptune`, `guess_passwd`, `satan`, `portsweep`, and `mscan`. Four genuine original test records were sampled per category using a fixed random seed, **not based on whether the classifier predicts them correctly**. Their source labels are shown separately and never passed to the classifier. The browser executes the fitted logistic coefficients, preprocessing and threshold directly in JavaScript on the record's 41 features.

Several `guess_passwd` and `mscan` records are incorrectly classified as normal, and one of the 24 selected normal samples is incorrectly flagged. These misses are visible rather than filtered out. The interface includes feature contributions, selected metric denominators and editable numerical features. Edits are labeled **hypothetical what-if inputs** and are not counted toward held-out accuracy. Its JSON audit distinguishes trained-model inference from hypothetical modifications.

## Interpretation and limits

This demonstrates **real supervised machine-learning inference on historical labeled network-connection features**, not a live network pilot, not a scripted outcome and not a forecast of when an attack will happen. The score is a linear-model sigmoid output, **not a calibrated probability of an attack in an operational network**. NSL-KDD's content features and short-window statistics are not equivalent to raw Zeek `conn.log` measurements, so this classifier cannot be directly applied to Zeek telemetry without a matching, independently verified feature pipeline.

This result does **not** establish production attack accuracy, zero-day threat discovery, AI defensive decision superiority, or resilience improvement at actual critical-infrastructure sites. Separate field training, prospective evaluation and independent benign/attack labels are still required. Report failure cases and the limitations of this historical benchmark whenever showing the demo.