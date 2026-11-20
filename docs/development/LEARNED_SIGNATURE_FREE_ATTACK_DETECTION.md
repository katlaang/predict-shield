# Learned attack and threat detection without explicit matching rules

**Status:** A read-only, experimental unsupervised detector is implemented in `unsupervised_detector.py`. It has not yet been tested on verified real CTU-13 source files, current U.S. infrastructure, or unseen attacks. Software unit tests contain *synthetic* flows only.

## What the AI learns

The Isolation Forest fits a population of publisher-labeled **From-Normal** flow features, using network duration, packet/byte counters and protocol. It learns a distribution of ordinary activity. At inference, it emits an anomaly score for each unlabeled flow and flags unusual observations **without specifying an ATT&CK technique, matching a signature, or evaluating an explicit attack rule**.

The model can flag deviations beyond the known training patterns. However **unusual does not imply malicious**; legitimate traffic shifts, maintenance and instrumentation artifacts can also be flagged. No zero-day detection, attribution or validated novel-attack recall is claimed.

Two distinct research tracks coexist:

- **Unsupervised deviation discovery**: normal-only training, no attack labels needed to fit, may surface unknown patterns for independent investigation.
- **Supervised malicious-behavior classification**: the separate incident detection model learns from labeled attack and benign cases; its performance depends on source quality and group-disjoint held-out tests.

The earlier LLM rule-generation experiment and Suricata rules remain **optional complementary signals**, not prerequisites for the learned anomaly detector.

## Frozen evaluation boundary

The CTU-13 manifest must list separate SHA-pinned scenarios for train, calibration and test. The data loader excludes unknown labels (including To-Botnet, To-Normal and Background) instead of inventing benign ground truth. The anomaly model is fit **only on reviewed-normal training flows**. A false-alarm ceiling is registered in the manifest; benign-only calibration determines the alert threshold, without using attack examples or any test labels. Only afterward are test recordings loaded and scored once.

Report: TP, FP, FN, TN, sample recall/precision/FPR, test denominators, source hashes, calibration false alarms and excluded unknown labels. The class-stratified sample precision is not operational precision; historical 2011 network flows do not establish modern critical-infrastructure effectiveness.

## Local experimental execution

With properly downloaded and checksum-verified CTU-13 `.binetflow` text captures, a pre-registered manifest (same format as `fit_evaluate.py`) and scikit-learn 1.7.2:

```bash
python -m pip install scikit-learn==1.7.2
python experiment-b/ctu13-flow/unsupervised_detector.py \
  --manifest /secure/research/ctu13-manifest.json \
  --data-root /secure/research/ctu13-files \
  --output /secure/research/ctu13-unsupervised-report.json
```

Optional `--unlabeled-flows /secure/research/unlabeled-flows.json` scores a JSON array of unlabeled telemetry observations against the **already fitted in-memory model**, emitting read-only investigation candidates. Ground truth fields are rejected from this inference boundary.

## Architectural safety and remaining work

The read-only detector is a **candidate signal**, not verified threat intelligence. Risk assessment should combine contextual vulnerability exposure, asset dependencies, behavior history and additional independent observations. Any suggested containment must pass the existing deterministic, independently authenticated policy gate and operator approval, with post-action verification. Do not turn a model score into authority to disrupt electric-grid, telecom, transport or clinical operations.

Next gates: obtain and pin authentic source captures; run independent group-disjoint evaluation; test against realistic benign drift and new attack families; measure false alarms per host-day, timeliness and out-of-distribution behavior; connect a signed, evidence-bearing detector service to the existing intake, in shadow mode only; assess adversarial evasion and concept drift; then run authorized external operator studies.

**No AI detection success claim is warranted until measured evidence exists.**
