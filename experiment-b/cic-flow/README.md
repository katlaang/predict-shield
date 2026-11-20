# Cross-dataset flow detector: CIC-IDS2017 to CSE-CIC-IDS2018

**Measured 19 November 2026: failed its 1% benign alert budget.** On the 2018
network it detected 99.97% of 3,535,422 attack flows but alerted on 30.85% of
59,659,723 benign flows. Full record:
`docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_2026_11_19.md`.

A learned network-flow detector that has no hand-written detection rules.
It is fitted on one lab network's traffic and then measured once on a
different lab network's traffic, captured a year later with different hosts,
different attack tools and different volumes.

## Why this design

The NSL-KDD measurement (docs/evidence/MEASURED_HISTORICAL_NSL_KDD_UNSUPERVISED_2026_11_19.md)
showed three gaps: some attacks had feature values identical to normal
traffic, the model ignored traffic type, and it judged each connection alone
so volume attacks such as mailbomb looked normal. This detector adds traffic
type and causal 60-second context per source and destination, and combines a
supervised model, which learns known attack families from labelled flows, with
an anomaly model fitted on benign flows only, which can alert on behaviour no
labelled family showed.

The NSL-KDD test set has already been looked at, so it is not used here.

## Data

Both datasets are the corrected versions by Engelen, Rimmer and Joosen
(CNS 2022), regenerated from the original packet captures with the same fixed
CICFlowMeter, so a feature means the same thing in both years. Flows labelled
"Attempted" carried no attack behaviour and are counted as benign, as the
dataset authors recommend. Both archives are pinned by SHA-256 in
`protocol.json`.

## Order of work

1. `protocol.json` fixes features, models, thresholds, splits and reporting
   before any development result or test label is read.
2. `train_dev.py` (workflow stage `develop`) fits on 2017 rows, sets both
   thresholds from benign calibration flows (0.5% each, at most 1% total),
   reports development results including leave-one-family-out runs, and
   writes the frozen bundle. It never downloads the test archive.
3. The bundle, its freeze record and the development report are committed in
   `frozen/`.
4. `score_test.py` (workflow stage `test`, dispatched once with the freeze
   hash) verifies the bundle, protocol and test archive against the freeze,
   then scores every 2018 flow and reports per family, per day, and which
   model fired.

## What a result does and does not show

It measures how a detector built on one lab network does on another lab
network. Both are simulated enterprise captures, not an operator's live
traffic. Flows within a day are strongly dependent (one attack run produces
thousands of near-identical flows), so per-day results are reported next to
the pooled rates and the pooled intervals understate real uncertainty.
