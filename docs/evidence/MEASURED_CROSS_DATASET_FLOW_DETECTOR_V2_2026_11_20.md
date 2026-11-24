# Cross-dataset flow detector v2: CIC-IDS2017 to CSE-CIC-IDS2018

**Date:** 20 November 2026.
**Outcome: met its pre-stated false-alarm condition and detected almost
nothing.** On the 2018 network the detector alerted on 0.55% of benign flows
(every day under 1%, worst day 0.72%), which satisfies the condition written in
`protocol_v2.json`. It found 0.83% of attack flows (28,643 of 3,441,225). One
alert in eleven was an attack. The condition was met, but this version is not
a usable detector, and the protocol's pass condition was too narrow: it bounded
false alarms and set no floor on detection.

## Relation to version 1

Version 1 (`docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_2026_11_19.md`)
failed with a 30.85% benign alert rate. Version 1 read every 2018 label once,
and version 2 changed the design in response, so this is a second measurement
on the same data and carries less weight than an untouched held-out test. The protocol records this in
`relation_to_version_1`. The version 1 result stays on record unchanged.

## What changed from version 1

- Per-source context counts removed; two per-destination counts remain,
  computed in timestamp order.
- Thresholds are set on the first 2018 day in time order
  (`Wednesday-14-02-2018.csv`), with its labels unread: flows in split buckets
  0 to 4 fit the Isolation Forest, buckets 5 to 9 set both thresholds at 0.5%
  each. Every flow of that day is excluded from scoring.
- The freeze covers the model and the four code files; the test stage refused
  to start on any mismatch.

## Locked run

| Item | Value |
|---|---|
| Develop run | 44779461910 |
| Supervised model SHA-256 | `f1fa7e6536e7d623f461c7719fd4ef2fbe5ffe121843b888be061ffb5ffeff3a` |
| Freeze SHA-256 | `793d315feaa1552ff68ddfa84caf4413c0f1136ed864ffeadf6562aa8982cbae` |
| Test archive SHA-256 | `7f7b6f8065a88527bcb6e1579f088e1d0480a49903c5fd7e4e907ab238344f6e` |
| Test run | 44782232012, attempt 2 |
| Report | `experiment-b/cic-flow-v2/frozen/test-report.json` |

## Results

Calibration day: 5,898,350 flows (200,000 fit the Isolation Forest,
2,950,384 set thresholds). Thresholds: supervised 0.99999997, anomaly 0.6224.

Scored: 57,296,795 flows (63,195,145 minus the calibration day), recomputed
from the report and checked by the workflow's accounting step.

| | Count |
|---|---|
| True positives | 28,643 |
| False negatives | 3,412,582 |
| False positives | 295,531 |
| True negatives | 53,560,039 |

- Detection 0.83% (Wilson 95%: 0.82% to 0.84%).
- Benign alert rate 0.55% (0.547% to 0.551%); per day 0.45% to 0.72%.
- Precision 8.8%.

Wilson intervals treat flows as independent. Flows within a day are not, so
the real uncertainty is wider.

### By attack family (all families also appear in 2017)

| Family | Flows | Detected | Rate | Supervised | Anomaly only |
|---|---|---|---|---|---|
| infiltration | 89,663 | 27,552 | 30.7% | 27,315 | 237 |
| dos-slow | 8,490 | 293 | 3.5% | 293 | 0 |
| botnet | 142,921 | 797 | 0.56% | 0 | 797 |
| ddos | 1,374,148 | 1 | 0.00007% | 0 | 1 |
| dos-hulk | 1,803,160 | 0 | 0% | 0 | 0 |
| dos-goldeneye | 22,560 | 0 | 0% | 0 | 0 |
| web-attack | 283 | 0 | 0% | 0 | 0 |

Of the benign false alarms, 283,089 came from the anomaly model and 12,442
from the supervised model.

## Why detection collapsed

1. **The supervised threshold was set on a day that contained attacks.** The
   published schedule for 14 February 2018 lists FTP and SSH brute force. The
   code never read that day's labels, so attack flows were counted as benign
   when the 0.5% budget was set. Confident attack scores filled that budget
   and pushed the threshold to 0.99999997, above nearly every 2018 attack.
   The same effect appeared in development. On the three held-out 2017 days
   whose thresholds landed between 0.9999992 and 0.99999999, detection was
   0.9% to 2.3%. On Tuesday the threshold landed at 0.00012 and detection
   reached 18.8%, at a 0.58% benign alert rate.
2. **The anomaly model was fitted on the same unlabelled day,** so the attacks
   in it were learned as normal.
3. **Each 2017 day has its own attack families,** so leave-one-day-out
   development measured generalization to families the model had never seen.
   High training fit with low held-out detection marks a failure to
   generalize to new families.

## Disclosures

- **Partial view before the final run.** Attempt 1 of run 44782232012 was
  stopped by a GitHub runner shutdown during scoring. Its log had already
  printed the calibration thresholds and the complete result for
  `Friday-02-03-2018.csv` (FP 40,940, TN 6,127,510, TP 797, FN 142,124).
  Attempt 2 re-ran the same frozen model and code; nothing was changed between
  attempts, and the Friday figures match exactly.
- **Placeholder pin.** The first v2 freeze carried `PENDING_PIN` for the test
  archive. Both test attempts on it refused to score, so no test flow was read.
  The pin was copied from version 1, development was re-run, and the
  supervised model came out byte-identical. Recorded in `pin_correction`.
- **Row order.** The report counts rows whose timestamp is earlier than an
  earlier row in the same file: over 99.9% of rows on every 2018 day and
  97% to 99% on 2017 days. The files are not stored in time order. Context
  counts are computed after sorting by timestamp, so file order does not
  change any input.

## What version 3 changes

Each change below addresses one cause above. All are fixed in the protocol
before any result is read.

- Thresholds and the anomaly model use only traffic verified as normal, with a
  check that known attacks are not absorbed.
- A detection floor joins the false-alarm ceiling in the pass condition.
- Training fit is reported beside held-out results; capacity is chosen on
  development data only, with learning curves.
- More varied training data, so the model sees more than one day per family.
