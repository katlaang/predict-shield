# Cross-dataset flow detector: CIC-IDS2017 to CSE-CIC-IDS2018

**Date:** 19 November 2026 (runs logged 20 November UTC).
**Outcome: failed its pre-registered alert budget.** On the second network the
detector found 99.97% of attack flows but alerted on 30.85% of benign flows,
against a budget of 1%. At that false-alarm rate the detection figure has no
operational value: one alert in six was an attack.

## What was tested

A learned flow detector with no hand-written detection rules
(`experiment-b/cic-flow/`): a supervised gradient-boosting model that learns
attack versus benign from labelled flows, plus an Isolation Forest fitted on
benign flows only. Inputs are CICFlowMeter flow statistics on a signed log
scale, protocol, a destination-service bucket and six causal 60-second context
counts per source and destination. IP addresses, ports, timestamps and labels
are never inputs.

Everything was fixed in `experiment-b/cic-flow/protocol.json` before any
development result or test label was read: features, models, seeds, the split,
the alert rule and the alert budget (each part's threshold at 0.5% of benign
calibration flows).

## Data and pins

Both datasets are the corrected versions by Engelen, Rimmer and Joosen
(CNS 2022), regenerated with the same fixed CICFlowMeter, so features mean the
same thing in both years. Flows labelled "Attempted" are benign, per the
dataset authors.

| Role | Archive | SHA-256 | Flows |
| --- | --- | --- | ---: |
| Development | CICIDS2017_improved.zip | `97fdb91d…48883` | 2,099,976 |
| Test | CSECICIDS2018_improved.zip | `7f7b6f80…44f6e` | 63,195,145 |

The test archive was pinned in run 44654927940 by reading only its headers and
row counts; its labels were first read by the scoring run.

## Order of runs

1. Develop, run [44657282908](https://github.com/katlaang/predict-shield/actions/runs/44657282908):
   fit, thresholds, development report, frozen bundle.
   Model `aeb53fb9…6833`, freeze `d2355cb3…1f6e`.
2. Freeze recorded in `experiment-b/cic-flow/frozen/FREEZE_RECORD.json`
   (commit a1ff061) before the test archive was scored.
3. Test, run [44660659725](https://github.com/katlaang/predict-shield/actions/runs/44660659725):
   the bundle was checked against the record, the protocol and the dispatch
   input, then every test flow was scored once. The workflow committed the
   bundle and both reports to `experiment-b/cic-flow/frozen/` (commit e04a749).

## Development results (CIC-IDS2017, held-out 20% of rows)

| | Count |
| --- | ---: |
| Attack flows detected | 101,106 of 101,106 |
| Benign flows alerted | 3,022 of 318,880 (0.95%) |

Rows were split at random, so flows of one attack run sit on both sides of the
split; this measures fit to the 2017 capture, not generalization. In
leave-one-family-out runs the supervised part still detected most withheld
families (DDoS 18,942/18,942; DoS Hulk 31,743/31,743), which suggested it was
using cues shared by every 2017 attack rather than family behaviour. Weak
withheld families: botnet 11/126, web attack 8/18.

## Test results (CSE-CIC-IDS2018, all flows, one run)

| | Count | Rate |
| --- | ---: | ---: |
| Attack flows | 3,535,422 | |
| Detected (TP) | 3,534,508 | 99.97% |
| Missed (FN) | 914 | |
| Benign flows | 59,659,723 | |
| Benign alerted (FP) | 18,407,328 | **30.85%** |
| Precision | | 16.11% |

The benign alert rate was between 20.9% and 40.3% on every one of the ten
days, so the failure is not driven by one day. The supervised part produced
18,292,010 of the benign alerts (30.66% of benign flows); the anomaly part
alerted on 0.88% of benign flows against its 0.5% share of the budget.

Per family (all families also occur in development):

| Family | Flows | Detected |
| --- | ---: | ---: |
| DoS Hulk | 1,803,160 | 1,803,160 |
| DDoS (HOIC, LOIC-HTTP, LOIC-UDP) | 1,374,148 | 1,373,989 |
| Botnet (Ares) | 142,921 | 142,921 |
| SSH brute force | 94,197 | 94,197 |
| Infiltration | 89,663 | 88,908 |
| DoS GoldenEye | 22,560 | 22,560 |
| DoS Slowloris | 8,490 | 8,490 |
| Web attacks | 283 | 283 |

Within infiltration: NMAP portscan 88,826/89,374, victim-attacker communication
82/204, Dropbox download **0/85**. The anomaly part added 26 detections the
supervised part missed, all DDoS-LOIC-UDP.

All arithmetic above was recomputed from `frozen/test-report.json` and
reconciles: 3,535,422 + 59,659,723 = 63,195,145 flows; family totals equal
TP + FN; per-day totals equal the flow count.

## What this shows

- The supervised threshold set on 2017 benign traffic (attack probability above
  3.7 × 10⁻⁶) does not carry over to another network's benign traffic. Benign
  2018 flows look unlike benign 2017 flows to the model, so a third of them
  scored as attacks. This is a calibration and generalization failure, and it
  is the main finding.
- A threshold fixed on one network should not be trusted on another. A
  detector has to be calibrated on the benign traffic of the network it
  protects.
- The detection figure is not evidence of capability by itself, because a
  detector that alerts on a large share of all traffic detects nearly
  everything.

## Limits

Both networks are lab captures of simulated enterprises. Flows within a day are
strongly dependent, so the Wilson intervals in the report understate
uncertainty; per-day rates are given instead. No setting was changed after any
result was seen.
