# Cross-dataset flow detector v3: single HIKARI-2021 test (2026-11-23)

**Outcome: failed both parts of its pre-stated condition.**

| Measure | Result | Limit |
|---|---|---|
| Attack flows detected | 42 of 30,174 (0.14%) | at least 50% |
| Normal flows alerted | 5,634 of 414,105 (1.36%) | at most 1% |
| Benign flows alerted | 0.57% | at most 1% |
| Background flows alerted | 2.97% | at most 1% |

## Setup

- **Protocol:** `experiment-b/cic-flow-v3/protocol_v3.json`, fixed before any version 3 code read a HIKARI-2021 flow.
- **Development data:** CIC-IDS2017 and CSE-CIC-IDS2018 (improved versions).
- **Test data:** HIKARI-2021, captured with a different flow meter (Zeek flowmeter).

| Stage | Run | Result |
|---|---|---|
| Develop | 44914414336 | freeze `36f81cea…bfecaf` |
| Test | 45314301123 | `experiment-b/cic-flow-v3/frozen/test-report.json` |

**Chosen configuration:** flow statistics plus destination-service bucket, gradient boosting with 15 leaves and 100 iterations. It was chosen by the pre-stated rule, using the networks in turn as training and held-out data.

**Calibration:** on HIKARI's own Benign flows only (34,624 to fit the anomaly model, 34,814 to set the thresholds).

**Scored:** the other 444,279 flows, once.

## Development already pointed to this result

| Training network | Held-out network | Attacks detected (chosen configuration) |
|---|---|---|
| 2018 | 2017 | 40.8% |
| 2017 | 2018 | 0.94% |

- **Across the whole grid:** on the 2018 network held out, no configuration detected more than 1.2% of attacks.
- **On its own training network:** detection was close to 100% in 23 of the 24 grid runs.
- **More training data did not help.** With 2018 held out, detection stayed near 1% at 10%, 30% and 100% of the training rows.
- **The protocol fixed that development results change nothing,** so the test ran on the frozen model.

## By traffic category

| Category | Flows | Alerts | Rate | Family seen in development |
|---|---|---|---|---|
| Benign | 277,993 | 1,594 | 0.57% | |
| Background | 136,112 | 4,040 | 2.97% | |
| Probing | 18,666 | 41 | 0.22% | yes (port scan) |
| Bruteforce | 4,687 | 0 | 0.00% | yes (web brute force) |
| Bruteforce-XML | 4,164 | 0 | 0.00% | yes (web brute force) |
| XMRIGCC CryptoMiner | 2,657 | 1 | 0.04% | no |

Of the 42 attack flows detected, 41 came from the anomaly part and one from the supervised model.

## What the result shows

- **Flow statistics learned on CICFlowMeter captures did not transfer** to a network captured with Zeek. This held even for attack families present in development.
  - The HIKARI brute-force attacks run over encrypted HTTPS. The development examples of web brute force were against plain HTTP.
- **Background traffic drove the false alarms.** Thresholds were set on Benign flows only, as pre-stated, so traffic unlike the calibration set alerted at about five times the Benign rate.
- **Three versions, one pattern.** This is the third cross-network failure (v1, v2, v3). A detector trained on public lab captures is not ready for a new network without labelled traffic from that network.

## Disclosures

- The development results (held-out detection under 1.2% on 2018) were visible before the test ran. The test ran unchanged because the protocol fixed that development results change nothing.
- Before the protocol was registered, HIKARI's column list, label counts and the first three rows had been seen during its schema probe.
- Flows within one capture are dependent, so the Wilson intervals in the report understate uncertainty.
