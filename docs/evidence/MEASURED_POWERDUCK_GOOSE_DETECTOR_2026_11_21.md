# Learned GOOSE anomaly detector on PowerDuck (2026-11-21)

**Outcome: failed its pre-stated condition.**

- **Scenarios:** it flagged every one of the 16 attack scenarios. In 14 of them the first malicious message itself raised an alert.
- **False alarms:** it alerted on 3.0% of the attack captures' non-malicious messages, against a 1% ceiling.
- **Message-level detection outside floods:** it caught 15.1% of malicious messages in the 14 non-flood scenarios.

## Setup

- **Protocol:** `experiment-b/powerduck/protocol.json`, registered before any attack-capture record was read. Before registration, the archive layout and the first three records of two normal captures had been seen.
- **Data:** PowerDuck (Zenodo record 6724225). The archive is pinned by SHA-256 `38c5e779…ac58b`.
- **Model:** an Isolation Forest fitted on normal GOOSE messages only. No attack message was used to fit, scale or threshold anything.
- **Features:** each message is described relative to its own stream and to recent traffic: timing, stNum and sqNum changes, frame length, carried values and message rates. A stream one-hot is added. No rules were written by hand.
- **Threshold:** each normal capture's first 70% fitted the model, and its last 30% set the threshold at 1% of messages.
- **Runs:**

| Stage | Run | Result |
|---|---|---|
| Develop | 44914997977 | model `5fe50aec…`, freeze `615315af…` |
| Test | dispatched with that freeze hash | `experiment-b/powerduck/frozen/test-report.json` |

## Development (normal captures only, reported before the test)

Each normal capture was held out in turn; the model was fitted and thresholded on the other three.

| Held-out normal capture | Alert rate |
|---|---|
| 01 | 1.09% |
| 02 | 1.28% |
| 03 | 1.08% |
| 04 | 1.79% |

All four held-out captures were already over the 1% budget. Under the protocol, development results are reported and change nothing. The test therefore ran on the frozen model.

## Test (all 16 attack captures, once)

| | Count |
|---|---|
| Messages | 1,106,609 |
| True positives | 1,044,687 |
| False negatives | 3,957 |
| False positives | 1,747 |
| True negatives | 56,218 |

### Pooled results

| Measure | Value |
|---|---|
| Message detection | 99.6%, almost all from the two flood scenarios |
| Non-malicious alert rate | 3.0% (Wilson 95%: 2.9% to 3.2%) |
| Precision | 99.8% |

### By scenario group

| Group | Malicious messages detected | Non-malicious alert rate |
|---|---|---|
| Flood (15, 16) | 1,043,986 of 1,044,000 | 7.3% (521 of 7,162) |
| The other 14 | 701 of 4,644 (15.1%; Wilson 95%: 14.1% to 16.2%) | 2.4% (1,226 of 50,803) |

### By scenario

| Scenario | Malicious | Detected | First alert after first malicious message | Non-malicious alert rate |
|---|---|---|---|---|
| 01 replay, switch opening isolated | 2 | 2 | 0 s | 0.5% |
| 02 replay, switch opening with context | 27 | 3 | 12.1 s | 1.2% |
| 03 replay of old measurements | 81 | 6 | 4.7 s | 1.0% |
| 04 fake open with intermediate | 150 | 138 | 0 s | 4.7% |
| 05 fake open, end only | 145 | 136 | 0 s | 2.0% |
| 06 measurement distortion up, gradual | 1,509 | 173 | 0 s | 3.7% |
| 07 measurement distortion down, gradual | 1,481 | 149 | 0 s | 1.7% |
| 08 measurement distortion up, sharp | 154 | 27 | 0 s | 3.5% |
| 09 measurement distortion down, sharp | 192 | 17 | 0 s | 4.7% |
| 10 suppression 1-1 tbv0 | 159 | 14 | 0 s | 1.5% |
| 11 suppression 1-1 tbv1 | 188 | 3 | 0 s | 0.8% |
| 12 suppression 1-1 tbv2 | 216 | 14 | 0 s | 1.9% |
| 13 suppression 2 | 164 | 14 | 0 s | 1.2% |
| 14 suppression 1 | 176 | 5 | 0 s | 4.3% |
| 15 flood, repeat | 484,000 | 483,991 | 0.008 s | 6.6% |
| 16 flood, bloat and repeat | 560,000 | 559,995 | 0 s | 7.9% |

## What the result shows

- **Onset is found; the rest of the attack is not.** In 14 of 16 scenarios the first injected message raised an alert. After that, most injected messages looked normal, because each one is judged against the stream's previous message, and once an attacker sustains a change the per-message differences become small again.
- **Replays were found late.** The two replay scenarios with context were caught 12.1 s and 4.7 s after their first malicious message.
- **The false-alarm budget did not hold.** It was missed even on unseen normal captures in development (up to 1.79%). In the attack captures, genuine messages next to injected ones also look unusual: a flood disturbs the timing of every stream, which pushed false alarms to 7.3% in the flood captures.
- **The pooled 99.6% detection reflects the floods.** Floods are over 99% of malicious messages, so the pooled figure says little about the other 14 scenarios.

## What the next version must change (stated before any new result)

1. Judge each stream against a longer, learned history, so a sustained change keeps standing out.
2. Group alerts into incidents. In 14 of 16 scenarios the first injected message was found, and an operator acts on incidents, not on single messages.
3. Measure the false-alarm rate on normal captures held out from fitting, and add more normal data before a new threshold is set.

## Disclosures

- The development alert rates above 1% were visible before the test ran. The protocol fixed that they change nothing, so the test went ahead unchanged.
- Messages within one capture are dependent, so the Wilson intervals understate uncertainty.
