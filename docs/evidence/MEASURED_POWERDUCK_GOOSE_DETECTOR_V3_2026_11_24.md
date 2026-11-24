# PowerDuck GOOSE detector v3: third measurement (2026-11-24)

**Outcome: failed its condition.** Building each stream's history only from messages judged normal brought flood detection back, but false alarms rose further.

Versions 1 and 2 had already read these captures, so this is a third measurement, not an unseen test (`experiment-b/powerduck-v3/protocol_v3.json`).

| Stage | Run | Result |
|---|---|---|
| Develop | 45337132344 | freeze `93e14a4c…4baec` |
| Test | 45338172898 | `experiment-b/powerduck-v3/frozen/test-report.json` |

## Change from version 2

- **Gated history.** A message enters its stream's 20-message history only when the detector did not alert on it. Messages are scored in time order against the history the detector's own earlier decisions admitted.
- **Incidents in the pass condition.** False incidents per hour now count toward pass or fail, on held-out normal captures and on the attack captures. The limit is 2 per hour.
- Everything else is as in version 2. Per-message scoring uses a direct walk of the fitted trees, checked against scikit-learn to 1e-9.

## Results

| Measure | Version 2 | Version 3 | Limit |
|---|---|---|---|
| Non-malicious messages alerted | 1.48% | 1.65% (958 of 57,965) | at most 1% |
| Scenarios with a malicious message alerted | 15 of 16 | 15 of 16 | at least 12 |
| Detection in flood scenario 15 | under 0.1% | 62.1% | |
| Detection in flood scenario 16 | under 0.1% | 99.99% | |
| Malicious messages detected outside the floods | 10.0% | 9.6% (454 of 4,644) | |
| False incidents per hour, attack captures | 54 | 80 | at most 2 |
| False incidents per hour, held-out normal captures | 17 to 90 (per capture) | 58 (pooled) | at most 2 |

Three of the four checks failed. The development stage had already shown 58 false incidents per hour before any attack capture was read.

**Missed again:** replay of old measurements (scenario 03).

## What the result shows

- **Gating works for what it was built for.** Attack traffic no longer becomes the reference, so sustained floods are detected again.
- **Gating also locks history after a false alarm.** In the attack captures, false incidents rose from 54 to 80 per hour. Scenario 14 alone had 44. This was the risk registered beforehand: once a legitimate message alerts, the history stops taking in the change, so later normal messages keep alerting.
- **The false-alarm rate on normal captures is far from usable.** At 58 incidents per hour, message-level anomaly scoring on these GOOSE features cannot meet an operator's budget. The remaining malicious messages outside the floods (distortion, suppression, replay) look like normal messages to these features.

## Next step (stated before any new result)

No version 4 of this message-level forest. Distortion and suppression attacks change what a measurement means, not how a message looks, so the next detector must check physical consistency between streams (for example, a breaker state against the measurements that should follow it).
