# PowerDuck GOOSE detector v2: second measurement (2026-11-24)

**Outcome: failed its condition again.** It halved false alarms but caught less once an attack was under way.

The captures had already been read by version 1's test, so this is a second measurement, not an unseen test (`experiment-b/powerduck-v2/protocol_v2.json`).

| Stage | Run | Result |
|---|---|---|
| Develop | 45330612517 | freeze `b1f763fa…65fb1` |
| Test | 45330952174 | `experiment-b/powerduck-v2/frozen/test-report.json` |

## Changes from version 1

- **History features.** Each message is compared with its stream's last 20 messages.
- **Tighter threshold:** 0.5% of held-out normal messages, down from 1%.
- **Incident grouping.** Alerts no more than 2 s apart count as one incident.

## Results

| Measure | Version 1 | Version 2 | Limit |
|---|---|---|---|
| Non-malicious messages alerted | 3.0% | 1.48% | at most 1% |
| Scenarios with a malicious message alerted | 16 of 16 | 15 of 16 | at least 12 |
| Malicious messages detected outside the floods | 15.1% (701 of 4,644) | 10.0% (463 of 4,644) | |
| Malicious messages detected inside the floods | over 99.99% | 0.09% | |
| False incidents per hour of capture | not measured | 54 | |
| Held-out normal captures alerted (development) | 1.1% to 1.8% | 0.2% to 1.3% | |

**Missed:** the replay of old measurements (scenario 03).

## What the result shows

- **The history learned the attack.** The comparison window took in every message, including attack messages. Once a flood or a sustained distortion started, the window filled with attack traffic and the attack looked normal. Message-level detection in the floods fell from almost all to 0.1%.
- **False alarms moved in the right direction but stayed over the limit.** At 54 false incidents per hour, an operator would still be flooded.

## What version 3 must change (stated before any new result)

1. Build each stream's history only from messages the model judged normal, so an attack cannot become the reference.
2. Report incidents per hour on held-out normal captures as part of the pass condition, not only alongside it.
