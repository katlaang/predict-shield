# v3.2 unseen-page fallback on real web logs: failed (2026-11-27)

**Outcome: the registered primary passed in 1 of 2 organizations, and v3.2 made Organization Y much worse.** In the early test window, 76% of Organization Y's requests alerted under v3.2, against 0.07% under v3. That window had never been scored, but its requests were part of the original v3 model's training period, so it is not an independent dataset. The cause is in how the change interacts with calibration, explained below. The method is not carried forward.

- **Protocol:** `experiment-b/real-logs-indonesia/protocol_v32.json`, registered before any v3.2 model was fitted or any new window was scored.
- **Freeze:** `f776d2a4…fa4f`.
- **Runs:** develop 46034494173; single test 46035174294.
- **Change:** a template absent from training is scored against its site's pooled profile instead of receiving the maximum novelty score.

| Arm | Organization | Requests | Alerts | Without independent evidence | Detection proxy | Pass |
|---|---|---|---|---|---|---|
| v3, early window | X | 3,462 | 1.24% | 0.12% | 25.5% | yes |
| **v3.2, early window (primary)** | **X** | 3,462 | 1.07% | 0.09% | 22.2% | **yes** |
| v3, early window | Y | 558,017 | 0.07% | 0.02% | 24.2% | yes |
| **v3.2, early window (primary)** | **Y** | 558,017 | **76.1%** | **76.0%** | 43.2% | **no** |
| v3.2, original split (secondary) | X | 6,244 | 0.82% | 0.13% | 10.2% | yes |
| v3.2, original split (secondary) | Y | 279,389 | 33.8% | 2.94% | 99.4% | no |

## Why it failed

- **Whole sites with no training data:** in Organization Y's early window, 76% of test requests fall on templates unseen in training, mostly because several sites' logs begin after the training window. For a site with no training data at all, v3.2 still gives the maximum score, as registered.
- **The calibration shift:**
  - Under v3, the benign calibration split contained many maximum scores: rows whose template appeared in calibration but not in the 40% fit split. A maximum score therefore looked ordinary to the tail probability, and test requests on unseen templates seldom alerted. That is the 0.07% above. It was an accident of calibration, not a judgement about the inputs.
  - Under v3.2, those calibration rows got pooled scores, so a maximum score became rare in calibration and extreme in test. Every request from a new site alerted.
- **Original split (secondary):** the same shift changed how ordinary novelty combined with the isolation forest. Fused alerts then followed the forest, which flagged the password-guessing campaign. Detection of independently flagged requests rose to 99.4%. Alerts rose to 33.8%, mostly that campaign. Unconfirmed alerts stayed at 2.94%, essentially unchanged from v3's 2.91%.

## What is and is not established

- **The evidence supports the calibration explanation:** the frozen novelty threshold for Organization Y fell from 10.0 under v3 to 1.0 under v3.2 in the early window.
- **The split between causes is not measured:** no ablation separated the calibration shift from the share of requests on sites with no training data.
- **Neither result settles the general question:** v3's low rate does not show that it handles new websites well, and v3.2's failure does not show that every site-wide approach fails.
- **Labels:** as in the v3 real-log test, alerts were judged by agreement with CRS and libinjection, not by adjudicated labels.

## What this means

- **Calibration makes v3's unseen-template behaviour fragile.** Its alert rate on new pages depends on how many templates happen to fall between the fit and calibration splits, which nobody chose.
- **A next design should separate three cases:** known sites, new pages on known sites, and entirely new sites. New sites get an onboarding or abstention policy until enough history exists, and calibration should be checked on site-separated development data.
- **A further version should not be fitted and tested on these logs again.** This data has now informed two designs. The next version needs fresh real traffic, either another public log set or a pilot.

v3.0 remains the detector of record. Its real-traffic result is in `MEASURED_REAL_WEB_LOGS_2026_11_27.md`.
