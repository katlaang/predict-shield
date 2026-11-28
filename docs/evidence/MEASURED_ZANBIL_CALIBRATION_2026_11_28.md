# Choosing a calibration on real e-commerce logs (zanbil.ir): failed on its band (2026-11-28)

**Outcome: the registered winner failed its pass condition, in the cautious direction.** The method chosen on the early days does not score new pages. On the two test days it alerted on 0.22% of known-page requests, just under the registered floor of 0.25%, against a budget of 0.5%. Two findings are clearer than the pass or fail:

- **The current calibration floods new pages, confirmed on a second real dataset.** The random-split calibration used by v3 alerted on 9.8% (selection) and 11.4% (test) of requests to pages absent from training.
- **Calibrating on later data removes that flood.** Every time-ordered candidate kept new-page alerts at or below 0.5%.

- **Data:** the zanbil.ir nginx access log, 22 to 26 January 2019 (Zaker, Harvard Dataverse doi:10.7910/DVN/3QBYB5, CC0). The owner supplied the Kaggle mirror, pinned by SHA-256 `ac587ea6…763f5a` under amendment 1, made before any request was read.
- **Scope:** 1,900,342 requests with query strings.
- **Protocol:** `experiment-b/zanbil-calibration/protocol.json`, registered before the log was obtained.
- **Freeze:** `275c6fb2…ef55`, committed before the test days were scored.
- **Run:** in the owner's private workspace. The raw log is never committed; only counts are.
- **Periods:**
  - development: 22 to 24 January (1,170,474 requests);
  - selection: fitted on its first two thirds, scored on the last third;
  - test: 25 and 26 January (729,868 requests).

| Candidate | Selection: known / new pages | Test: known / new pages | Test alerts per day |
|---|---|---|---|
| C0 random split (v3) | 0.60% / 9.83% | 0.27% / 11.37% | 1,626 |
| C1 time-ordered | 0.77% / 7.92% | 0.22% / 0.01% | 772 |
| C2 time-ordered, separate per stratum | 1.03% / 0.41% | 0.26% / 0.48% | 966 |
| **C3 time-ordered, new pages not scored (winner)** | 0.77% / not scored (2.5%) | **0.22%** / not scored (2.4%) | 770 |

Selection score: the largest distance from 0.5% in any scored stratum. C3 scored 0.27 points, C2 0.53, C1 7.4 and C0 9.3.

## What the numbers show

- **Day-to-day drift is larger than the band:** C1 and C3 alerted on 0.77% of known-page requests in the selection window and 0.22% on the test days. The traffic shifted between those days, and the threshold did not follow. This is a separate calibration problem from new pages: it needs a recalibration cadence, such as a rolling window.
- **Separate strata were the most balanced on the test days, but that is after the fact:** C2 put both strata inside the band on the test days (0.26% and 0.48%). It lost the registered selection, so that result is reported, not claimed.
- **Agreement with libinjection was low:** libinjection flagged 246 test requests. The candidates alerted on 10% to 15% of them. The logs have no attack labels, so this is an agreement measure only.

## How to read this

- **The protocol worked as intended:** the choice was made on early data and fixed before the test. The test then showed both that the choice was too cautious on later days and that the selection window was a poor guide to them.
- **For the design:**
  - Calibration must come from data later than the fit. The random split is the source of the new-page flood seen on both real datasets.
  - Calibration must also be refreshed as traffic drifts.
  - Separate strata deserve the next registered test, with selection over several windows instead of one.
- **Limits:**
  - one site over five days;
  - no attack labels;
  - new websites cannot be tested here;
  - numpy 2.5.3 locally, against 2.3.4 pinned in CI.
