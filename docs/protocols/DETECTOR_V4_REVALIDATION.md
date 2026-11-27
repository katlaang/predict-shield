# Detector v4: development and prospective revalidation plan

**Status: DESIGN ONLY.** v3 frozen scores, original tests, and reports must remain unchanged. This document is written *after* v3 Juice Shop results were observed; no new preregistration claim is made yet.

## Observed failure
Juice Shop v3 gave a high fused threshold (25.69) because response-shift scores saturated on ordinary JSON; isolated rare request/host signals could not cross it. Its 9/10 matched ZAP-alert detections were all SQL injection. An isolation forest worsened the fused result relative to request novelty alone in the same test. See [PR #172](https://github.com/katlaang/predict-shield/pull/172).

## Candidate v4, training-domain only
- Preserve per-field character/length/parameter profiles as a reference baseline. Expand duplicate query-parameter and header handling so the feature extractor does not silently collapse evidence.
- Independently calibrate individual novelty and response/host/temporal signals. Evaluate max-of-calibrated-evidence or gated fusion beside traditional Fisher fusion; **do not guarantee** a 0.5% combined alert budget by assuming component scores are independent.
- Model JSON response variation with typed endpoint/response templates and bounded distributional statistics; do not allow a saturated response statistic to suppress independent request evidence.
- Use group-aware splits across sessions/hosts/applications; hold out later dates and entire attack families. Allocate sufficient benign volume for calibration of low alert rates.
- Keep AI-first learned temporal/relationship representation as a candidate, but compare every AI component to simple novelty, forest ablation and signature controls at matched false-alarm rates.
- Add bounded streaming inference: authentication, schema and size checks, missing value/late event handling, model fingerprint and abstain/UNKNOWN. No learned detector directly authorizes action.

## Prospective test gate
Before a fresh final test, commit a new specific protocol naming app version, scope, seeds, capture-group splits, anomaly/AI definitions, threshold calibration, independent exploit-confirmation rule, valid ground truth, minimum events per attack family, and pass/fail thresholds. The first Juice Shop run **cannot** become an untouched v4 test. Select a new site or independent later attack sessions and mark repeated generator families as seen. Use realistic benign sessions and quantify false alerts per host-day where exposure is known.

Do not declare improved detection without showing both the accuracy gain *and* false-alarm/disruption impact, against competent ablations.
