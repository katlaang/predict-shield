# Threat intelligence / risk prioritization baseline (pre-alpha)

This module initiates the missing *predictive threat intelligence* and *automated risk prioritization* workstreams. It is a deterministic, transparent **baseline**, not a learned AI model, not a validated enterprise risk score, and not a production remediation controller.

## Inputs

- Archived FIRST EPSS CSV with `cve` and `epss` columns, plus an explicitly declared actual snapshot date.
- Archived CISA KEV JSON containing `vulnerabilities[].cveID` and `vulnerabilities[].dateAdded`, plus an actual snapshot date.
- Synthetic or authorized asset-context JSON list: `asset_id`, `cve`, `criticality` (0–1), `exposure` (0–1).
- As-of date. Both source snapshot dates must be on or before this date. **Do not mislabel newer downloaded feeds as historical snapshots.** Even when KEV `dateAdded` is old, a newly downloaded catalog is not an archived historical source.

The output includes per-source SHA-256, snapshot dates, KEV membership by the as-of date, missing EPSS indicators and a ranked asset/CVE list.

## Quick start

From repository root:

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
PYTHONPATH=engine python -m predict_shield.threat_intel \
  --epss /path/to/archived-epss.csv --epss-date 2026-11-10 \
  --kev /path/to/archived-kev.json --kev-date 2026-11-10 \
  --assets /path/to/authorized-assets.json --as-of 2026-11-10 \
  --output /tmp/threat-ranking.json
```

## Baseline formula and limitations

For an asset/CVE with available EPSS score:

`score = 0.55 × EPSS + 0.20 × KEV-membership + 0.15 × asset-criticality + 0.10 × asset-exposure`.

Weights are exploratory placeholders, **not empirical estimates** or probabilities. Do not interpret this composite as financial loss, exploit likelihood, or calibrated impact. Assets without available EPSS remain unranked (null score), rather than silently treating unknown likelihood as zero. Inputs do not authorize any remediation action.

The KEV date-added field is a catalog inclusion timestamp, not the date of first exploitation. EPSS at date T is an estimate made at T, not a label for whether future exploitation actually occurs.

## Acceptance criteria for follow-on work

1. Obtain and archive correctly dated, checksum-verified EPSS and KEV snapshots with licensing/provenance information.
2. Declare a prediction horizon and target before seeing outcomes, e.g., future KEV **additions** as an imperfect catalog-event proxy, not observed exploitation or total critical-infrastructure risk.
3. Perform chronological train/calibration/test splitting without using future snapshots or future KEV membership as features.
4. Compare learned temporal risk ranking against EPSS-only, KEV-only and the transparent contextual heuristic, with PR-AUC, ranking precision/recall and uncertainty where justified.
5. Connect *eligible* ranked risk records via a separately versioned adapter to Experiment B; preserve its frozen protocol, private oracle separation, policy gate and independent verification.
6. Build a distinct re-verification scheduler benchmark against fixed-interval and change-triggered rules under an equal probe budget.

## Safety

This module is offline and has no credentials, network calls, asset discovery, scanners or execution hooks. Never claim critical-infrastructure field validation on the basis of synthetic asset fixtures.

## Official historical EPSS archive integrity

The parser accepts the official `.csv.gz` format, records a checksum of the *original compressed bytes*, and compares a modern file's embedded `score_date` with the declared `snapshot_date`. A mismatch fails closed. Older EPSS CSVs without an embedded date are accepted with `embedded_score_date: null` and must have independently preserved historical provenance. Metadata validation alone cannot prove a file existed before the prediction cutoff.

The official historical EPSS archive is `https://github.com/empiricalsec/epss_scores`, not a current-date CSV renamed to an older date. Historical KEV snapshots must also come from dated repository history and preserve the source commit SHA. EPSS model versions change over time; chronological evaluations crossing a version boundary must report the boundary explicitly.
