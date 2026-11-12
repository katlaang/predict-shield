# Chronological threat-intelligence baseline evaluation

This module evaluates **future KEV catalog additions** as a limited retrospective proxy target. A KEV entry's catalog addition date is **not** an observed exploitation date. Results must never be described as real-world exploitation prediction or validated critical-infrastructure risk.

## Snapshot requirements

- EPSS at an authentic baseline date T, not a recent file relabeled with T.
- KEV JSON genuinely archived at or before T, not reconstructed by filtering a future download.
- KEV JSON genuinely captured on or after T+H (H is the prespecified horizon).
- Authorized or synthetic baseline asset/CVE pairs and asset-context features available at T.

The code rejects feature snapshots later than T, outcome snapshots earlier than T+H and already-known KEV vulnerabilities from the future-addition candidate set.

## Command

```bash
PYTHONPATH=engine python -m predict_shield.threat_backtest \
  --epss-file /data/epss-at-T.csv --epss-date 2026-10-01 \
  --kev-before-file /data/kev-at-T.json --kev-before-date 2026-10-01 \
  --kev-after-file /data/kev-after-T-plus-H.json --kev-after-date 2026-11-01 \
  --assets-file /data/assets-at-T.json --as-of 2026-10-01 \
  --horizon-days 30 --top-k 10 --output /tmp/backtest.json
```

The script produces average precision and precision@K for EPSS-only and the transparent contextual heuristic. No model is fit. If the evaluation has no positive future KEV additions, average precision is null rather than fabricated.

## Validity restrictions

- The same CVE on multiple assets generates dependent labels. The output flags this; any inference or bootstrap must cluster at least by CVE and, for temporal repetitions, use blocked time windows.
- The finite candidate universe is baseline EPSS-covered asset/CVE pairs. Missing EPSS is not interpreted as a zero exploitation probability.
- Source SHA-256 checksums are recorded, but a checksum does not itself prove a file was available on the claimed date. Preserve acquisition timestamps and archived immutable references separately.
- Historical calibration, forecast horizon, choice of K and train/test boundaries must be preregistered before examining quantitative effectiveness.
- Compare with simple fixed baselines, then train and evaluate a genuine model on disjoint chronological data. Any improvement must be demonstrated against the strongest honest comparator.

Tests: `PYTHONPATH=engine python -m unittest discover -s engine/tests -v`.
