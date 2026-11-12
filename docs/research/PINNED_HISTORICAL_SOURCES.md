# Pinned historical threat-data acquisition (research baseline)

This is an acquisition manifest and downloader for a prospective *future KEV-catalog-addition* proxy backtest. It does **not** represent an exploitation event classifier, prove a model improves on FIRST EPSS, or validate risk to real infrastructure assets.

## Verified public source locations

- FIRST / Empirical Security official EPSS historical archive: https://github.com/empiricalsec/epss_scores
- CISA official KEV catalog history mirror: https://github.com/cisagov/kev-data

The manifest at `docs/research/data/historical_sources_2026_10.json` pins full 40-hex Git commit refs for EPSS at October 1, 2026; KEV at October 1, 2026; and a later KEV snapshot at November 10, 2026. The *feature cutoff* is October 2, with a 30-day catalog-addition horizon ending November 1. The later KEV file is used **only for labels**, with `dateAdded` filtered to the horizon. Pinned Git commit references prevent changing branch heads from silently modifying this dataset, but researchers must separately verify observed commit timestamps and upstream history.

## Fetch

From repository root, on a machine with outbound access to raw.githubusercontent.com:

```bash
PYTHONPATH=engine python -m predict_shield.archive_acquire \
  --manifest docs/research/data/historical_sources_2026_10.json \
  --output-dir /tmp/predict-shield-2026-10-data
```

The downloader rejects mutable refs, unauthorized repositories, unsafe paths, source dates beyond the pre-action cutoff, mismatched embedded EPSS score dates and outcome snapshots earlier than the horizon. The output includes SHA-256 checksums and immutable upstream refs in `acquisition.json`.

**No archived data is committed to the repository.** The downloader does not treat missing files or failed network access as successful acquisition. It does not overwrite existing source artifacts. It must be run and checked independently before using any performance results.

## Evaluation

After acquisition, create an appropriately documented *as-of* synthetic or authorized asset/CVE inventory, then run the existing `predict_shield.threat_backtest` with the actual acquired files. Asset coverage and dependent CVE labels restrict the interpretation. A single time window with no trained model is insufficient to claim predictive performance or AI benefit. Additional independent time windows, preregistered outcome definitions, model-version boundaries and chronological training/test splits are required before publishing AI results.
