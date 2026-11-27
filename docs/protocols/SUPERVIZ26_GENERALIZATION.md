# Superviz26-SQL cross-domain evaluation plan

**Status: PROTOCOL DRAFT, no completed run.** [Official Zenodo publisher](https://zenodo.org/records/21068333), DOI 10.5281/zenodo.21068333. Dataset archive is large (publisher describes 2.4 GB compressed). Do not commit it.

## Source and access
Before download record Zenodo version, published checksum, license or usage rights, archive URL, and exact local checksum. Train only under permissions. **OurAirports data is reused verbatim from Superviz25**, and some target test records are repeated between Superviz26 protocol subsets. Exclude or disclose overlap; never call overlapping rows unseen.

## Three planned studies
1. **LODO:** train benign-only models on permitted source domains, freeze method and signal definitions, then evaluate one held-out target domain. Repeat by target domain using separately predefined protocols; report nonindependent repeats as such.
2. **Concept drift:** fit strictly on earlier benign time periods, calibrate on a later non-test period, freeze and score the later test. Avoid including a test-day template or attack in feature selection.
3. **Few-shot adaptation:** update with only the publisher-allowed target-domain benign training portion; keep its test portion untouched and deduplicate across LODO/FSL releases. Report adaptation cost and before/after comparison.

## Required baselines and metrics
Frozen non-AI request novelty, original v3 scorer, learned anomaly ablation, supervised label-aware reference (clearly disadvantaged/advantaged by access to attack labels), and independent signature controls where applicable. Thresholds MUST come from training/calibration benign, never final test benign. Report attack attempts versus actual successful exploits where labels permit, grouped uncertainty, each domain/technique, FPR at frozen operating point, alerts per nominal host-day only if duration is known, and model/data hashes.

### Outcome
No pass/fail gate is in force yet. Register a reproducible final protocol before fitting any fresh target-domain model. No SQL-only result demonstrates zero-day attack detection on production networks.
