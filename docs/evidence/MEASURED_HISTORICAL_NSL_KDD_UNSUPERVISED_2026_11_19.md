# Measured external *historical* benchmark: learned anomaly detection on NSL-KDD

**Experiment date:** November 19, 2026 (GitHub runner log Nov 20 UTC).  
**Measured status:** REAL BENCHMARK EXECUTED AND ACCOUNTING CHECK PASSED.  
**Scientific scope:** Historical NSL-KDD benchmark only. No live operator, unseen real zero-day, authenticated publisher-byte equality, or U.S. critical-infrastructure effectiveness has been established.

## Provenance and reproducibility

- Measured CI: [Historical external NSL-KDD learned anomaly evaluation, run 44648143458](https://github.com/katlaang/predict-shield/actions/runs/44648143458). Job concluded **success**; [PR #137](https://github.com/katlaang/predict-shield/pull/137) merged at `2ad0af23b67c399549d5121c6b9da9a738f2f363`.
- Original dataset description: [Canadian Institute for Cybersecurity, University of New Brunswick, NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html). The test set is an older research benchmark derived from KDD'99 and must **not** be described as live, contemporary operator telemetry.
- Public *nonpublisher* mirror: `Jehuty4949/NSL_KDD`, immutable commit `27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9`. The runner independently recomputed and checked each **Git object SHA-1**, then recorded each complete file's SHA-256. This establishes equality to the pinned GitHub mirror objects, **not** to any unavailable publisher original.
- Original measurement artifact: GitHub Actions artifact `nsl-kdd-historical-learned-anomaly-metrics`, artifact ID `14588404511`. This report records the metrics before the artifact's retention period expires. The artifact itself is kept unchanged at `experiment-b/nsl-kdd-anomaly/original-report/nsl-kdd-historical-result.json` (SHA-256 `4769308f…3f79`, copied by run 44915072250; see `PROVENANCE.txt` there).
- Train file: `KDDTrain+.txt`; 125,973 rows; 19,109,424 bytes; Git blob `20002897492adc110190a10509aa694f26f7f308`; SHA-256 `1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95`.
- Test file: `KDDTest+.txt`; 22,544 rows; 3,441,513 bytes; Git blob `b30e89605285a5ccd8cf8fd38dba72906c20d3dd`; SHA-256 `fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84`.
- Model and protocol: `experiment-b/nsl-kdd-anomaly/run_historical_benchmark.py` and `frozen_protocol.json`. Isolation Forest, 100 trees, at most 512 samples per tree, seed 20261119. **No explicit signatures and zero malicious examples used in model fitting.** Numeric features only. A content-hash partition placed 50,482 normal records into model fitting and 16,861 normal records into benign-only cutoff calibration. The exact model tree fingerprint was `b214b49183109bdd07ff9c18dc41450dc8df201180e3cea5c2026636c9c61737`; pre-test freeze fingerprint `a54c88f2875ce55e00b126f59924df8934a95af5c58d13e769d95c4c5b0c81da`.
- Calibration: predeclared sample false-positive ceiling 5%. Cutoff `0.538077480712127` selected solely on the 16,861 benign calibration rows, with 842 alerts (4.9938%). **Test file was read only after model and threshold freezing.**

## Actual measured held-out test outcomes

| Count/measure | Observed |
| --- | ---: |
| Test flows | **22,544** |
| Actual labeled attacks | **12,833** |
| Actual labeled benign | **9,711** |
| True positives (TP) | **8,580** |
| False negatives (FN) | **4,253** |
| False positives (FP) | **274** |
| True negatives (TN) | **9,437** |
| Attack recall (8,580 / 12,833) | **66.86%** |
| Benign false-positive rate (274 / 9,711) | **2.82%** |
| Precision (8,580 / 8,854) | **96.91%**, *benchmark prevalence only* |
| Test records with attack-type names absent from the published train labels | **3,750** |
| Detected among those attack records | **2,759** |
| Missed among those attack records | **991** |
| Recall on these unseen-type attack records (2,759 / 3,750) | **73.57%** |

**Unseen-type here means that the type-name string is absent from the published training file.** It does **not** mean the attacks were newly invented, previously unreported to security experts, or zero-days. The public test dataset is historically known; this experiment is not a prospective blind field test. These attack rows come from a dependent benchmark population, not 3,750 independent real incidents.

### Important uneven performance

Selected exact per-type counts extracted from the same measured artifact:

| Published attack type absent from training labels | Detected | Tested | Recall |
| --- | ---: | ---: | ---: |
| `mscan` | 988 | 996 | 99.20% |
| `apache2` | 734 | 737 | 99.59% |
| `mailbomb` | 12 | 293 | 4.10% |
| `snmpguess` | 0 | 331 | **0%** |
| `snmpgetattack` | 0 | 178 | **0%** |
| `sendmail` | 0 | 14 | **0%** |

The low recalls and 4,253 overall missed attack flows are **material negative findings**. Model capability is uneven. Aggregate accuracy must not conceal them.

## Scientific conclusion and explicit limits

This experiment establishes that the implemented **unsupervised** model did classify some held-out labeled attack flows in an independently released *historical benchmark* without fitting on attack labels or first matching explicit intrusion signatures. It also produced many missed attacks and some false positives. It does **not** establish ability to reliably detect future attacks at a real operator, detect actual zero-day exploitation, preserve control-system availability, independently verify threat attribution, or select and execute safe defensive responses.

Calibrated false-positive ceiling applies to a partition of the *training file*, **not** to future traffic. Precision is benchmark-prevalence dependent and cannot be extrapolated to an actual low-prevalence network. The records have dependencies and cannot justify naive independent flow-binomial confidence intervals for site-level effectiveness. The mirror's equivalence to publisher source and label validity have not been independently authenticated.

**Preceding negative attempt:** A separate, predeclared real CTU-13 original-publisher download run in [PR #136](https://github.com/katlaang/predict-shield/pull/136) failed with `urllib.error.URLError: <urlopen error timed out>` in [run 44647359159](https://github.com/katlaang/predict-shield/actions/runs/44647359159) **before any original CTU-13 recording was measured**. It was closed unmerged. The successful NSL-KDD run is a different and explicitly inferior-to-real-telemetry benchmark, not a replacement claim of CTU-13 measurement.

## Next validation gates

1. Repeat on real, modern, permissioned external attack **and** benign telemetry with independently checked event labels and source SHA-256 pins, group-separated sites/campaigns, and prespecified thresholds.
2. Evaluate unseen attack families, routine operations/maintenance drift, alert latency and false alerts per asset-day. Report confidence intervals at independent site/campaign unit and separate false-negative families.
3. Integrate the learned detector's authenticated read-only findings with the existing intake and AI-assisted risk assessment, without bypassing human/change authorization and independent post-response verification.
4. Conduct independent U.S. critical-infrastructure pilot under signed operator scope, with non-mutating shadow mode before considering any action.

### Reproduction

```bash
python -m pip install scikit-learn==1.7.2
python experiment-b/nsl-kdd-anomaly/run_historical_benchmark.py \
  --protocol experiment-b/nsl-kdd-anomaly/frozen_protocol.json \
  --output /secure/measurements/nsl-kdd-historical.json
```

The report flags `zero_day_detection_established=false`, `operational_attack_detection_established=false` and `external_current_critical_infrastructure_effectiveness_established=false`.
