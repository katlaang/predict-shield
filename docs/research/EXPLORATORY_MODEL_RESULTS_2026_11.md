# PREDICT-SHIELD exploratory historical learned threat-ranking results

**Observed on:** November 12, 2026 (GitHub Actions CI). **Status:** completed exploratory research, **not** confirmatory or statistically powered proof of improvement.

## Reproducibility

- Study PR: #27, merged as `7dce41e05038a6b644c23211ba23ad0343ca3e0b`
- GitHub Actions run: `43168631318`, job `131016323192`
- Source declaration: `docs/research/data/exploratory_model_windows_2026.json`
- Algorithm: fixed-parameter standard-scaled logistic regression on EPSS log-odds, EPSS percentile and CVE-year age
- Fit: June 2, July 2 and August 4 historical windows
- September 2: diagnostic; October 2: previously inspected retrospective evaluation
- Sampled model-fitting examples: **30,881**; future catalog-addition positives: **38**
- Full raw historical input files were downloaded from pinned official commits and removed after the CI job. Only a sanitized results artifact is retained.

## Actual observed ranking metrics

| Window | Baseline eligible CVEs | New KEV catalog additions | Additions with baseline EPSS | EPSS-only AP | Learned reranker AP |
| --- | ---: | ---: | ---: | ---: | ---: |
| September 2 | 365,161 | 39 | 12 | 0.00006813098785180933 | **0.001771959854876857** |
| October 2 | 379,952 | 33 | 13 | **0.002157227587594774** | 0.00012644657419271378 |

At precision@100, both methods scored **0.0** in both windows. At precision@1000, in September EPSS-only was **0.0** and learned reranker **0.002**; in October EPSS-only was **0.003** and learned reranker **0.0**.

**The model improved on September's EPSS baseline but lost materially to EPSS in October.** Report both. There is no justified overall model-superiority claim from two windows, and no effect-size threshold was met under a confirmatory protocol.

## Scientific interpretation and limitations

These are very sparse labels and a severely restricted proxy. A CISA KEV catalog addition is not the time when exploitation started and does not establish the severity of operational service risk. EPSS score itself is already a model-derived forecast, so a learned reranker fed EPSS is *not* independent forecasting from raw threat evidence. Deterministic negative subsampling and class-balancing mean model decision scores are not calibrated probabilities.

October's baseline outcomes were viewed before this model was designed. October is therefore **not a blinded, independent held-out evaluation**, despite occurring later than the training windows. September is labeled diagnostic, not a final test. It would be invalid to edit model features/hyperparameters in response to the October loss and then report the same October window as new confirmatory evidence.

Potential explanations (not established causes) include label sparsity, reliance on EPSS-derived features, historical time variation and proxy-label selection bias. The results do **not** establish which explanation is responsible.

## Next protocol before any positive AI claim

1. Define an independent prospective later window that has not been inspected, with a public preregistered feature/split/model specification and full source provenance.
2. Use genuine additional threat signals available at each prediction time, not future KEV membership; preserve a strong EPSS-only comparator and context-aware deterministic baseline.
3. Report missing-source coverage, uncertainty, calibratability, rare-event precision/recall and negative results; predefine acceptable operating precision rather than optimizing on test labels.
4. Do not connect these uncalibrated scores directly to autonomous remediation. Deterministic policy gates, service continuity and independent verification remain separate safety requirements.

This result documents real research progress toward the predictive threat intelligence pillar; it does not prove cybersecurity risk reduction for critical infrastructure or NIW approval criteria.
