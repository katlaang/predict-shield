# Single-window historical EPSS baseline, KEV-addition proxy

This analysis uses **actual dated source data**, not generated samples. The source acquisition is pinned in `docs/research/data/historical_sources_2026_10.json`. GitHub Actions retrieves the EPSS October 1, 2026 snapshot, KEV October 1, 2026 snapshot, and a separate future KEV November 10, 2026 snapshot.

The **prediction cutoff is October 2, 2026**, with a 30-day horizon ending November 1, 2026. The measured target is newly recorded CISA KEV *catalog additions* between the cutoff and horizon. It is not a record of the first exploit date, an independent exploitation observation, or operational impact. This evaluation excludes baseline KEV-listed CVEs and ranks only baseline EPSS-covered CVEs.

The benchmark reports:

- Eligible CVE count
- All future KEV catalog additions in the horizon
- The share of future additions covered by the baseline EPSS inventory
- Average precision and precision@10/100/1000 on covered CVEs
- Pinned source commits and original-byte SHA-256 hashes

**Limits:** This is **one retrospective window, one EPSS baseline, zero trained AI models**, and zero actual assets or infrastructure operators. It cannot substantiate model superiority, statistical generalization, calibrated attack probabilities, or the effectiveness of cyber defense. KEV listing practices and time delays introduce label bias and missingness. Multiple independent windows, explicit holdout protocol, calibration, and non-AI comparator selection are required before a future model study.

Execute the source-acquisition workflow and `.github/workflows/threat-cve-proxy.yml`; retain the generated source hashes and proxy report as research provenance. Do not commit the downloaded raw datasets.
