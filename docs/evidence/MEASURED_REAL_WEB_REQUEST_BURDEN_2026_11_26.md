# PREDICT-SHIELD real-web-log applicability pilot, November 26, 2026

**Status: first-scored measurements completed, full fused DVWA v3 validation NOT completed. No real-world false-positive rate can be derived from these unlabeled logs.**

## Frozen component and scope

The committed DVWA v3 frozen model SHA-256 is `7ae09d7d4d4a39d762f1edf3ca214aa89c6ebe2f23e851c865e02a2ae4eda97a`. The request-novelty threshold is **0.0**. We verified the unchanged original feature code/model bundle and used **only the frozen request-novelty scorer**, not the fused model. Web access logs lack host process/file/network activity and full HTTP response bodies. Publisher-held real logs contain unknown malicious/benign mixtures.

**Evidence:** first-scored GitHub Actions run [45898435311](https://github.com/katlaang/predict-shield/actions/runs/45898435311); the original measured head is `39168b68109636bdf2a289fd8b8421f77e553413`. The project stores derived aggregates in `experiment-b/real-traffic/reports/`, never raw third-party HTTP logs.

## Source A: Indonesian public-sector Organization X

- Publisher: [Web Server Log Dataset v1](https://zenodo.org/records/20001206), published May 3, 2026, **MIT** license declared.
- `organization-x.zip`, published MD5 `b4bf79effa6f3ee1b9e53f278d916620` **verified against actual archive**.
- Observed file: **2,135,289 bytes**; SHA-256 `1429caba2803c3e8c90e9fb287bc04f6f8249f8bb34712b39127044e134d631f`.
- Log lines inspected: 31,035; parsed HTTP requests **21,617**; non-parsed lines **9,418** (not automatically counted as benign or attacks).
- Query-bearing requests: **1,930 / 21,617 = 8.93%**. POST or other methods with unavailable bodies: **1,789**.
- Request-novelty component alerts: **21,617 / 21,617 = 100%**; paths absent from DVWA training vocabulary: **21,617 / 21,617**.
- The parsed subset covers 2 local calendar dates. This is **not** a study of every access/error/auth/syslog record in the larger publisher collection.
- **Interpretation:** every observed request path was outside the frozen DVWA vocabulary. The scorer therefore flagged everything by design. These are NOT verified false alarms; no independent benign labels or attack recall established.

## Source B: December 2025 Polish e-commerce web access logs

- Publisher: [Online Shop Server Logs, Zenodo 18895701](https://zenodo.org/records/18895701), published March 6, 2026, **CC BY 4.0** declared.
- `domain.access.log-20251208.anonymized.txt`, published MD5 `725822e13e09281b498e7cd5d082a039` **verified**.
- File: **28,630,570 bytes**, SHA-256 `d60f8cf9a907a7d70df201e8d931b5df6d3d384e21ed058551cc154089b84f59`.
- HTTP requests parsed: **178,939 / 178,939** log lines.
- Query-bearing requests: **0**, consistent with publisher's explicit sanitization of query strings. Body data from **19,837 non-GET/HEAD** requests is not available.
- Request-novelty component alerts: **178,920 / 178,939 = 99.9894%**. Unknown paths: **178,920**. Exactly **19** paths happened to match DVWA's training vocabulary, which does not establish genuine transferability.
- The log spans about one 24-hour period crossing two calendar dates; reporting alerts per "observed day" would be misleading without the time-zone and span caveat.
- **Interpretation:** overwhelming application-vocabulary mismatch; query strings removed, so the Polish source cannot test the input-value part of DVWA v3. Do NOT present these alerts as confirmed false positives.

## Sources examined and blocked, no data ingestion

| Source | Status and verified impediment |
| --- | --- |
| [EClog, Harvard Dataverse](https://doi.org/10.7910/DVN/Z834IK) | Original 2019-2020 e-commerce dataset and schema discussed in [peer-reviewed Data in Brief article](https://pmc.ncbi.nlm.nih.gov/articles/PMC7540248/), but dataset-specific license, file list and checksums were not independently confirmed due repository access challenge. Publisher's article license is not the underlying dataset license. |
| [CDSL Website Access Logs](https://github.com/cdsl-research/website-access-logs-public) | The README publishes 2023-February 2026 anonymized multi-service access logs. An inspected 2026 sample retained some queries. GitHub API reported no explicit license. Dataset may not be ingested for PREDICT-SHIELD until permission/reuse rights are established. |
| [Biblio-US17](https://doi.org/10.12795/11441/148254) | University of Seville's 2017 real-traffic dataset, about 47 million requests. Its official repository serves a "Request a Copy" page for raw files; file access and reuse terms are not resolved. Labeling is not fully independent of sanitization/signatures. |

## What this proves and what it does not

1. **Demonstrated**: the original request-novelty scorer is reproducibly loadable, pinned, and can process the approved real-world log formats; sources passed publisher checksum checks; its domain-specific URL profiles trigger near-universal alerts on unrelated sites.
2. **Not demonstrated**: real-world benign false-positive rate; malicious detection recall; full fused model performance on public logs; cross-application generalization; real critical-infrastructure operations.
3. **Review not yet performed**: no human examined the random alerted/nonalerted cases. A new offline private review manifest generator is available; it does not upload raw requests or identify benign traffic automatically. The Indonesian dataset has no unalerted request under this component; the Polish one has only 19. Estimating false-alarm fractions from either source would be statistically and scientifically unsound without independent labels.
4. **Next technical milestone**: register a separate, prospective adaptation protocol with external normal-training period, later fixed evaluation period, proper host/request/response instrumentation if possible, independent truth labels, a non-AI baseline and matched AI ablations. Never retrofit new training into the v3 frozen report.

**Conclusions:** The real-traffic transfer test exposes a substantial domain shift. PREDICT-SHIELD's scientific status is unchanged: AI decision superiority and effectiveness for U.S. critical infrastructure remain unproven.
