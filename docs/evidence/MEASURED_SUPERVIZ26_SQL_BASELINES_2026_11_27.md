# Superviz26-SQL baselines beside the frozen detector (2026-11-27)

**Outcome: on these three applications, the OWASP Core Rule Set is a much stronger baseline than it was on Superviz25.** At paranoia level 1 it caught 96.4% to 98.5% of attack queries with almost no benign alerts (0.0% to 0.02%). The frozen benign-only detector caught more (99.3% to 99.9%), including every exploitation query and nearly all reconnaissance probes. It did so at 0.44% to 0.51% benign alerts by its frozen threshold, or at 0.1% with a lower threshold set on the sample. The supervised reference, trained with attack labels, did not exceed the frozen detector.

- **Protocol:** `experiment-b/superviz26-sql/baselines/protocol.json`, registered before any baseline was run.
- **Code:** `experiment-b/superviz25-sql/baselines.py`, unchanged.
- **Run:** 45948038789, one job per application. Reports are in `experiment-b/superviz26-sql/baselines/reports/`.
- **Sample per application:** 10% of benign and 25% of attack test queries (seed 2026112901), about 302,000 benign and 84,000 attack queries.

| | sakila | AdventureWorks | OHR |
|---|---|---|---|
| **Frozen detector, frozen threshold** | **99.3% at 0.50%** | **99.9% at 0.45%** | **99.9% at 0.51%** |
| Frozen detector, threshold at 0.1% benign | 99.3% | 99.9% | 99.9% |
| Supervised reference at 0.5% benign | 98.7% | 99.8% | 99.6% |
| libinjection | 59.2% at 0.0% | 81.1% at 0.0% | 77.5% at 0.0% |
| CRS paranoia level 1 | 96.7% at 0.02% | 98.5% at 0.0% | 96.4% at 0.0% |
| CRS paranoia level 2 | 98.3% at 0.41% | 99.7% at 5.8% | 99.5% at 0.14% |
| CRS paranoia level 3 | 98.8% at 8.3% | 99.8% at 5.8% | 99.6% at 0.14% |
| CRS paranoia level 4 | 99.9% at 64.9% | 99.9% at 57.5% | 99.7% at 41.7% |
| ROC AUC: frozen / supervised | 0.997 / 0.998 | 1.000 / 1.000 | 1.000 / 1.000 |

## Where they differ

- **Reconnaissance probes:**
  - CRS level 1 caught 78.7% (sakila), 84.5% (AdventureWorks) and 87.7% (OHR).
  - The frozen detector caught 95.4%, 99.1% and 99.5%.
  - Exploitation queries were caught at 99.4% to 99.8% by CRS level 1, and at 100% by the frozen detector.
- **By technique:**
  - CRS level 1 missed every `insider` query in all three applications.
  - Its weakest other techniques were stacked queries (79.7% to 92.7%), time-based (79.1% to 96.7%) and union (83.4% to 86.8%).
  - The frozen detector's weakest technique was time-based, at 93.5% (sakila).
- **Cost of each:**
  - CRS needs no training data from the application and raised almost no benign alerts at level 1.
  - The frozen detector needs benign traffic from each application. Its 0.5% benign alert rate is set by design, and it would cost about 15,000 alerts per 3 million queries.
  - On these clean, template-generated benign queries, a threshold set at 0.1% on the sample kept the same detection. That threshold is chosen with test labels in view, so it shows headroom rather than a deployable setting.
- **Harness:** CRS's level 4 blocked the multi-word benign probes in every application, as it did on Superviz25. Single-token probes passed at every level, so the client was not the cause.

## How to read this

The benign-only detector catches what signatures and rules miss: insider-style queries, and the probes before an attack. Its cost is per-application training data and a higher benign alert rate at its registered operating point. On Superviz25-SQL, CRS needed 5.5% benign alerts to match the detector. Here level 2 came close at 0.14% to 0.41% in two of three applications. These results are from generated benign traffic, and the CRS margin may differ on real inputs, as may ours.
