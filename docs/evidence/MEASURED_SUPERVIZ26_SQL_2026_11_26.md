# v3 SQL method on Superviz26-SQL: four application domains (2026-11-26)

**Outcome: the primary condition passed in all three new domains (sakila, AdventureWorks, OHR).** Each model was learned only from that application's own benign queries, then tested once:

- Detection: 99.3% to 99.9% of sqlmap attack queries caught.
- Benign alerts: 0.44% to 0.51% of about 3 million benign queries per domain.

The two registered failure controls failed as predicted. With no benign data from the target application, every benign query alerts.

- **Dataset:** Superviz26-SQL, from Telecom Paris and Inria Rennes (Zenodo 21068333, CC-BY-4.0). Archive pinned by the publisher's MD5 and by SHA-256 `9f19d1bb…6cc5`.
- **Labels:** by construction. Benign queries are filled from per-domain query templates; attacks come from sqlmap campaigns.
- **Protocol:** `experiment-b/superviz26-sql/protocol.json`, registered after reading only the member list, column names and row counts, and before any model was fitted. It is the final protocol that the draft plan (`docs/protocols/SUPERVIZ26_GENERALIZATION.md`) required.

| Stage | Run | Result |
|---|---|---|
| Archive listing and row counts | 45925835450 | 20 CSV members; train splits all benign |
| Develop (18 arms, train rows only) | 45928319914 | freeze `b739c584…ced35`; models kept as a workflow artifact, hashes in `freeze.json` |
| Test (once) | 45929721027 | `experiment-b/superviz26-sql/frozen/test-report.json` |

## Method

The method is the Superviz25 v3 SQL method, imported unchanged; nothing was tuned on this dataset.

- **Input novelty:** a per-template profile of character classes and input length.
- **Learned anomaly:** an isolation forest.
- **Fusion and threshold:** benign-calibrated tail probabilities combined with Fisher's method; threshold at 0.5% on held-out benign training rows.

Each arm fits its own model from its own benign rows.

## Primary result: each domain learned from its own benign traffic

| Domain | Benign alerts | Attacks caught | Weakest technique | Result |
|---|---|---|---|---|
| B sakila | 15,179 of 3,016,033 (0.50%) | 335,404 of 337,638 (99.3%) | time 93.9% | **pass** |
| C AdventureWorks | 13,325 of 3,016,512 (0.44%) | 336,912 of 337,159 (99.9%) | stacked 97.9% | **pass** |
| D OHR | 15,417 of 3,014,539 (0.51%) | 338,710 of 339,132 (99.9%) | stacked 98.4% | **pass** |
| A OurAirports (replication) | 15,881 of 3,017,390 (0.53%) | 308,190 of 336,281 (91.6%) | (as Superviz25) | pass |

- **Exploitation queries:** 100% caught in every domain. All misses were reconnaissance probes: 95.5% of probes caught in B, 99.2% in C, 99.5% in D.
- **Domain A replication:** Domain A reproduces the Superviz25 result exactly, to the alert: 15,881 benign alerts and 308,190 attacks caught. This shows the pipeline is deterministic. It is not new-domain evidence, because the OurAirports data is Superviz25 verbatim.
- **Input novelty alone:** caught 99.3 to 99.9% at 0.01% benign alerts in B, C and D. Most fused benign alerts come from the forest. On these domains, novelty alone would have been the better operating point. That observation is after the fact and is not a tuned result.

## Limited target data (few-shot, descriptive)

| Domain | 500 benign rows | 5,000 benign rows | Full (335,306) |
|---|---|---|---|
| B | 98.4% caught, 2.54% benign | 99.2%, 1.01% | 99.3%, 0.50% |
| C | 98.4%, 0.52% | 99.8%, 0.61% | 99.9%, 0.44% |
| D | 94.8%, 0.41% | 99.3%, 0.32% | 99.9%, 0.51% |

- **500 rows:** these are not enough to see every template (37 of 57 templates seen in B, 28 of 46 in D).
- **Why the 500-row threshold is coarse:** it comes from only 125 rows, so the realised benign rate drifts: 2.5% in B.
- **5,000 rows:** this is about 1.5% of the training data, and it comes close to the full-data result.

## Registered failure controls

- **Leave one domain out:** 100% of benign queries alerted in every target domain. This was the registered prediction: per-template profiles treat every template of a new application as unseen. The method does not transfer between applications without benign data from the target. The forest alone kept its benign rate low (0.0 to 0.14%), but caught only 67.5 to 94.7% of attacks.
- **Template drift:**
  - Origin-template test rows behaved like the in-domain arm: 0.45 to 0.57% benign alerts, and 94.8 to 99.9% of attacks caught.
  - Shifted-template rows alerted 100%, benign included, as predicted. A new query template in production needs re-learning before this method can score it.

## How to read this

- **Strength:** with benign traffic from the target application (even about 5,000 queries), the method detects sqlmap injection in three applications it was never designed on, at about 0.5% benign alerts.
- **Synthetic benign data:** benign data is generated from fixed templates and value pools, so benign test traffic matches training closely. Real users would raise the benign rate. The very high detection in B to D likely reflects simpler benign value pools than OurAirports.
- **Volume:** 0.5% of 3 million queries is still about 15,000 alerts per domain.
- **No transfer:** the method needs per-application benign data. This is a deployment requirement, measured here.
- **Draft protocol deviations:**
  - Drift is the publisher's template split, not a time split.
  - The signature controls and supervised reference listed in the draft were not run here; they remain open.

## Reproduce

```
gh workflow run superviz26-sql.yml -f stage=test \
  -f freeze_sha256=b739c5846f913c5e786b105f2038b7f030b72f992d9fb18f64dc77db64dced35 -f develop_run_id=45928319914
```

The test refuses to run if `frozen/test-report.json` exists, or if the code or any model hash differs from the freeze.
