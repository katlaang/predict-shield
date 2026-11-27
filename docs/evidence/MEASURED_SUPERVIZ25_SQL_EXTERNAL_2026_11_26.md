# DVWA v3 method on Superviz25-SQL: external test (2026-11-26)

**Outcome: passed its condition, by narrow margins.** The detection method developed on our DVWA lab was learned from this dataset's benign training queries only, then tested once. It caught 91.6% of 336,281 sqlmap attack queries and alerted on 0.53% of 3,017,390 benign queries.

This is the first PREDICT-SHIELD detection result on data generated outside this project:

- **Dataset:** Superviz25-SQL v2, from Télécom Paris, LAAS-CNRS and Inria (Zenodo record 17086037, MIT license). The file was pinned by the publisher's MD5 and by our SHA-256.
- **Labels:** by construction. Attacks come from sqlmap campaigns; benign queries come from 65 query templates filled with legitimate values.
- **Protocol:** registered before any model was fitted or any test row was read (`experiment-b/superviz25-sql/protocol.json`).

| Stage | Run | Result |
|---|---|---|
| Structure check (training split only) | 45894476872 | 335,306 / 3,017,390 / 336,281 rows, as published |
| Develop (training split, benign only) | 45894824541 | freeze `e3423d8b…d8aa` |
| Test (publisher's test split, once) | 45895391129 | `experiment-b/superviz25-sql/frozen/test-report.json` |

## Method carried over

`char_class`, `tail_p` and `fused` are imported unchanged from the DVWA v3 code. The "field" is the query template, and its value is the user input. There are two evidence scores:

- **Input novelty:** character classes or lengths never seen for that template in benign training.
- **Learned anomaly:** an isolation forest over character counts, length, token count and template.

Each score is turned into a tail probability against benign calibration data, and the two are fused with Fisher's method. The threshold was set at 0.5% on held-out benign training queries. No setting was tuned on this dataset.

## Results

| | Benign alerts | Attack queries caught |
|---|---|---|
| **Fused (pass/fail)** | **15,881 of 3,017,390 (0.53%)** | **308,190 of 336,281 (91.6%)** |
| Input novelty alone | 3,222 (0.11%) | 89.7% |
| Isolation forest alone | 16,088 (0.53%) | 73.9% |

Checks:

- Benign alerts at most 1%: **passed** (0.53%).
- At least 90% of attacks caught: **passed** (91.6%; 95% CI 91.6 to 91.7%).
- At least 75% for every sqlmap technique: **passed**. Time-based was the closest, at 75.5%.

| By technique | Caught | | By stage or outcome | Caught |
|---|---|---|---|---|
| boolean | 97.4% | | exploitation stage | **100% (161,178 of 161,178)** |
| insider | 100% | | reconnaissance stage | 84.0% |
| inline | 90.0% | | successful campaigns | 93.2% |
| error | 86.2% | | failed campaigns | 86.5% |
| union | 85.3% | | | |
| stacked | 79.5% | | | |
| time | 75.5% | | | |

The weakest tamper script was `commentbeforeparentheses`, at 72.1%.

## How to read this result

- **Every exploitation query was caught.** All misses were reconnaissance probes, where sqlmap tests whether an input is injectable. Some probes look like ordinary values for the field.
- **Fusion mattered here.** Input novelty alone fell just short of 90% (89.7%). Combining it with the isolation forest lifted detection to 91.6%, at the cost of more benign alerts (0.11% to 0.53%). On DVWA the forest added nothing. Here it did.
- **The margins are narrow.** 91.6% against a 90% bar, and 75.5% against 75% for time-based attacks. A modest shift in data could flip either check.
- **Limits:**
  - The benign queries are synthetic. Training and test come from the same 65 templates and value pools, so benign test traffic matches training closely, and real user input would cause more false alarms.
  - At 0.53%, 3 million benign queries still produce about 15,900 alerts. Volume matters as much as rate.
  - The data is SQL queries and user inputs only, so this tests the input-field part of the method, not the server-side or response signals.
  - The attacks are sqlmap only.
