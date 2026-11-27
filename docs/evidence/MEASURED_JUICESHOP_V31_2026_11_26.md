# Juice Shop v3.1: Cauchy fusion and exact multi-source confirmation (2026-11-26)

**Outcome: inconclusive by the registered rule (20 confirmed attacks, 30 required). The benign check also failed: 56 of 2,257 benign test requests alerted (2.5%), against a 1% ceiling and 0.27% on the development threshold split.**

Protocol registered before any v3.1 session: `experiment-b/juiceshop-v3/protocol_v31.json`. The v3 result (run 45913538168) stands unchanged.

| Stage | Run | Result |
|---|---|---|
| Develop (3,000 benign requests, seed 2026112904) | 45918879749 | freeze `fd5d1b93…0447`; 0.27% Cauchy alerts on the threshold split |
| Test (one fresh session, 40-minute ZAP scan, sqlmap on 3 endpoints) | 45919350931 | `experiment-b/juiceshop-v3/frozen-v31/test-report.json` |

## Results

| Detector (same session) | Benign alerts (of 2,257) | Confirmed attacks caught (of 20) | Scanner and sqlmap requests (of 8,847) |
|---|---|---|---|
| **Cauchy fusion (registered)** | **56 (2.5%)** | **13** | 7,425 |
| Cauchy without the forest | 34 | 13 | 7,521 |
| Fisher fusion (v3) | 59 | 13 | 7,459 |
| Fisher without the forest | 34 | 13 | 7,521 |
| Request novelty alone | 20 | 12 | 7,252 |
| Isolation forest alone | 41 | 3 | 3,029 |

**Confirmed attacks:** 20 from 5 families (the registered minimum is 30 from 2).

| Source | Confirmed |
|---|---|
| Juice Shop challenge tracker | 15 (from 6 challenges solved) |
| sqlmap confirmed payloads | 3 |
| ZAP active-scan alert requests | 2 |

| Family | Caught |
|---|---|
| SQL injection | 5 of 5 |
| Improper Input Validation | 5 of 6 |
| Broken Access Control | 3 of 5 |
| Broken Anti Automation | 0 of 2 |
| Security Misconfiguration | 0 of 2 |

## What the result shows

- **The fusion change made no measurable difference.** On this session Cauchy and Fisher alerted on almost the same requests (7,425 and 7,459) and caught the same 13 confirmed attacks. Requests from attack families seen on DVWA were caught at 95.7%, and unseen families at 71.3%, against 78.8% and 40.0% in the v3 session. Because Fisher did as well here, that gain comes from the new development session and its thresholds, not from the fusion method.
- **Benign alerts rose tenfold from development to test** (0.27% to 2.5%), and the forest drove much of it: removing it cut benign alerts from 56 to 34. Two causes are likely, neither tested: benign requests during an active attack meet application state the attackers changed, and 751 threshold rows are too few to set a 0.5% threshold stably. Thresholds also moved between development sessions (Fisher 25.7 in v3, 16.9 in v3.1).
- **The confirmation sources were thin.** ZAP confirmed 2 requests, sqlmap 3. The challenge tracker supplied most confirmations, and its 50 ms window can match more than one fast scanner request to one solved challenge (6 challenges matched 15 requests), so it overstates the count.

## Conclusion for the detector line

Two registered Juice Shop tests could not reach a conclusive verdict, because automated scanners rarely produce confirmable successful attacks. The second also showed benign alerts that do not hold from development to test. Further Juice Shop iterations under this design are not justified. The next detection test needs independent ground truth by construction (as in Superviz25-SQL or Superviz26-SQL), and benign calibration large and varied enough to hold under attack-time conditions.
