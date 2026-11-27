# Superviz25-SQL: baselines beside the frozen detector (2026-11-26)

**Result: the frozen benign-only detector caught more attacks than OWASP CRS at every comparable false-alarm level, and matched a supervised classifier that saw attack labels.**

The comparison plan was registered before any baseline ran (`experiment-b/superviz25-sql/protocol_baselines.json`). The registered pass/fail test (run 45895391129) is unchanged; the frozen model was only re-scored.

Every detector ran on one fixed sample: 302,430 benign and 84,294 attack queries (seed 2026112901).

| Detector | Benign alerts | Attacks caught |
|---|---|---|
| **Frozen v3-method detector** (benign-only) | 0.1% / 0.5% / 1% | **90.3% / 91.6% / 92.3%** (AUC 0.973) |
| Supervised reference (sees attack labels, campaign-grouped folds) | 0.1% / 0.5% / 1% | 91.1% / 91.9% / 92.6% (AUC 0.990) |
| libinjection 1.1.6 | 0% | 65.8% |
| OWASP CRS, paranoia level 1 | 0.08% | 84.8% |
| OWASP CRS, paranoia level 2 | 5.5% | 91.2% |
| OWASP CRS, paranoia level 3 | 11.4% | 91.9% |
| OWASP CRS, paranoia level 4 | 72.8% | 99.7% |

At about 0.1% benign alerts, the frozen detector caught 90.3% against CRS level 1's 84.8%. To match its 91.6%, CRS needed level 2 and alerted on 5.5% of benign queries, eleven times as many. At level 4, CRS blocked every multi-word benign probe tested ("Vieques Airport", "MX 950.0", "Fort Cavazos").

## Runs

| Run | Status |
|---|---|
| 45906319077 | CRS figures void: client headers made CRS block everything at levels 3 and 4. Other detectors valid. |
| 45911603634 | Stopped at level 4 by the harness check; reproduced levels 1 and 2 exactly. |
| **45913812903** | Valid. Report: `experiment-b/superviz25-sql/reports/baselines-rerun.json`. CRS image digest recorded. |

## Limits

- Benign queries are template-generated; CRS's false alarms on real input would differ.
- CRS judged a single URL-encoded GET parameter carrying the user input, not the original application's requests.
- Thresholds for the continuous detectors were set on the sample's own benign scores (the same oracle for all of them).
