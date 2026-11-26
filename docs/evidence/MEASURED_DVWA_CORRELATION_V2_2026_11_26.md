# DVWA learned correlation v2: first frozen follow-up (2026-11-26)

**Outcome: FAILED its preregistered detection target.** This document records run [45881347517](https://github.com/katlaang/predict-shield/actions/runs/45881347517), first-scored head `4f6d9e2c70f9ce1e74eeb730afe8b006d9ff1551`, and original frozen model `b26755182533b82f009afba5b1fccbded60c3649c4d6e85649fd9eea686e2304`. The [first-scored artifact](https://github.com/katlaang/predict-shield/actions/runs/45881347517/artifacts/15147900824) contains the freeze and recorded report; the compact report is committed in `experiment-b/dvwa-correlation-v2/reports/first-scored-run-45881347517.json`.

The experiment developed an Isolation Forest on 1,400 benign-only DVWA requests: 979 fit rows, 421 held-out benign calibration rows, and 2 calibration alerts. The model adds explicit novel executables, endpoints and files, and learned response-structure deviation. The test was a separately seeded local DVWA session with 500 benign requests, 120 attack attempts and 92 attacks independently confirmed successful.

| Measure | First-scored result | Registered limit |
|---|---:|---:|
| Benign request alert rate | 3/500 = **0.6%** | At most 1%: passed |
| Successful attack detection | 35/92 = **38.04%** | At least 90%: failed |
| Command injection | 26/26 | Family floor 75%: passed |
| File inclusion | 6/22 | Family floor 75%: failed |
| SQL injection (lookup) | 3/22 | Family floor 75%: failed |
| SQL injection (login) | 0/22 | Family floor 75%: failed |

The workflow completed successfully because it recorded a scientifically negative result. **No success or AI superiority is claimed.** DVWA v1 scored 29/117 = 24.8% on a different session; those two figures cannot support a paired superiority claim. The attack families were known from previous versions and the entire environment is a disposable local lab, not a real operator or critical-infrastructure site.

After this first test, code review found that repeated invocation should reject an existing output file before any live experiment, and that a separate cross-stream prototype omitted missing primary measurements. Both are follow-up correctness fixes, **not** new held-out results. A rerun using the same fixed test seeds is exploratory and must not be reported as an independent replication.

## Pending scientific work

- Test a revised model on *newly registered* session and attack families.
- Add an external host/network dataset and independently audited attack timelines; preserve UNKNOWN for unconfirmed records.
- Compare matched decisions with explicit rule and learned-feature ablations, confidence intervals, and false-alarm denominators.
- Establish production-scale and independent critical-infrastructure validation before deployment claims.
