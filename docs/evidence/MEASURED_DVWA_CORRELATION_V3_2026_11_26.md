# DVWA correlation detector v3: single test session (2026-11-26)

**Outcome: passed its condition.** The fused detector caught 117 of 117 successful attacks and alerted on 5 of 1,000 benign requests.

The protocol was registered before the development session ran and before v3 scored any attack traffic: `experiment-b/dvwa-correlation-v3/protocol.json`.

| Stage | Run | Result |
|---|---|---|
| Develop (3,000 benign requests) | 45883884274 | freeze `7ae09d7d…da97a` |
| Test (one fresh session) | 45884393589 | `experiment-b/dvwa-correlation-v3/frozen/test-report.json` |

## What changed from v2

v2's code showed two causes for its misses:

- **Hand-picked weights.** Novelty and response evidence were added with weights of 0.08 and 0.025, too small to cross the threshold.
- **Site-wide character tracking.** An apostrophe that is normal on the greeting page counted as normal in the id and username fields.

v3 makes two changes:

1. **Per-field request profiles.** For each page and parameter, the detector learns from benign traffic which character classes, lengths and parameter names occur.
2. **Calibrated fusion, with no hand-set weights.** Four evidence scores (request novelty, host novelty, response shift, and the v1 isolation forest) are each turned into a tail probability against a separate benign split. They are combined with Fisher's method, and the threshold is set at 0.5% on a third benign split.

## Results

The test session had 1,000 benign requests and 160 attack attempts. 117 attempts succeeded, judged from responses and the canary, never from the trace.

| Detector | Benign alerts | Successful attacks caught | Failed attempts flagged |
|---|---|---|---|
| **Fused (pass/fail)** | **5 (0.5%; 95% CI 0.2 to 1.2%)** | **117 of 117 (95% CI 96.8 to 100%)** | 43 of 43 |
| Fused without the isolation forest | 0 | 117 of 117 | 43 of 43 |
| Request novelty alone | 0 | 117 of 117 | 43 of 43 |
| Host novelty alone | 0 | 50 of 117 | 0 of 43 |
| Response shift alone | 0 | 28 of 117 | 0 of 43 |
| Isolation forest alone | 4 | 17 of 117 | 3 of 43 |

The fused detector caught every successful attack in all four families: command injection 29 of 29, file inclusion 27 of 27, SQL lookup injection 31 of 31, and SQL login injection 30 of 30.

All three checks passed: benign alerts at most 1%, at least 90% of successful attacks, and at least 75% in each family.

## How to read this result

- **The per-field request profile carries the result.** On its own it caught every successful attack with no benign alerts. Learning what each input field normally contains, from benign traffic only, was the change that mattered.
- **The isolation forest added nothing here.** It caught only 17 of 117 alone, and it contributed 4 of the fused detector's 5 benign alerts. The fusion without it was strictly better on this session. That was measured, not chosen in advance, so the registered fused detector stands as the result.
- **Host and response evidence separate success from attempt.** Request evidence flags every attempt, failed ones included. Host novelty and response shift fired on successful attacks only (0 of 43 failed attempts). They are what can tell an operator an attack worked.
- **Limits:**
  - The four families and their payload strings come from the v1 generator and were seen in v1 and v2. Only the seeds are new, so this is not a test against new attack types.
  - Benign traffic is synthetic and drawn from a fixed set of values, which makes per-field profiles easy to learn. Real user input is far more varied, and false alarms would be higher.
  - This is the fourth detector design on this lab, and the design used what the v1 and v2 failures showed.

## Next step

Measure the same detector, unchanged, on traffic it was not designed around: a different application, or an external dataset with real benign traffic (CAM-LDS is the first candidate). Report the fusion without the forest beside it as a registered comparison.
