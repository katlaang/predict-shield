# DVWA request-process-network-file correlation detector (2026-11-24)

**Outcome: failed its condition.** The correlated model kept benign alerts under the ceiling but detected 25% of successful attacks. The host signals contributed nothing. The limited representation and the tested model configuration are plausible explanations. Their individual causal contributions have not been independently isolated.

Protocol registered before the development session and before any detector saw attack traffic: `experiment-b/dvwa-correlation/protocol.json`.

| Stage | Run | Result |
|---|---|---|
| Develop (2,000 benign requests) | 45338134980 | freeze `48937585…ba2c` |
| Test (one fresh session) | 45339299220 | `experiment-b/dvwa-correlation/frozen/test-report.json` |

## Setup

- **Target.** DVWA at a pinned commit, security level low, on PHP's built-in server with MariaDB, all on loopback.
- **Telemetry.** strace on the server records the programs it started, the connections it opened and the files it opened. Each call is joined to the request in flight, so one row per request carries what was asked, what ran, where it connected and what it read.
- **Ground truth** comes from the response or a canary listener, never from the trace.
- **Test session.** 1,000 benign requests and 160 attack attempts in four families: SQL injection on the lookup page, command injection (including exfiltration to the canary), local file inclusion, and SQL injection on the login page. 117 attempts succeeded.

## Results

Benign alerts are out of 1,000. Successful attacks are out of 117, failed attempts out of 43.

| Model | Benign alerts | Successful attacks | Command injection | File inclusion | SQLi lookup | SQLi login | Failed attempts |
|---|---|---|---|---|---|---|---|
| **Correlated** | 7 (0.7%) | 29 (24.8%) | 29/30 | 0/30 | 0/30 | 0/27 | 2 |
| Request only | 13 (1.3%) | 56 (47.9%) | 30/30 | 0/30 | 6/30 | 20/27 | 18 |
| Process only | 0 | 0 | 0/30 | | | | 0 |
| Network only | 0 | 0 | 0/30 | | | | 0 |
| File only | 1 | 0 | | 0/30 | | | 0 |
| Any single model | 14 (1.4%) | 56 (47.9%) | 30/30 | 0/30 | 6/30 | 20/27 | 18 |

Checks: benign rate at most 1% **passed**. At least 90% of successful attacks **failed**. At least 75% in each family **failed**.

## What the result shows

- **Host-modality models flagged no successful attacks in this test.** Isolation Forest splits are fitted from observed training features; an unseen category encoded as a feature that is constant in training cannot cause a split on that feature.
  - The "unseen program / endpoint / file" counts were zero on every training row by construction, since the vocabulary came from those same rows. The forest never split on them, so a command injection that started `id` or a file inclusion that opened `/etc/passwd` scored like any benign request.
  - The same holds for counts above the training range. Counts greater than the largest observed training value may follow the same terminal tree paths; this is a model-specific limitation, not a proof that all such counts are indistinguishable.
- **The telemetry itself carried the signal.** Development saw only two programs started, `sh` and `ping`, so every successful command injection started a program outside that vocabulary. File inclusions of system files opened files benign traffic never opened. The `php://filter` variant is the exception: it read a page file that benign traffic also reads. The recorded instrumentation contains potentially useful evidence, but this experiment does not independently establish that a different learned detector would exploit it.
- **This host telemetry did not detect the successful SQL injection cases.** The process, connection and file records of a successful SQL injection match a benign lookup. Request and response evidence is a plausible next source for evaluating those cases.
- **Request features alone over-alert.** They alerted on 18 of 43 failed attempts, and on 1.3% of benign requests (over the ceiling).

## What version 2 must change (stated before any new result)

1. **Score novelty explicitly.** A program, endpoint or file never seen in benign traffic, or a count beyond the benign range, must raise the score directly. Evaluate this explicit novelty feature separately; the original forest was not trained with variation in these particular unseen-category features.
2. **Add response evidence for SQL injection.** For example, rows returned compared with the page's benign range, since host telemetry cannot see it.
3. **Keep the same test design:** a fresh session from new seeds, scored once.
