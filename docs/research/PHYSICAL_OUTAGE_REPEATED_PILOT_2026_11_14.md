# Repeated physical authority-outage pilot: two four-action batches

**Executed:** 2026-11-14 UTC, GitHub Actions run [43626532168](https://github.com/katlaang/predict-shield/actions/runs/43626532168). The physical runner and accompanying Python/Java/Docker CI passed in [PR #54](https://github.com/katlaang/predict-shield/pull/54), merge `7fbb6c3c4e8b0a69bb0e8f8e50f3f8167be2e005`.

**Observed source commit in the GitHub runner checkout:** `2f8ae743136a112b97146f15c92500adc7ea699b`. This is the code as checked out by the PR-triggered runner. Do not confuse it with the later PR merge commit.

## Actual measured outcomes

Two complete physical batches each replayed `resync_policy`, `restart_enforcer`, `gateway_restrict`, `monitor_only` against the same configured missed Kafka revocation plus physically stopped policy authority. These are **8 executed physical action replays**, not eight independent operating conditions.

| Action | Gateway revoked-access exposure, sampled lower–upper (seconds, sum of both batches) | Protected authorized request failures | Legitimate endpoint failures | Physical intervention observation |
| --- | ---: | ---: | ---: | --- |
| Resync policy | 2.400–2.420 | 0/20 | 0/20 | TRANSPORT_UNAVAILABLE |
| Restart enforcer | 2.274–3.488 | 2/20 | 4/20 | JVM_RESTART_OBSERVED |
| Gateway restriction | 0–0.009 | 16/20 | 0/20 | GATEWAY_RESTRICTION_ACCEPTED |
| Monitor only | 3.590–3.597 | 0/20 | 0/20 | NO_ACTION |

Each authorized/legitimate denominator is 20 actual HTTP requests across both physical batches. Gateway restriction nearly removed observed gateway exposure while disrupting 16 of 20 protected authorized requests. These are **observations in this single laboratory configuration** and not a statistical prediction of future conditions.

The exact per-batch records:

| Batch | Action | Sampled exposure lower–upper (seconds) | Authorized failures | Legitimate failures |
| --- | --- | ---: | ---: | ---: |
| 1 | resync_policy | 1.201–1.217 | 0/10 | 0/10 |
| 1 | restart_enforcer | 1.146–1.753 | 1/10 | 2/10 |
| 1 | gateway_restrict | 0–0.004 | 8/10 | 0/10 |
| 1 | monitor_only | 1.795–1.799 | 0/10 | 0/10 |
| 2 | resync_policy | 1.200–1.203 | 0/10 | 0/10 |
| 2 | restart_enforcer | 1.128–1.735 | 1/10 | 2/10 |
| 2 | gateway_restrict | 0–0.005 | 8/10 | 0/10 |
| 2 | monitor_only | 1.795–1.798 | 0/10 | 0/10 |

All eight action records retained **live policy truth UNKNOWN** and verifier conclusion **INDETERMINATE**. A historical pre-outage SHA-256 witness does not turn a physical outage into independently VERIFIED authoritative truth. The bounded exposure estimate uses monitored gateway HTTP intervals and must not be interpreted as a direct probability of exploitation.

## Traceable experimental evidence

The successful workflow produced two artifacts (available from the [GitHub Actions run](https://github.com/katlaang/predict-shield/actions/runs/43626532168)):

- `physical-repeated-outage-evidence` (artifact ID `14126935605`): full sanitized report, each separately committed four-arm batch record, and checksum manifest.
- `predict-shield-research-demo` (artifact ID `14126376957`): source dashboard HTML and the actual `data/ci-report.json` as a presentation bundle.

SHA-256 integrity values, computed on the downloaded GitHub artifact contents:

```text
ci-repeated-outage.json   a6ee9be5301202bb8043e7c999c8982e5155a4a35bb38435b06c0422fa001246
physical-batch-01.json   e077c3e554dd3b47f68950f95e6a7c2c070a7959aa39cab3c4c06b43370e04a2
physical-batch-02.json   acc84cb58020e0b47d00382b13f5f99b8f814a84accfbee2f7a4593296a550db
```

The sanitized source report is 10,700 bytes. The two action-batch records are 4,131 and 4,136 bytes. These public research records contain witness commitments and aggregated observed counts, **not** raw private oracle policy or lab tokens. Store an independent secure copy because GitHub Actions artifacts may expire.

The PR also passed its Python unit suite, Java 25 / Docker integration, and separate real Kafka regression. The latter includes an existing 40-replay pilot over four fault mechanisms; **it is separate from these eight new authority-outage replays**.

## Scientific interpretation

- **No AI selector was trained, invoked, or evaluated by these batches**. They demonstrate reproducible experimental measurement and action effects, not learned decision superiority.
- **No infrastructure operator participated**. The environment was a disposable Docker lab, not a critical-service production system.
- Repeated trials share one fault configuration. They do not provide independently sampled system conditions, a confidence interval for generalization, or a complete six-family v3.1 feasibility result.
- The new dashboard is read-only and presents measured artifact data; it cannot itself verify the provenance of the laboratory measurements.
- `resync_policy` is physically replayed as an impossible-action mechanism control during a known authority outage. It is **not** a valid eligible deployment comparator under that condition.
- The remaining research milestone is a separately registered and sufficiently powered six-family study, then AI model fitting and held-out decision evaluation; external operator validation must be separately consented and assessed.

**Status:** `EXPLORATORY_MECHANISM_REPEATS_ONLY`. No AI superiority, national infrastructure effectiveness, or independent field validation conclusion is supported by these measurements.
