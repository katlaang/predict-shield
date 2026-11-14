# Observed v3.1 physical consumer-pause smoke (November 14, 2026)

**Status:** CI-validated, exploratory *single physical condition*, not a five-group feasibility result, model comparison, independent validation or production deployment.

## Reproducibility

- Implementation: PR #33, merged at `3827349b8e8a32b6d58c89ec5d5b286fc6fa4f7f`
- Actual physical GitHub Actions run: **43598777032**, job **132458845854**
- Original PR head: `7738e9044ff662cd60cc5edf8a66993bfd230969`
- Mechanism: actual Spring Kafka listener `enforcer-b` paused *before* revocation event; HTTP process remains healthy
- Configuration: TTL 30,000 ms, 25 requested RPS, 5-second action observation, PARTIAL_VISIBILITY, balanced routing, hidden enforcement included
- Action cost formula: 0.50 × time-integrated upper path exposure + 0.25 × unresolved-control indicator + 0.25 × absolute observed failed legitimate requests / 25
- Four distinct action replays, without an independent configuration-level replication or trained model.

## Actual CI measurements

| Physical action | Measured primary cost, lower is better | External verification status |
| --- | ---: | --- |
| `restart_enforcer` | **0.321988** | VERIFIED |
| `monitor_only` | 0.345757 | NOT VERIFIED |
| `resync_policy` | 0.349388 | NOT VERIFIED |
| `gateway_restrict` | 0.538891 | INDETERMINATE |

These values are rounded to six decimal places **for this display only**, as printed by the GitHub Actions log. The raw sanitized report retains more precision. The physical smoke asserts that resync must not repair a physically paused consumer. Restart was the lowest-cost action in this one condition. Gateway restriction incurred real disruption and cannot be treated as a free safety action.

The status VERIFIED comes from this isolated laboratory's scope-reconciled verifier; it does **not** certify a real critical-infrastructure deployment. The experimental oracle remains a separate measurement process, and no oracle labels were passed to an AI selector. The sole physical condition was inspected before the subsequent independent multi-group exploratory pilot, which uses different configurations.

**Interpretive restrictions:** one decision group cannot support a confidence interval for mean decision value. Do not infer that restart usually wins, that AI predicts the best action, or that the 30% v3.1 group-diversity gate has passed. The planned 150 × 4 × 2 study still requires a truthful authority-outage outcome collector and a frozen six-family protocol.

## Source

[GitHub Actions run](https://github.com/katlaang/predict-shield/actions/runs/43598777032) and [PR #33](https://github.com/katlaang/predict-shield/pull/33).
