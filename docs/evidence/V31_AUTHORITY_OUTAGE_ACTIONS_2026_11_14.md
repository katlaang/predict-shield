# First four-action physical authority-outage observations (November 14, 2026)

**Status:** exploratory physical mechanism evidence, **not** a validated decision-utility campaign and not an AI selector evaluation.

## Provenance

- Implementation PR: [#44](https://github.com/katlaang/predict-shield/pull/44) (under review when recorded).
- [Physical GitHub Actions run](https://github.com/katlaang/predict-shield/actions/runs/43606223372), job `132481324127`.
- Upstream prerequisite [PR #43](https://github.com/katlaang/predict-shield/pull/43) provided the pre-outage independent live policy witness and conservative UNKNOWN semantics; merged as `9b2df5cf3079384d1a7988dc4d30aff0e6dd8e9b`.
- The physical lab uses four separate Java enforcers, Kafka, a policy authority, a gateway and an independently deployed oracle. Each of the four interventions follows a fresh revocation event missed by `enforcer-b`, witnesses the policy while authority is online, physically stops authority and observes HTTP outcomes.

## Actual independent direct-node observations

| Physical action | Observed allowed fraction lower | Upper | Transport / action observation |
| --- | ---: | ---: | --- |
| `resync_policy` | 0.25 | 0.25 | `TRANSPORT_UNAVAILABLE` |
| `restart_enforcer` | 0.00 | 0.25 | `JVM_RESTART_OBSERVED` |
| `gateway_restrict` | 0.25 | 0.25 | `GATEWAY_RESTRICTION_ACCEPTED` |
| `monitor_only` | 0.25 | 0.25 | `NO_ACTION` |

These fractions are **counts of observed direct-node allow decisions divided by four registered nodes**, with missing or stale-trial observations contributing only to the **upper** bound. They are **not probabilities of exploitation, risk reduction, time-integrated exposure or final decision scores**. Gateway restrictions do not necessarily change direct-node state, and restarting one enforcer does not restore the independent authority.

Every intervention's authoritative policy status remains `UNKNOWN` and verification status `INDETERMINATE`. The pre-outage witnessed desired revision is historical information, not a live authority reading. The experiment did not infer success from a resync/restart acknowledgement, and it made no selection using AI.

## What the result does not establish

This study covers one physical condition with four interventions and no preregistered group-level repeats. It cannot prove the model predicts best actions. Authorized-user HTTP status samples were collected but are not an independently validated continuous disruption cost.

## Next scientific gates

1. Freeze and audit the exact outage action-observation schema, witnessing chronology and full source commit.
2. Observe continuous actual exposure and authorized-identity disruption across full action windows; define how UNKNOWN bounds enter primary utility before viewing final held-out outcomes.
3. Compare only eligible actions under identical probe budgets and independently drawn registered configurations, with real authority-down behavior retained.

See [issue #36](https://github.com/katlaang/predict-shield/issues/36). Public logs contain only sanitized experimental results; raw oracle details must not be included in published artifacts.
