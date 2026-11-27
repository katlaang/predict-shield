# Measured physical defense comparison: seed 20261130

**Status:** exploratory one-configuration physical lab result, not AI superiority.

## Source and experimental integrity

- Completed [GitHub Actions run 45943075475](https://github.com/katlaang/predict-shield/actions/runs/45943075475). Physical experiment and offline four-stream scoring completed successfully.
- Registered source seed: `20261130`. Selected configuration: `mechanism-005`, three repeated episodes and four physical action arms per episode (12 actual laboratory measurements).
- Recorded physical collector revision: `12f57a6fc2ddca5e0568c4d9597defe8ca4dddf4`.
- [Aggregate GitHub artifact 15173224681](https://github.com/katlaang/predict-shield/actions/runs/45943075475), physical raw-record artifact ID `15173259665`.
- Downloaded physical raw ZIP SHA-256: `88c6480d307ecde5c12ffafc64de65ff5c6125e8fababdde4953609d2c32f646`.
- The four observed operator telemetry responses were accepted under `operator_pre_action_v2`. Zero AI abstentions were reported. The model was frozen before new physical measurements; the learned policy's selection remained offline, evaluated using outcomes from separately executed action arms. The evaluation did not dispatch the chosen AI action.

## Actual measurements

| Policy | Verified security resolution | Legitimate failed requests | Disruption-budget breaches | Mean configuration composite cost |
|---|---:|---:|---:|---:|
| Learned selector | 3/3 | 0 | 0 | 0.000559516 |
| Monitor-only | 0/3 | 0 | 0 | 0.250629585 |
| Resync policy | 0/3 | 0 | 0 | 0.250686876 |
| Restart-if-authorized | 3/3 | 0 | 0 | 0.000559516 |

The learned selector chose `restart_enforcer` in all three episodes. It **matched the strong restart baseline** and cannot be described as superior to that baseline.

The configuration was a persistent Kafka event-loss fault targeting `enforcer-hidden` with 10,634 ms cache TTL and requested load of 30 RPS. That context is **post-hoc experimental metadata**; the model did not receive the fault identity as an input.

## Critical limits

- Only one independently configured setup is represented. Three within-configuration repeats cannot establish generalization or statistical superiority.
- `mechanism-005` is an index reused by multiple plan seeds, including the prior 20261129 cohort; it is **not** a globally unique independent deployment ID. The seed must always accompany it.
- Historical training report attached to the same run records held-out grouped 90% nominal interval coverage of **70%** for security exposure, **60%** for gateway path exposure and **90%** for failed legitimate requests. The security/path interval shortfalls remain unresolved and do not certify operational decision reliability.
- The temporary GitHub artifact is not a permanent raw-data archive. Keep the original SHA-256 and run reference; independently retain raw evidence before retention expiry.
- The experiment neither tested authentic independent critical infrastructure operators nor dispatched a production model action.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
