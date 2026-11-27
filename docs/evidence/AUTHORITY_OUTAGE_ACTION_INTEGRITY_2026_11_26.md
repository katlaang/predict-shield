# Measured authority outage: action evidence and time-unit integrity

**Status:** Validation complete in the disposable laboratory. [GitHub Actions run 45923676494](https://github.com/katlaang/predict-shield/actions/runs/45923676494) passed the fail-closed unit contracts and executed the four physical interventions, independently measured gateway requests and bounded UNKNOWN policy evidence, and performed cleanup. No AI selector is trained or tested in this experiment.

Before any report is interpreted as bounded physical outage utility, the scoring adapter now checks:

1. The registered action arm must match an independently logged action-observation status. Offline `resync_policy` is recorded `TRANSPORT_UNAVAILABLE`; a claimed successful restart without a `JVM_RESTART_OBSERVED` receipt is rejected.
2. Measured time-integrated exposure fractions must correspond to measured exposure *seconds* and the registered monotonic observation window; inconsistent units, zero durations and impossible upper/lower bounds are rejected.
3. Existing rules remain: no full `VERIFIED` during authority outage, four distinct action witnesses, complete four-node target counts, measurable HTTP disruption denominators, and strict interval dominance rather than unsupported winners.

These checks can expose corrupted/incorrect physical reports, but cannot infer true authority state during a stopped authority. The outcome of real physical runs must be recorded separately and may be negative or inconclusive.

The [physical workflow](https://github.com/katlaang/predict-shield/actions/workflows/authority-outage-actions.yml) performs four interventions only on an isolated localhost-bound Docker/Redpanda/Java lab. No public website scanning, real operator impact or production response.

## Verified physical observations (2026-11-27 UTC)

Original GitHub Actions run: [45923676494](https://github.com/katlaang/predict-shield/actions/runs/45923676494). The physical measurement in the runner logged:

| Action | Observed transport/physical action | Observed unauthorized allow fraction lower bound | Upper bound |
| --- | --- | ---: | ---: |
| Resynchronize policy | TRANSPORT_UNAVAILABLE | 0.25 | 0.25 |
| Restart enforcer | JVM_RESTART_OBSERVED | 0.00 | 0.25 |
| Restrict gateway | GATEWAY_RESTRICTION_ACCEPTED | 0.25 | 0.25 |
| Monitor-only | NO_ACTION | 0.25 | 0.25 |

The separately calculated interval diagnostic returned `EXPLORATORY_INTERVALS_ONLY` and `unique_definite_best_action: null`. The policy authority was genuinely offline, so current authority truth was **UNKNOWN** and verifier status **INDETERMINATE** for all actions. The interval result does **not** establish a unique safe best defense, an operational recovery, or superior learned policy.

This is a lab physical feasibility check only. It is **not** a registered four-action stopped-authority AI experiment with independently confirmed full policy truth, and has no U.S. critical-infrastructure field evidence. It also does not justify treating a gateway restriction as a successful global remediation merely because gateway requests were blocked.
