# Measured authority outage: action evidence and time-unit integrity

**Status:** Software validation/physical measurement pending CI when first committed. No AI selector is trained in this experiment.

Before any report is interpreted as bounded physical outage utility, the scoring adapter now checks:

1. The registered action arm must match an independently logged action-observation status. Offline `resync_policy` is recorded `TRANSPORT_UNAVAILABLE`; a claimed successful restart without a `JVM_RESTART_OBSERVED` receipt is rejected.
2. Measured time-integrated exposure fractions must correspond to measured exposure *seconds* and the registered monotonic observation window; inconsistent units, zero durations and impossible upper/lower bounds are rejected.
3. Existing rules remain: no full `VERIFIED` during authority outage, four distinct action witnesses, complete four-node target counts, measurable HTTP disruption denominators, and strict interval dominance rather than unsupported winners.

These checks can expose corrupted/incorrect physical reports, but cannot infer true authority state during a stopped authority. The outcome of real physical runs must be recorded separately and may be negative or inconclusive.

The [physical workflow](https://github.com/katlaang/predict-shield/actions/workflows/authority-outage-actions.yml) performs four interventions only on an isolated localhost-bound Docker/Redpanda/Java lab. No public website scanning, real operator impact or production response.
