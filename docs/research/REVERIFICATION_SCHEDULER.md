# Continuous re-verification: deterministic scheduler baselines

Research pre-alpha, November 2026. This is a scheduler of proposed **independent verification requests**, not an executor, autonomous defense controller, or trained AI regression detector.

## Current policies

- `fixed`: fixed age threshold since the last completed independent verification.
- `change`: a recorded change after the last completed verification.
- `adaptive`: transparent risk-and-age heuristic plus fixed/change triggers.

All policies receive the same integer probe-unit budget and input subjects. The scheduler refuses future timestamps, invalid risk values, negative budgets, and duplicate subjects. It never accesses oracle outcomes or marks a request as VERIFIED. A future execution component must reconcile observed result, scope, provenance, incomplete coverage and failure.

## Run unit tests

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
```

## Next evaluation, before AI claims

Create synthetic, physically injected silent-regression histories separate from pre-action telemetry. Predefine interval, sensor noise/missingness, observation windows, the verification probe-unit cost, an equal fixed budget, and censored detection delays. Compare policies on time-to-detection, missed regressions, false triggers, probe utilization and service-disruption effects. Do not label future regression data as available to scheduling. Split histories by independent scenario group rather than probe event. Only after deterministic baselines pass evaluation should an AI risk-of-regression model be trained, calibrated and compared.

This capability is currently **not wired to the Java lab**; no live probes are executed.
