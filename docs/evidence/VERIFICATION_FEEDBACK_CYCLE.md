# Verification feedback cycle: offline adapter

The first integration between the scheduler and scope-aware independent evidence assessment is in `engine/predict_shield/verification_cycle.py`.

## Contract

1. `select_probes` applies the same explicit probe-unit budget to fixed-interval, change-driven and risk/age heuristic schedulers.
2. A scheduled `ProbeRequest` is **not** a successful verification. Independent probe evidence must be collected separately.
3. `record_probe` calls the existing scope-aware `assess` implementation with timestamp, required independent coverage and bounded evidence age.
4. Only `VERIFIED` advances `last_verified_at` and clears the pending change. `NOT VERIFIED`, `INDETERMINATE` and missing evidence never manufacture freshness.
5. The output is an immutable verification record. It contains no private oracle labels.

## Limitations and next stage

This module does **not** execute HTTP probes, authenticate the evidence source, persist records durably, or guarantee atomic consumption of concurrent changes. Callers must authenticate observer identity and bind evidence to the requested scope and observation ID. Before integration with the Java mechanism lab, add probe request IDs, deduplication, durable event history, checks against late/out-of-order responses and a transactionally checked state-version or compare-and-swap update. In particular, a new change arising **after** the probe request must not be cleared by a late successful result.

The scheduler is deterministic. A learned regression model has not been implemented.

## Tests

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
```
