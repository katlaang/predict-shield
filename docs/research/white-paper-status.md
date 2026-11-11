# Research documentation status

The technical framework is described in the [v2.2 implementation specification](PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md). A separate editable white paper draft is maintained outside this repository; it is a working research document, not a peer-reviewed result or validated implementation.

## Research questions

- Can learned action-effectiveness and disruption estimates improve authorized defensive selection over competitive deterministic baselines?
- Can re-verification detect silent access-control regressions efficiently under measured probe costs?
- How does a verifier's assessment differ from a separately established laboratory oracle under incomplete, stale or contradictory evidence?

## Experimental scope

- **Experiment B:** inconsistent effective access control, partial propagation, stale authorization caches and re-verification after regression.
- **Experiment A (planned):** incomplete vulnerability remediation and partially stale deployments.

## Evaluation gates

1. Confirm reproducible source and scenario definitions.
2. Measure actual action outcomes and service health.
3. Keep model features separate from post-action outcomes and experiment truth.
4. Train, calibrate and evaluate on disjoint configuration groups.
5. Compare against strong deterministic and lookup baselines.
6. Report limitations and invite external technical replication when feasible.

No claims of model superiority, cross-environment generalization, or production readiness are made without corresponding measurement and review.
