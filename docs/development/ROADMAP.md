# Engineering roadmap

This roadmap tracks software deliverables only. Entries marked “implemented” mean that corresponding source exists in the repository, not that its effectiveness has been externally demonstrated.

| Workstream | Status | Next acceptance gate |
| --- | --- | --- |
| Evidence-assessment engine | Implemented, pre-alpha | Exercise independent Compose/runtime-gateway inventory reconciliation under complete and omitted targets |
| Policy-constrained action screening | Implemented, pre-alpha | Establish verified remaining error budgets and approved execution permissions |
| Experiment B authorization-drift lab | Implemented and Kafka/Docker tested | Validate trial-scoped broker events, non-dominated candidate actions and multi-revision reordering |
| Seeded 100 × 4 × 3 plan | Implemented | Execute all permitted lab trials and retain valid, separated measurement records |
| Experiment B data collection | Implemented, limited | Audit diverse 12-trial pilot before expanding to the full registered campaign |
| Supervised action-outcome training | Code implemented; trained evaluation not verified | Fit and compare models on actual full-scope run data, use disjoint configuration splits |
| Regression detection model | Planned | Collect time-to-regression labels, define censoring, compare under measured probe budgets |
| Contextual threat intelligence | Planned | Integrate dated source data with defensible temporally valid labels |
| Experiment A partial remediation | Planned | Introduce controlled remediation failure and independently observe running state |
| Independent validation | Planned | Reproduce published protocol outside original development environment |

## Scientific reporting rules

Keep predictions, verifier assessments, fixture oracle truth and operational measurements distinct. Any results must state the exact scenario, sample size, denominator, exclusions, versioned inputs, calibration method, competing baseline, and limitations. Report unfavorable findings as well as improvements.

See the [Experiment B guide](../../experiment-b/README.md) and [v2.2 specification](../research/PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md).
