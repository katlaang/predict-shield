# PREDICT-SHIELD: Evidence-first adaptive defense v2 (no retraining)

**Status:** New implementation under review; synthetic contract and isolated physical measurement must pass before claiming validation.

## Change in engineering objective

**The previous 0/3 physical AI-defense failure was not corrected by training.** In the original registered new-configuration lab experiment, the learned selector chose resynchronization for all three episodes, while independently measured restart resolved all three, at 16–17 failed legitimate requests per episode within the *observed* 25-request allowance. At decision time, restart's predicted error plus calibrated radius exceeded that allowance. This discrepancy highlights unreliable calibration and weak action-effectiveness information, not evidence that safety bounds should be relaxed. [Frozen negative study](../evidence/MEASURED_NEW_CONFIG_AI_DEFENSE_PILOT_2026_11_26.md).

This change is a safety-and-evidence redesign, **not** a newly trained or more accurate model.

## Operator telemetry v2

The disposable Spring/Kafka enforcement instances now expose, through the existing authenticated read-only operator endpoint, the actual local Kafka listener state: `consumer_state_observed`, `consumer_running`, `consumer_paused`, `consumer_pause_requested` and the server timestamp. The collector separately records when it received each response and the node identity.

Previously available fields remain: applied local revision, cache age, refresh failure, handled-event count, pending callbacks and service latency. This is operational information, not the hidden injected fault mode or post-action oracle truth. **It is not a genuine broker offset or Kafka consumer-lag measurement.** The code keeps broker lag explicitly UNKNOWN; any claim that it was measured is rejected.

The new `defense_review_v2.py` reviews actual pre-action evidence. It rejects incomplete, stale, misidentified, contradictory and privileged data, and flags actual paused/non-running listener observations. It distinguishes revision differences as observed indicators, not independent evidence that resynchronization will work.

## Evidence-first decision outcome

The existing AI selection model, calibrated action predictions, typed policy gate, registered action set and disruption budget remain unchanged. **A model recommendation is not permission to claim a fix.** A second veto-only review checks:

1. All four pre-action source identities and timestamps are present and fresh (currently a five-second laboratory bound).
2. All four listener states are actually observed. The oracle and injected fault metadata must be absent from the model's inputs.
3. A separately SHA256-verified evaluation report matches the model fingerprint and reports measured 90%-nominal held-out configuration-group coverage for both security exposure and failed-request disruption. Missing reports or coverage shortfalls fail closed.
4. The selected action's modeled residual-security-exposure upper bound does not exceed the **provisional 0.10 lab acceptance threshold**, and its predicted failed-request upper bound is within the original externally declared action budget.
5. Resynchronization is not presented as a verified repair of an actually paused consumer. Monitor-only is not counted as remediation. Restart remains human-approval-only in the lab executor.

When any check fails, the result includes the original model proposal and exact reason, but sets `selected_action: null`, `abstained: true`, `reason: HUMAN_REVIEW_REQUIRED_EVIDENCE_OR_EFFECTIVENESS`, and `decision_review.status: HUMAN_REVIEW_REQUIRED`. The independent lab action dispatcher rejects any missing or escalated review **before dispatch**. No security-success verdict is assigned without an independent post-action observation.

**Do not interpret a passed lab review as production authorization or a prediction of successful remediation.** The numeric residual upper-bound threshold is a conservative engineering placeholder, not empirically demonstrated to yield 90% reliability.

## Concrete limitations

- This change deliberately makes the old frozen model **ineligible for autonomous lab action** when its held-out security-exposure coverage is only 70%, below its 90% nominal target, or its authentic evaluation report is unavailable. Its ranking remains visible as a proposal. The original negative experiment and model weights are preserved.
- The internal laboratory operator endpoint currently uses a control credential that can also mutate the lab. Least-privilege production telemetry authentication remains pending.
- The lab has evidence of local consumer pause/running state; it still lacks a directly sampled broker consumer-offset/lag time series. Adding that requires an actual authenticated Kafka read-only consumer-group offset observer with explicit timestamp, topic/partition and group scope.
- A paused listener is physical evidence of inability to process new Kafka records while paused; it does not prove every resynchronization action is ineffective, nor that restart is always safe or effective.
- Escalations are neither free successful outcomes nor proof of correct action. Future matched trials must count escalation rate, unjustified escalations, exposure left unresolved, resolution after approved intervention and real disruption.
- The prior 20 configuration groups have already been examined; further tuning on those results cannot be described as confirmatory validation.
- The laboratory v2 contract should be independently validated under source-preserving physical pause/resume testing before asserting any improvement.
- **No AI advantage, lower false-alarm rate, superior remediation, operator pilot or U.S. critical-infrastructure impact is established by this implementation.**

## Next validation phases

Once unit and physical telemetry tests pass: (1) add a read-only authenticated Kafka offset/lag observer; (2) register fault families in which different permitted actions genuinely work, retaining the best expert rule as a baseline; (3) use development-only cases to improve objective/coverage, not a repeated test holdout; (4) evaluate a newly frozen candidate on unseen configurations, measuring **verified resolution under disruption limits**, actual escalation costs and conditional uncertainty coverage; (5) repeat on authorized shadow-mode operator telemetry and obtain independent expert assessment.

**Research owner:** non-detection/adaptive defense stream. Claude's detection experiments and the separate commercial product pilot repository remain untouched.
