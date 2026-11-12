# Experiment B v3.1: feasibility amendment (PROPOSED, not frozen)

**Status:** draft, prospective amendment (not frozen or authorized for execution), motivated by the successful 40-trial v3 *instrumentation* pilot. This file does not replace `PROTOCOL_V3_AI_EVALUATION.md`. The v3 reference commit and its protocol blob remain untouched. The full v3.1 protocol must be separately frozen before collecting new campaign evidence; no AI effectiveness is claimed.

## Recorded motivation (pre-amendment)

The five-configuration, ten-paired-decision pilot reported the following exploratory **mean primary regret**: always resync 0.025; always monitor 0.029; engineering rule 0.069; telemetry rule 0.069; cross-fitted tuned rule 0.087; always restrict 0.258. Eight of ten hindsight choices were resync or monitor. The pilot contained transient conditions that could resolve within the observation window. These results motivated auditing *recovery semantics* and the ability of the environment to evaluate consequential choices; they are not independent AI results or a power calculation.

## Proposed independent campaign design

- **150 independent configuration groups × 4 actions × 2 repeats = 1,200 physical replays.**
- Freeze group-level **90 train / 30 calibration / 30 held-out test** split, and its exact deterministic seed and membership, before execution.
- Select difficulty stratum and routing profile independently; balance fault families and restart constraints within feasible strata, without implying a population prevalence estimate.
- Retain transient/self-healing cases as negative controls, and add realistic persistent-state faults to probe situations requiring intervention.
- Treat actions as physical interventions; the test harness must never set the recovery result using the intended winning action or privileged evaluator flags.
- Train the learned action-effectiveness estimator only on training groups; tune deterministic rules on the same training groups. Use calibration groups only for calibration/model selection as preregistered, and report the best eligible non-AI comparator.
- Carry forward the original 0.50/0.25/0.25 primary weights, two sensitivity profiles, group-bootstrap CI, 10% threshold, missingness handling, action eligibility, and independent oracle separation unless an explicit revision is separately justified.

## Physical fault and recovery contract, to validate in CI before declaring implemented

| Mechanism | No action | Resync | Local restart | Gateway restrict |
| --- | --- | --- | --- | --- |
| Transient broker delay | May expire/recover | Can accelerate if source reachable | May be unnecessary | Reduces access exposure; may block legitimate protected calls |
| Duplicate events | Can settle if revision/idempotency handling works | Does not repair broken deduplication logic | Does not inherently repair broken deduplication logic | Reduces exposure with collateral cost |
| Two-revision reorder | Outcome depends on actual revision guard | May fetch latest if source reachable | May reload local revision if source reachable | Reduces exposure with collateral cost |
| **Persistent consumer failure** | Must remain impaired until physically repaired | Cannot publish into a stopped/unhealthy consumer | May restore only if restart actually restores consumer health | Reduces exposure; does not repair consumer |
| **Authority outage** | Remains unavailable until external authority restored | Cannot fetch from stopped authority | Cannot restore authority by restarting enforcer | Reduces exposure; does not restore authority |
| Restart-prohibited operation | Fault remains unless another action repairs it | Allowed only if independently safe | **Ineligible** | Eligible only within explicit disruption/scope limits |

Implement fault injection using actual broker consumer pause/crash and stopped authority container with observed readiness and independent verification. The mechanisms must be calibrated and measured, not claimed to work from configuration metadata alone. The table gives *expected causal constraints*, not invented measured outcomes.

## Pilot feasibility gates (predeclared proposal)

Use a distinct, pre-identified exploratory configuration set, **not** the held-out groups used for final scientific inference. Compute each decision's hindsight-optimal *set* of eligible actions using a preregistered cost-tie tolerance of **0.001 normalized utility units**. Count fixed-policy mismatch only when its choice is outside that set. Avoid choosing a fixed policy retrospectively using the pilot itself: determine the comparator from training-only policy selection, or treat the feasibility comparison as descriptive and report its selection method.

1. **Execution integrity:** all four measured action streams complete; no oracle leakage; the physically injected mechanism is observed at both fault injection and independent outcome checks. All denominators and action eligibility are valid.
2. **Decision diversity:** at least **30%** of the exploratory pilot's *configuration-level* decisions have a unique optimal action set excluding the prespecified fixed comparator's selected action. Report counts and exact denominators; this gate is a feasibility heuristic, **not a scientifically validated effect threshold**.
3. **Partial visibility:** at least **two distinct** optimal actions across PARTIAL_VISIBILITY configurations, after resolving ties with the same 0.001 tolerance. Record missing-feed patterns and do not present intentionally hidden fault modes to the selector.
4. **Precision diagnostics:** estimate paired-regret variance and a group-level bootstrap 95% CI width for baseline-minus-model *only once a defined candidate model is available*, using exclusively exploratory/training data. Also estimate uncertainty for paired action-cost differences before training. Report the smallest detectable effect across plausible observed variances. The **10% relative gain** criterion remains the preregistered superiority threshold, but pilot variance alone does not prove or disprove power. If precision is insufficient, prespecify a larger held-out group count or explicitly declare an inconclusive design prior to data collection.
5. **No iterative AI favoring:** if any gate fails, record `FEASIBILITY_INCONCLUSIVE`, report why, and do not resample scenarios or tune the difficulty mix until the AI would appear to win. A later new protocol requires a separate prospective rationale and fresh independent sample.

## Revision boundaries and provenance

- Keep v3 pilot results visible as exploratory evidence, even if unfavorable.
- This amendment was written after inspecting the v3 pilot. It is not retroactive preregistration.
- Add code and test evidence that each new fault is physically present and that resync/restart cannot repair unrelated external failures.
- Before v3.1 campaigning, lock this document, exact plan generator, configuration IDs, split files, baselines, measured-unit definitions and hashes in a separately named freeze commit/tag.
- Do not infer deployment effectiveness, critical infrastructure field validity, or autonomous execution authorization from any synthetic pilot.

## Implementation inventory at current baseline (November 2026)

- The authority outage smoke is implemented with a real Compose service stop/start and passed isolated mechanism CI; it demonstrates HTTP resync unavailability and that local enforcer restart cannot restore the stopped authority.
- The consumer-only Kafka listener pause/resume has been physically checked in CI; it is not the same as the original callback-based event-loss fault.
- `plan_v31.py` produces 150 proposed configuration groups and 1,200 PLANNED_NOT_EXECUTED actions in a new schema, intentionally rejected by the v3 collection runner. Group distribution is six fault families (25 each), three strata (50 each), and 90/30/30 groups.
- `feasibility_v31.py` defines a proposed numeric gate on independently audited *pilot* costs; the secure exporter, v3.1 full runner, feasible-action outcome collection, prospective split-lock and physical mixed-fault pilot still need validation.
- The present v3.1 document **is not a prospective pre-pilot freeze**. The old 40-replay data remain exploratory. No AI model effectiveness claim is supported by these implementation smoke tests.

## Unresolved before final protocol freeze

1. Establish that each fault mode yields genuinely distinguishable physical recovery behavior and that no action can repair an unrelated dependency.
2. Register a separate set of pilot configurations with an immutable manifest, distinct from train/calibration/held-out groups; implement corresponding complete, independently audited four-action runner.
3. Define a feasible baseline for no-restart conditions and secure the cost-to-gate export schema, including exact rounding and ties.
4. Decide whether the group-split 90/30/30 is sufficiently powered using prospective power/precision diagnostics; no power is currently established.
5. Freeze complete runnable code, splits, metric definitions, thresholds and provenance before collecting the final 1,200 evidence trials. Any more revisions require versioned amendments.
