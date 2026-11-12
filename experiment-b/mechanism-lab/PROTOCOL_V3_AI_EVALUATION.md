# Experiment B v3: preregistered AI decision-value evaluation

**Protocol status:** prospective research design, before the new heterogeneous-node / observable-telemetry pilot. This document specifies hypotheses and comparisons; it does not report results.

**Code baseline:** PR #9 merged on November 11, 2026. The previous loss/delay/duplicate 12-trial pilot was inspected before this protocol was written. Its results are exploratory and are *not* independent validation of the new protocol.

## Question and falsifiable hypothesis

Does an action-effectiveness estimator trained on **only operationally observable pre-action evidence** reduce exposure, unresolved controls, and legitimate service failures more than robust, prespecified non-AI decision policies?

The primary null is that AI selection does not improve paired configuration-level hindsight regret compared with the strongest prespecified feasible non-AI comparator. The AI must be allowed to tie or lose; experiments will not be edited after examining held-out outcomes to manufacture a model win.

## Experiment and difficulty strata

The fixed-sized campaign retains **100 independent configuration groups**, **four measured action replays**, **three repetitions**, and **60 train / 20 calibration / 20 held-out test configurations**. Group identity, not individual action replay, determines the split. Fault mechanism is balanced across difficulty strata to avoid learning a trivial fault-generator index.

The following strata are preregistered **before their pilot results are reviewed**:

1. **SIMPLE:** four healthy but independent enforcer JVMs, gateway routing with balanced weights, fixed node capacity defaults, no change freeze, and measured timing/load; this tests whether rules and AI tie on easy conditions.
2. **INTERACTION:** heterogeneous gateway traffic shares, distinct measured JVM cold-start times and legitimate service response latencies, TTL, requested load and Kafka event propagation interact. No true fault label is available to the predictor.
3. **PARTIAL_VISIBILITY:** the heterogeneous setup plus a restricted observability view, possibly missing gateway targets, noisy/incomplete operator-visible evidence, and an independent restart/change-freeze constraint. Missingness is not imputed as safety or a known fault type.

Difficulty is a *label describing planned conditions*, not a target-dependent classification assigned after observing which policy won. Any unavailable capability is recorded as not implemented, rather than simulated as if measured.

A separate subsequent **SHIFT** experiment may change fault mix or load after model training. It needs a new locked protocol, independent prospective dates and evaluation split; there is no online adaptation claim in v3.

## Allowed model inputs, observed before action

- Configured TTL, intended load and gateway routing/traffic shares
- Measured gateway allow/deny/unknown rates, route identity, and latency over a pre-action sampling interval
- Authenticated operator-facing, read-only policy revision gaps or stale-cached update age, actual refresh-failure flags and event handling indicators if implemented, **without exposing injected fault mode, fault target, oracle ground truth or post-action results**
- Permitted candidate action and predeclared change/restart constraints
- Missingness indicator for any unavailable telemetry

No true injected loss/delay/duplicate/reorder label, private oracle administrative answer, scheduled post-action outcome, simulated "best action" or test-set labels may be model inputs. A lag-like revision gap is **not** a direct Kafka consumer-lag measurement and must not be labeled as one.

## Measurements and policy eligibility

- **Path exposure:** integral of time-stamped live gateway allows divided by the observation window, with missing/error periods included in an explicitly reported worst-case upper bound.
- **Control remediation:** separately observed complete direct enforcement-point access from the private oracle.
- **Service disruption:** actual *absolute* non-200 legitimate HTTP requests and latency under concurrent traffic, reported alongside the observed denominator and real restart/recovery time.
- **Lab disruption cost allowance:** a predeclared *absolute failed-request count* (current experimental comparator: 25 requests per observation window). It is **not** an established remaining production service error budget.
- **Eligibility:** never choose restart when the preregistered change-freeze constraint prohibits it. Evaluate actual replay outcomes for every arm solely inside this isolated disposable lab; prohibited actions are excluded from policy selection and hindsight feasible optimum.

## Prespecified comparisons

Model: trained action-outcome predictor with group-split calibration and conservative missingness/OOD abstention, scored on held-out configurations only.

Non-AI policies: fixed resync, fixed restart with safe fallback, fixed gateway restriction, fixed monitoring, a simple engineering threshold, and a stronger *observable-information* deterministic heuristic using revision gaps, pre-action gateway allows, TTL, load and available change permissions. The privileged ground-truth fault lookup is a diagnostic upper reference only and never a fair operational baseline.

Primary outcome: **paired held-out mean hindsight decision regret** relative to the lowest cost among eligible actions, at the configuration-group level. Scores are assessed only once after training/calibration choices are frozen. Secondary outcomes: optimal-action match rate, exposure-seconds, absolute errors, scope-verification error, abstention, model calibration interval coverage, worst-case excess cost and stratified regret by difficulty.

Primary preregistered weights: (path exposure, unresolved control, normalized absolute failed requests) = **(0.50, 0.25, 0.25)**. Sensitivity profiles, not selected by test outcome: **(0.70, 0.20, 0.10)** and **(0.30, 0.20, 0.50)**.

No win is claimed merely for lower MAE. Compare AI against the **best** prespecified eligible non-AI baseline; report ties and worse results explicitly. To support a positive claim, the group-cluster bootstrap 95% confidence interval for baseline-minus-model regret must exclude zero and the reduction must be at least 10% relative to that baseline where baseline regret is positive. Report absolute differences and uncertainty where relative percentages are unstable. This is a research threshold, not an assertion of statistical power or guaranteed improvement.

**The crossover curve is a hypothesis:** report measured regret separately at SIMPLE, INTERACTION, PARTIAL_VISIBILITY whether or not the rule and model diverge. Do not change definitions to favor the model.

## Small-pilot gate before 1,200 replays

Perform at least two paired repeats of four actions on each deliberately chosen exploratory condition covering loss, delay, true two-revision reorder and a restart-prohibited exposure condition. Inspect time-integrated exposure sampling, per-target traffic weights, startup timings, operator telemetry missingness and budget exceedances. This pilot is for instrumentation/feasibility, **not held-out AI efficacy**.

Freeze the next complete-campaign protocol and commit its SHA before collection. The campaign may proceed only if every fault family is actually exercised, every observation has valid denominators, timestamped pre-action signals are clearly separated from oracle outcomes and no experimental label is supplied to model selection.

## Provenance and limitations

Every measurement must carry the exact Git commit and registered-plan fingerprint. This four-JVM fixture is not a U.S. critical infrastructure deployment. Gateway and Docker inventory evidence is limited to the declared testbed. A read-only operator telemetry endpoint is distinct from a private oracle, but still reported by the system being tested. No model-selected autonomous corrective action is approved by this protocol.

**No scientific result is asserted by this document.**