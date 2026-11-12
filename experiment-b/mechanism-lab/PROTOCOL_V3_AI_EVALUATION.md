# Experiment B v3: preregistered AI decision-value evaluation

**Protocol status:** prospective research design, revised before inspecting any scored outcomes from the expanded heterogeneous-node / observable-telemetry pilot. Previously observed 12-trial results were exploratory and are not part of the new held-out evaluation. This document specifies hypotheses and comparisons; it does not report results.

**Code baseline:** PR #9 merged on November 11, 2026. The previous loss/delay/duplicate 12-trial pilot was inspected before this protocol was written. Its results are exploratory and are *not* independent validation of the new protocol.

## Question and falsifiable hypothesis

Does an action-effectiveness estimator trained on **only operationally observable pre-action evidence** reduce exposure, unresolved controls, and legitimate service failures more than robust, prespecified non-AI decision policies?

The primary null is that AI selection does not improve paired configuration-level hindsight regret compared with the strongest prespecified feasible non-AI comparator. The AI must be allowed to tie or lose; experiments will not be edited after examining held-out outcomes to manufacture a model win.

## Experiment and difficulty strata

The fixed-sized campaign retains **100 independent configuration groups**, **four measured action replays**, **three repetitions**, and **60 train / 20 calibration / 20 held-out test configurations**. Group identity, not individual action replay, determines the split. Fault mechanism is balanced across difficulty strata to avoid learning a trivial fault-generator index.

The following strata are preregistered **before their pilot results are reviewed**:

1. **SIMPLE:** four independent enforcement JVMs with uniform 15 ms handler latency, actual gateway routing and policy-event faults, with operator evidence available. This tests whether a rule already matches AI under uncomplicated conditions. Routing and restart constraints are varied separately in registered configurations, not necessarily fixed to balanced or unrestricted.
2. **INTERACTION:** measured and configured per-process JVM legitimate-request latency, gateway traffic share, TTL, requested load and Kafka event propagation interact. Node latencies vary by configuration and actually delay the HTTP handler. JVM restart recovery time is measured as a separate secondary outcome but its distribution is **not independently controlled**. No true fault label is available to the predictor.
3. **PARTIAL_VISIBILITY:** the heterogeneous setup plus a deliberately suppressed operator telemetry feed from a registered process, potentially omitted gateway routes, and independently registered restart/change-freeze constraints. The current fixture implements missingness, not a calibrated sensor-noise distribution. Missingness is never imputed as safety or a known fault identity.

Difficulty is a *label describing planned conditions*, not a target-dependent classification assigned after observing which policy won. Any unavailable capability is recorded as not implemented, rather than simulated as if measured.

A separate subsequent **SHIFT** experiment may change fault mix or load after model training. It needs a new locked protocol, independent prospective dates and evaluation split; there is no online adaptation claim in v3.

## Allowed model inputs, observed before action

- Configured TTL, intended load and gateway routing/traffic shares
- Measured gateway allow/deny/unknown rates and actual configured traffic routing profile before action
- Authenticated operator-facing, read-only policy revision gaps or stale-cached update age, actual refresh-failure flags and event handling indicators if implemented, **without exposing injected fault mode, fault target, oracle ground truth or post-action results**
- Permitted candidate action and predeclared change/restart constraints
- Missingness indicator for any unavailable telemetry

No true injected loss/delay/duplicate/reorder label, private oracle administrative answer, scheduled post-action outcome, simulated "best action" or test-set labels may be model inputs. A lag-like revision gap is **not** a direct Kafka consumer-lag measurement and must not be labeled as one.

## Measurements and policy eligibility

- **Path exposure:** integral of time-stamped live gateway allows divided by the observation window, with missing/error periods included in an explicitly reported worst-case upper bound.
- **Control remediation:** separately observed complete direct enforcement-point access from the private oracle.
- **Service disruption:** actual *absolute* non-200 legitimate HTTP requests, including authorized users of the same protected operation blocked by a coarse gateway restriction. Response latency and restart recovery time are measured **secondary outcomes**, not components of the preregistered primary utility. Service latency may affect real timeout/failure counts, but no distinct restart-latency contribution is asserted.
- **Lab disruption cost allowance:** a predeclared *absolute failed-request count* (current experimental comparator: 25 requests per observation window). It is **not** an established remaining production service error budget.
- **Eligibility:** never choose restart when the preregistered change-freeze constraint prohibits it. Evaluate actual replay outcomes for every arm solely inside this isolated disposable lab; prohibited actions are excluded from policy selection and hindsight feasible optimum.

## Prespecified comparisons

Model: trained action-outcome predictor with group-split calibration and conservative missingness/OOD abstention, scored on held-out configurations only.

Non-AI policies: fixed resync, fixed restart with safe fallback, fixed gateway restriction, fixed monitoring, a simple engineering threshold, and a stronger *observable-information* deterministic heuristic using revision gaps, pre-action gateway allows, TTL, load and available change permissions. **An additional strong non-AI comparator uses a fixed, finite 216-option threshold grid fitted on training groups only**, freezes its parameters before test evaluation, and never accesses held-out outcomes for fitting. The privileged ground-truth fault lookup is a diagnostic upper reference only and never a fair operational baseline.

Primary outcome: **paired held-out mean hindsight decision regret** relative to the lowest cost among eligible actions, at the configuration-group level. Scores are assessed only once after training/calibration choices are frozen. Secondary outcomes: optimal-action match rate, exposure-seconds, absolute errors, scope-verification error, abstention, model calibration interval coverage, worst-case excess cost and stratified regret by difficulty.

Primary preregistered weights: (path exposure, unresolved control, normalized absolute failed requests) = **(0.50, 0.25, 0.25)**. Sensitivity profiles, not selected by test outcome: **(0.70, 0.20, 0.10)** and **(0.30, 0.20, 0.50)**.

No win is claimed merely for lower MAE. Compare AI against the **best** prespecified eligible non-AI baseline; report ties and worse results explicitly. To support a positive claim, the group-cluster bootstrap 95% confidence interval for baseline-minus-model regret must exclude zero and the reduction must be at least 10% relative to that baseline where baseline regret is positive. Report absolute differences and uncertainty where relative percentages are unstable. This is a research threshold, not an assertion of statistical power or guaranteed improvement.

**The crossover curve is a hypothesis:** report measured regret separately at SIMPLE, INTERACTION, PARTIAL_VISIBILITY whether or not the rule and model diverge. Do not change definitions to favor the model.

## Small-pilot gate before 1,200 replays

Perform at least two paired repeats of four actions on each deliberately chosen exploratory condition covering loss, delay, duplicate, true two-revision reorder, a restart-prohibited exposure condition and every difficulty stratum. Current expanded pilot: **5 configurations × 2 repeats × 4 actions = 40 measured replays**, distinct from the full 1,200 registered trials. Inspect time-integrated exposure sampling, per-target traffic weights, startup timings, operator telemetry missingness and budget exceedances. This pilot is for instrumentation/feasibility, **not held-out AI efficacy**.

Freeze the next complete-campaign protocol and commit its SHA before collection. The campaign may proceed only if every fault family is actually exercised, every observation has valid denominators, timestamped pre-action signals are clearly separated from oracle outcomes and no experimental label is supplied to model selection.

## Provenance and limitations

Every measurement must carry the exact Git commit and registered-plan fingerprint. This four-JVM fixture is not a U.S. critical infrastructure deployment. Gateway and Docker inventory evidence is limited to the declared testbed. A read-only operator telemetry endpoint is distinct from a private oracle, but still reported by the system being tested. No model-selected autonomous corrective action is approved by this protocol.

**No scientific result is asserted by this document.**
## Recorded implementation limits before evaluation

A synthetic `X-Lab-Principal: authorized` marker represents authorized users of the same protected operation. It is NOT an authenticated identity protocol. Exactly one quarter of intended legitimate requests target this protected operation; consequently, coarse gateway restriction must now incur collateral legitimate failures. This fraction is a preregistered workload assumption to be varied only in a separately declared future sensitivity experiment.

The primary research utility does not assign a separate penalty to latency. Report measured HTTP p95 latency and actual restart readiness as secondary outcomes, and do not claim independently manipulated cold-start distributions or genuine hardware capacity variability. The pre-action model may see only operator-visible per-node configured latency indicators and observable cache signals. Injected fault settings remain private evaluation metadata.

The model is not required or expected to win. Threshold tuning occurs on the training partition alone. No five-configuration exploratory pilot supplies enough independent groups for a defensible fitted-rule generalization claim; evaluate that comparator only when the registered 60 training configurations are collected, without using pilot or test outcomes to select thresholds.
