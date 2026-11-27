# AI-versus-fixed defense action selection: prospective plan

**Status: NOT YET RUN.** Existing [1,200 trial campaign](../evidence/MEASURED_MECHANISM_LAB_SCORED_CAMPAIGN_2026_11_21.md) measures action outcomes, not AI selector superiority. The previous outcomes may be used as development data, never as fresh confirmation of a model developed from them.

## Hypothesis
Given the **same authenticated pre-action observations**, can a learned action selector choose a safer/more useful permitted defense than fixed policies, without additional false verification or production-style disruptions?

## Structure
- Freeze a new disjoint set of lab fault configurations / deployments for confirmation. Split by **configuration/fault episode**, not individual repeated trials. Development scenarios and final test scenarios must not share hidden state or seeds.
- Each configuration has matched action outcomes for `restart_enforcer`, `resync_policy`, `gateway_restrict`, and `monitor_only` where permitted. Independent checker knows post-action state and legitimate traffic; decision models see **only** pre-action evidence.
- Baselines: monitor-only, static priority rule, least-disruption policy, fixed known-safe policy, simple supervised cost predictor and an AI learned selector. Pre-register training data and uncertainty/abstention behavior.
- Hard constraints: prohibited actions remain ineligible; no future oracle, privileged witness or verification outcome enters selection. No automatic network changes beyond disposable lab.
- Measure normalized risk/exposure, failed legitimate requests, service availability, constraint violations, abstentions, late fixes, real verifier VERIFIED/NOT VERIFIED/INDETERMINATE, and return on permitted actions.
- Report paired per-configuration regret, mean and distribution, stratified fault class, bootstrap by configuration with enough independent configurations, not by repeats. Register safety stop rules and negative outcomes before test.

## Blocking realism
[Issue #36](https://github.com/katlaang/predict-shield/issues/36): authority outage outcomes remain INDETERMINATE when live authority cannot be observed. [Issue #132](https://github.com/katlaang/predict-shield/issues/132): cold restart of authority loses in-memory revision. An outage must not be counted as a successful physical recovery until those independent checks are resolved.

## Decision
Do not claim learned-defense superiority unless the preregistered paired primary endpoint and noninferiority safety gates pass. Negative/equivocal results remain in the permanent report.
