# Registered four-family physical defense development study

**Registration:** before the 20261201 seed's new physical action outcomes. **Evidence classification:** exploratory development, not an independently powered confirmatory test or proof of AI superiority.

## Why this replaces repeated one-configuration tests

The previous small pilots, seeds 20261128/29/30, were each one physical configuration with three action repeats, frequently reusing the index `mechanism-005`. They do not establish independent fault-family generalization. A successful CI workflow is not a successful AI defense. We now evaluate **four distinct registered test configurations**, deliberately spanning:
- persistent Kafka event loss;
- persistent consumer pause;
- self-healing delayed event;
- self-healing loss due to short cache TTL.

Selection is deterministic: generate v3.1 plan with seed `20261201`, choose lexicographically first `test` configuration in each of the four registered family classes. Require four different configuration IDs and exactly 12 planned arms in each. If a class is unavailable under the frozen seed, fail before measurements and document the limitation. Never select a different seed based on observed outcomes.

## Execution

A fresh disposable local Redpanda/Kafka plus four JVM enforcement processes is started in GitHub Actions. One model is fitted to the original historical 60 training groups and calibrated on the original separate 20 calibration groups, **before** generating the new outcomes. The new measured configurations are not passed to training or calibration. The old test partition has already been examined historically and cannot be relabeled confirmatory.

For each selected new configuration, **three repeated episodes × four physical action arms** (monitor, resync, restart, gateway restriction) are separately executed after resets, giving **48 physically executed action arms** and **12 paired episodes across four independent configuration groups**. Each arm records pre-action operator-only v2 observations and gateway probes, actual request failures, direct-target security oracle and independent verification; all records must pass four-stream identity and completeness joins.

## Comparators and locked scoring

All policies receive exactly the same operator-observable pre-action projection from the matching monitor replay. No injected fault identity or post-action outcome is accessible to either AI or expert heuristic. The pre-existing learned policy and original cost weighting are frozen:
`0.50 * verified gateway path exposure + 0.25 * independent oracle exposure + 0.25 * observed failed legitimate requests / declared failure budget`.

The five comparators are:
1. Historical trained AI action selector with grouped disruption radius;
2. Fixed monitor-only;
3. Fixed policy resynchronization;
4. Fixed restart if authorized, otherwise monitor;
5. Fixed gateway restriction;
6. A **transparent engineering heuristic**, explicitly not oracle or expert-certified. Rules defined *before* outcomes: if operator readings are incomplete, abstain; if all gateway probes deny, monitor; if TTL ≤4000ms and pending callbacks exist, monitor; otherwise if restart is authorized and load ≤30 RPS and observed max node latency ≤55ms, restart; otherwise if gateway restriction is eligible and load ≤20 RPS, restrict; else resynchronize. These are predeclared development thresholds, **not** measured safe-authority permissions.

The fixed restart policy is a particularly important strong safety/security comparator. If restart resolves more exposures than AI, report that directly even if composite utility favors AI. Counterfactual laboratory execution of a disallowed action does **not** authorize selecting it. The offline evaluator never executes actions.

## Precommitted reporting and safety

Report per-policy verified security resolutions, failed legitimate request counts, budget breaches, abstentions, per-configuration cost, per-fault-family chosen actions, and any observed deviation. Report the held-out configuration-group model calibration from the frozen historical training report and classify nominal coverage shortfalls as reliability limitations. Do not shift thresholds or retrain based on this new cohort. Fail closed on missing v2 telemetry, incomplete independent oracle truth, missing physical arms, incorrect source revisions or invalid request denominators. Preserve raw negative and invalid evidence as artifacts.

**Primary interpretation is descriptive.** Four independent configurations, only one per fault family, do not support a statistically justified generalized superiority claim. To demonstrate that, a further pre-registered sufficiently powered unseen lab/field campaign, grouped uncertainty assessment, and credible security/disruption noninferiority margins remain necessary.

No third-party targets, production infrastructure, or real credentials are involved.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
