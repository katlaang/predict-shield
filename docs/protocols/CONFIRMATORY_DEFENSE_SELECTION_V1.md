# Confirmatory test of AI defense selection (v1)

**Status: REGISTERED PLAN, NOT RUN.** This turns the prospective plan in [AI_DEFENSE_DECISION_EVALUATION.md](AI_DEFENSE_DECISION_EVALUATION.md) into a single confirmatory test with fixed endpoints, comparators, sample-size rule and analysis. Inputs come from the [four-family exploratory run](../evidence/MEASURED_FOUR_FAMILY_PHYSICAL_AI_DEFENSE_2026_11_27.md); none of its configurations are reused here.

## Question

Given the same pre-action operator observations, does the frozen learned selector resolve security exposures at least as often as a sensible fixed expert rule, while causing fewer failed legitimate requests?

## What is frozen before any confirmatory outcome

- **Model:** SHA-256 `87208240dbea19b34c4a5ac067639ac9cdb484b2de8f1985dbbcd143d4fe3b39`, trained on the original 60 historical groups and calibrated on the original 20. No retraining, threshold change or feature change during this study. Any change makes a new version and a new registration.
- **Telemetry:** the v2 operator schema with fail-closed admission (PR #193). A failed live preflight voids the run before any action.
- **Code:** the evaluation code is committed and its hash recorded before the pilot stage runs.

## Policies compared

All policies see only the operator-observable pre-action projection.

1. **AI** (primary): the frozen selector, unchanged.
2. **AI with escalation gate** (secondary): if the selector's chosen action is monitor-only or resync, and the pre-action observations match the persistent-fault signature below, the output becomes `escalate`. The rule is fixed here and not tuned.
3. **Expert ladder E** (primary comparator). Rules fixed here:
   - If operator readings are incomplete, escalate.
   - If TTL is at most 4,000 ms and pending callbacks exist (self-healing signature), monitor.
   - Otherwise, if restart is authorized, restart.
   - Otherwise, escalate.
4. Restart if authorized, otherwise monitor (the previous strong baseline).
5. Monitor-only.
6. Resync.
7. The transparent heuristic of the four-family protocol, unchanged.
8. **Per-configuration best authorized action** (an upper bound, not a competitor). It shows how much room there is to improve.

**Persistent-fault signature** (used by policy 2): the self-healing signature is absent, and at least one gateway probe still admits a revoked principal.

## Endpoints

The unit of analysis is the **configuration**; the three episodes within a configuration are repeats, not independent samples.

- **Primary, H1 (security non-inferiority).** An episode succeeds when all of these hold:
  - the independent oracle verifies the exposure is resolved;
  - failed legitimate requests stay within the declared budget;
  - no unauthorized action was selected.

  A configuration's score is its share of successful episodes. H1 holds if the one-sided 95% lower bound of mean(AI − E) across configurations is above **−0.10**, using a bootstrap over configurations with 10,000 resamples and seed 2026112701.
- **Secondary, H2 (disruption superiority).** This is tested only if H1 holds: fewer failed legitimate requests per configuration for AI than for E, by a one-sided Wilcoxon signed-rank test at α = 0.05.
- **Escalation scoring.** Escalating is scored as correct only when no authorized action resolved the exposure in that configuration's executed arms. Escalating when an authorized action would have resolved it counts as a failure, so escalation is never a free pass. Neither case counts as a resolution under H1. Correct and wrong escalations are reported separately for policies 2 and 3.
- **Not an endpoint:** composite cost. It is reported for continuity with earlier runs, but its weights are a modelling choice, so it cannot decide the result.

## Configurations

- **Families:**
  - persistent loss;
  - persistent consumer pause;
  - self-healing delay;
  - self-healing short-TTL loss;
  - withheld publication, where resync is the uniquely effective action ([DEV_WITHHELD_PUBLICATION_FAULT.md](DEV_WITHHELD_PUBLICATION_FAULT.md)).

  Each family is crossed with restart authorized or not authorized.
- **Exclusions:** every configuration ID and parameter set used under seeds 20261128 to 20261201 is excluded. Every confirmatory configuration must differ in at least one fault parameter from all excluded ones.
- **Seed:** taken from the first 8 hex digits of the commit that registers this file, read as an integer. Nobody can choose it after seeing outcomes. If a stratum cannot be filled under that seed, the run fails before measurement; no seed is swapped in.
- **Arms:** each configuration runs 3 episodes × 4 physical arms (monitor, resync, restart, gateway restriction), with resets between arms. Arms run even where an action is unauthorized, so the oracle is complete; unauthorized arms are never eligible choices.

## Sample size (pilot, then fixed)

1. **Pilot:** 16 new configurations, one per stratum plus 6 more spread evenly. These estimate the discordance rate between AI and E at configuration level. Pilot configurations are excluded from the confirmatory set and reported separately as development data.
2. **Confirmatory size:** N = ceil(6.18 × d / 0.01), where d is the upper 80% bound of the pilot discordance rate. The constant 6.18 is (1.645 + 0.842)², for one-sided α = 0.05, 80% power and a 0.10 margin. N is bounded to [40, 150] and recorded in a committed file before any confirmatory arm runs. For example, d = 0.2 gives N = 124. If N exceeds 150, the study cannot reach the margin at this lab's capacity, and the run is reported as underpowered rather than shrunk.
3. **Strata:** N is spread evenly over the 10 strata (5 families × 2 authorization states), rounded up.

## Execution rules

- The test runs once. A run that fails telemetry preflight, oracle completeness, the four-stream join or a source-revision check is void. A void run is kept with its reason, and a new run uses the next registered seed (registration commit digits 9 to 16). Never rerun because the outcome was unwelcome.
- Selectors are evaluated offline against the executed arms. No selector drives the live executor in this study.
- **Calibration:** report the held-out coverage of the frozen model's security intervals. If security-interval coverage on the confirmatory configurations is below 80% against a nominal 90%, say so with the result. This does not change the pass rule.
- Fully disposable lab only. No third-party targets, production systems or real credentials.

## Report

- **Configuration level:** per-configuration tables for every policy.
- **Primary result:** H1 and H2 with their bounds and p-values.
- **Breakdowns:** results by family and by authorization state; escalation correctness; how far each policy falls short of the best authorized action (regret); calibration.
- **Pilot:** pilot results in a separate section.

**Allowed claims:**

| Outcome | Claim |
|---|---|
| H1 and H2 pass | The AI is non-inferior to an expert rule on security and causes less disruption, in this lab |
| H1 passes, H2 fails | The AI matches an expert rule |
| H1 fails | The AI is not shown non-inferior to an expert rule |

Field or critical-infrastructure effectiveness is out of scope in every case.

## Owner

The defense-selection workstream runs this test. This file only registers the design.
