# Mechanism lab: scored campaign result (2026-11-21)

- **Run:** CI run 44879497946, on `master` at `4f154d3`.
- **Lock hash:** `9422667f129b2da8d1d121387f2f8dc0a2b0f40777d6f4b7c635bf39243f973b`. This is the lock `52c22efe…` (tag `mechanism-prereg-v1` on `0b17715`) plus deviation 1.
- **Plan:** v3.1, fingerprint `a246dea5…`. It has 100 configurations, 4 actions each, repeated 3 times, for 1,200 trials.
- **Reports:** in `docs/evidence/mechanism-scored-campaign/run-44879497946/`.
- **Full per-trial records:** kept as the run artifact `mechanism-scored-records`, held for 90 days.

Every number below comes from the locked analysis code (`outcome_report.py` and
`verifier_scoring.py`) and no other analysis. The label is the oracle's
post-action reading: a separate process reads cache state directly and probes
each enforcer directly. The verifier never reads it.

## Integrity

| Check | Result |
|---|---|
| Lock check before the run | passed with the expected hash |
| Controls on this code before the first trial | all 10 cells confirmed; 8 of 8 no-fault runs healthy |
| Trials complete | 1,200 of 1,200; none missing, partial or invalid |
| Reruns / exclusions | 0 / 0 (stopping rule not reached) |
| Source revisions in the records | 1 |
| Split | train 720, calibration 240, test 240 |

The controls repeated the earlier results:

- **Lasting faults** (loss and paused listener, TTL 10 s and 30 s): all 16 runs were still exposed at 6 s. Access was denied once the cache entry expired, after about 9.0 s and 29.0 s.
- **Self-healing faults:** all 16 runs healed within the window.
  - Loss at TTL 2.5 s and 4 s: about 2.05 s and 3.06 s.
  - Delay of 2 s and 3 s: about 1.03 s and 2.04 s, measured from the first oracle read. The delay timer starts when the revocation is published during setup, about 1 s before that first read.

## Q1. Which action leaves every revoked access denied?

The tables below count trials. Intervals are Wilson 95%. In the "Configurations" column, a configuration counts as fixed when most of its repeats were fixed. The configuration is the primary unit, because repeats share a seed.

### Lasting faults (70 configurations, 210 trials per action)

| Action | Trials fixed | Configurations fixed |
|---|---|---|
| restart_enforcer | 210 of 210 (98.2 to 100%) | 70 of 70 (94.8 to 100%) |
| resync_policy | 0 of 210 (0 to 1.8%) | 0 of 70 (0 to 5.2%) |
| gateway_restrict | 0 of 210 | 0 of 70 |
| monitor_only | 0 of 210 | 0 of 70 |

The same pattern held for loss and for the paused listener separately: 105 of 105 trials with restart, 0 of 105 with each other action.

The plan forbids restarts in 48 of the 100 configurations
(`restart_permitted: false`, a policy flag; every action is still run so that
its outcome can be measured). These include 34 of the 70 lasting-fault
configurations. In those 34, **no permitted action fixed the fault** within
the window: the only fix was the forbidden one. This is a null result for
resync and gateway restriction on these fault modes.

### Self-healing faults (30 configurations, 90 trials per action)

All four actions ended with access denied in 90 of 90 trials and 30 of 30
configurations. Each configuration's Wilson interval is 88.6 to 100%. Here the
action adds nothing to the outcome, so only its cost matters.

## Q2. Exposure and failed legitimate requests

The 4 s measurement window began when the action was applied, under load.
"Exposure" is the time the gateway let a revoked request through. The upper
bound also counts time when the gateway's answer was unknown.

| Fault class | Action | Exposure, lower to upper (mean s) | Failed legitimate requests (mean) |
|---|---|---|---|
| lasting | restart_enforcer | 0.38 to 0.87 | 17.6 |
| lasting | resync_policy | 0.83 | 0.0 |
| lasting | gateway_restrict | 0.25 | 25.5 |
| lasting | monitor_only | 0.90 | 0.0 |
| self-healing | restart_enforcer | 0.30 to 0.70 | 16.7 |
| self-healing | resync_policy | 0.32 | 0.0 |
| self-healing | gateway_restrict | 0.21 to 0.22 | 27.0 |
| self-healing | monitor_only | 0.33 | 0.0 |

Read these exposure figures with three limits:

- **The figures are sampled at the gateway.** They do not measure the exposure the oracle sees. The faulty enforcer is chosen at random, and in half the configurations the gateway does not route to the hidden enforcer. So the gateway can show little exposure while the oracle reports access still open.
  - Example: with monitor_only on a lasting fault, the oracle reported exposure at the end of all 210 trials, yet the gateway saw only 0.90 s of the 4 s.
- **The gap between lower and upper bounds comes from the restart.** Gateway probes fail while an enforcer restarts, and that time counts as unknown.
- **gateway_restrict blocked legitimate traffic.** It cut gateway exposure, but it also exceeded the 25-request disruption budget in 105 of 210 lasting-fault trials and 48 of 90 self-healing trials. It never fixed the fault itself.

## Q3. Verifier accuracy against the oracle

All 1,200 trials. Post-action operator telemetry was available in 1,009.

| Verdict | Correctly verified | Correctly not verified | Wrongly verified | Wrongly not verified | Abstained |
|---|---|---|---|---|---|
| Gateway scope only | 173 | 334 | **0** | 0 | 693 (57.8%) |
| Scope plus telemetry | 122 | 334 | **0** | 0 | 744 (62.0%) |

"Wrongly verified" means the verifier said fixed while the oracle reported access still exposed.

When the verifier gave an answer, every answer was correct.

- **Specificity** (it reports NOT VERIFIED when access is truly exposed): 334 of 334, Wilson lower bound 98.9%.
- **Sensitivity** (it reports VERIFIED when access is truly denied): 173 of 173 for the scope verdict (lower bound 97.8%) and 122 of 122 for the dual verdict (lower bound 96.9%).

The cost of that accuracy is abstention.

- **Scope verdict:** abstained on 693 trials, 397 of them where access was truly denied. Every one of these abstentions was "scope indeterminate". `scope.py` returns that verdict when the gateway's inventory differs from Compose's (half the configurations leave the hidden enforcer out of the gateway) or when the probes do not reach every route. The reason for each trial is in the records artifact.
- **Dual-evidence rule:** caught no error the scope verdict missed, because the scope verdict had none to catch. It moved 51 correct VERIFIED answers into abstention, all of them cases where operator telemetry was unavailable. In this campaign the second kind of evidence added abstentions and no protection.
- **Delay faults:** every delay trial ended with access truly denied. The scope verdict abstained on 130 of 180 and the dual verdict on 153 of 180.

## Cost comparison (preregistered matrix)

The weights were:

| Error | Weight |
|---|---|
| Unnecessary action | 1 |
| Late fix | 5 |
| Disruption | 5 |
| Abstention | 2 |
| Missed fix | 1, 5 or 20, depending on the ratio |

Under the robustness rule, a finding is robust only if it holds at all three ratios.

| Fault class | 1:1 | 1:5 | 1:20 | Robust? |
|---|---|---|---|---|
| lasting (both modes) | monitor_only and resync_policy tie (1.41) | restart_enforcer (3.13) | restart_enforcer (3.13) | no |
| lasting, loss | resync_policy (1.48) | restart_enforcer (3.67) | restart_enforcer (3.67) | no |
| lasting, paused listener | monitor_only (1.32) | restart_enforcer (2.60) | restart_enforcer (2.60) | no |
| self-healing (both modes, and each mode separately) | monitor_only (1.71) | monitor_only | monitor_only | **yes** |

- **Self-healing faults:** doing nothing had the lowest cost at every ratio. It was the robust finding.
- **Lasting faults:** restart_enforcer was cheapest once a missed fix cost at least five times an unnecessary action. When a missed fix cost the same as an unnecessary action, restart's disruption, late-fix and abstention costs outweighed it. The finding is therefore stated only for 1:5 and 1:20.
- **Late fixes:** restart's late-fix count (31 of 210 on lasting faults) is driven by the unknown time during restart, not by exposure the oracle observed. Under the preregistered rule it still counts as a late fix.

## Q4. Estimator calibration

Not reported. No calibration analysis was locked before the scored results
existed, and deviation 1 covered Q1 to Q3 only. Calibration code written now
would have to be recorded in `DEVIATIONS.md` as written after results were
seen.

## What this result does and does not show

**It shows:**

- In this lab, a restart is the only one of the four actions that clears a lasting stale-cache fault within the window.
- On self-healing faults, doing nothing costs least.
- The gateway verifier made no false VERIFIED in 1,200 trials, and abstained on more than half of them.

**It does not show:**

- Behaviour beyond the four-enforcer Compose lab.
- Behaviour under the fault classes the preregistration lists as unobservable here.
- Any comparison with a learned model.

Repeats within a configuration share a seed, so the trial-level intervals overstate precision. Use the configuration-level figures.
