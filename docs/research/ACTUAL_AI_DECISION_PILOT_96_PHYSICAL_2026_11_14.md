# First trained AI defense-selection result, 96 physical trials

**Study date:** November 14, 2026. **Actual GitHub Actions run:** [43628445648](https://github.com/katlaang/predict-shield/actions/runs/43628445648). **Experimental source revision:** `dc62d3aaec0e1d2cb9537f49eff0168693f19562`. **Pre-registered measured plan SHA-256:** `2e241225369fd72b18e25fa84f461b52e6385451328fce7cb27dc9fe2fdede68`. Implementation PR [#56](https://github.com/katlaang/predict-shield/pull/56), merged with successful Python, Java/Docker, Kafka integration, and dedicated physical AI experiment checks.

## What physically ran

Twenty-four distinct lab operating configurations balanced across four Kafka policy-fault families and three complexity strata. **Twelve** configuration groups trained a real scikit-learn `RandomForestRegressor` action-effect model, **six** selected a deterministic comparator on calibration data alone, and **six** were held out entirely from model fitting and comparator choice. Each configuration physically replayed four actions on the disposable separate-JVM Kafka/Spring/Oracle laboratory.

The physical audit reported **96 complete, 0 partial, 0 invalid, 0 missing and 0 unexpected** four-stream action records. Features were pre-action operator observations plus action identity; no injected hidden fault labels or post-action oracle values were model features.

## Actual held-out result

| Metric | Measured value |
| --- | ---: |
| Trained AI mean hindsight regret | 0.000036245895832583606 |
| Calibration-selected engineering rule mean hindsight regret | 0.00009045383333727841 |
| AI minus rule benefit, regret reduction (rule − AI) | +0.000054207937504694805 |
| Paired configuration bootstrap 95% lower | −0.000045653229165054654 |
| Paired configuration bootstrap 95% upper | +0.00015428095833650937 |
| Always-resync mean hindsight regret | 0.000036245895832583606 |
| Independent held-out configuration groups | 6 |

**Result: EXPLORATORY, AI SUPERIORITY NOT ESTABLISHED.** The AI performed slightly better on the *point estimate* than the deterministic engineering rule selected on calibration. But its paired 95% group-bootstrap interval **crosses zero**, and it **tied the simpler fixed resync policy exactly** on mean held-out regret. Thus no distinctive AI value or generalizable superiority was demonstrated.

### Actual decisions by held-out group

| Group | AI's selected defense | AI regret | Engineering rule regret |
| --- | --- | ---: | ---: |
| mechanism-019 | resync_policy | 0 | 0.00013466400000083922 |
| mechanism-034 | resync_policy | 0 | 0.00008334437499968317 |
| mechanism-057 | resync_policy | 0 | 0.00007988012501414232 |
| mechanism-070 | resync_policy | 0.00011156637499709632 | 0 |
| mechanism-086 | resync_policy | 0 | 0.00024483450000900575 |
| mechanism-097 | resync_policy | 0.00010590899999840530 | 0 |

The AI chose **resync_policy on every held-out configuration**. Under the registered exploratory tolerance `0.001`, both `monitor_only` and `resync_policy` were within the hindsight-optimal set on all six groups. This indicates the tested four-family scenario mix often failed to distinguish consequential defensive decisions; it is not evidence that AI found sophisticated conditional strategies.

Other non-AI means were fixed_gateway 0.2134461857500012, fixed_monitor 0.00009045383333727841, fixed_restart_or_gateway 0.23859576966666632, fixed_resync 0.000036245895832583606, observable_telemetry_rule 0.00009045383333727841, train_tuned_rule 0.00009045383333727841.

## Scientific response and next experiment

1. **Do not change this held-out result** or retrospectively discard configurations where always-resync was competitive.
2. Run the frozen **100 independent-group, 1,200 actual action** original v3 plan in PR [#57](https://github.com/katlaang/predict-shield/pull/57), retaining the full zero/negative outcome if strong baselines remain competitive.
3. Prospectively test a **broader operational fault mix including genuine consumer-paused persistent state**. Only include faults and outcomes that the independent oracle can physically verify. Authority-outage scenarios require explicit UNKNOWN-safe separate interval estimands and cannot be assigned fabricated scalar results.
4. For any future AI superiority claim, report all deterministic comparators, group-level uncertainty, decision diversity, legitimate-user disruption, and physical fault witnesses. Reserve external critical-infrastructure effectiveness for separate independently assessed U.S. operator studies.

No claim of production deployment, U.S. operator field effectiveness, 1,200 completed trials, or EB-2 NIW approval is supported by these 96 observations.
