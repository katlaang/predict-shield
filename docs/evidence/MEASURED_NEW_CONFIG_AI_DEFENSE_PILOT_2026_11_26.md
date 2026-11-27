# New disjoint physical defense configuration: unsuccessful learned selector (2026-11-26 local / 2026-11-27 UTC)

**Outcome: laboratory pilot completed; AI did not outperform fixed restart. This is a small negative result, not a statistical demonstration of AI inferiority or field failure.**

## Registered protocol and independent evidence

- Protocol registered before this new configuration was tested: [PROSPECTIVE_SMALL_PILOT_V1.md](../../experiment-b/mechanism-lab/PROSPECTIVE_SMALL_PILOT_V1.md), with fixed plan `create_plan(version="v3.1", seed=20261127)`, selecting the first test-partition configuration by ascending index.
- [GitHub Actions run 45922944490](https://github.com/katlaang/predict-shield/actions/runs/45922944490), source commit `07912950076315dd13bb49fa53824135ab941e87`, conclusion **success**. The plan and model were frozen before fresh physical measurements.
- Existing training source: historical 1,200-trial action campaign run 44879497946, with its 60 training / 20 calibration groups; this new configuration was not in that campaign's data. Historical library and model settings were held fixed for this run.
- Executed 4 physically distinct actions × 3 repeats for **one new configuration** (12 action trials). Each had a separately collected pre-action stream, operations, verification and independent oracle post-action observation. Execution was only in the isolated four-JVM Kafka/Compose lab, not at a real operator.
- The report/metadata artifact **new-config-physical-defense-pilot-report**, GitHub artifact ID 15165297763, ZIP SHA-256 `fb76117394fefef6240582ce7aa6ed931639e05a2b19ad59828b8fb64e769733` (expires February 25, 2027 UTC).
- The disposable laboratory four-stream artifact **new-config-disposable-lab-physical-streams**, GitHub artifact ID 15165432379, ZIP SHA-256 `fb26478bfcd1c88de2dfc15fb10943428ad9806b260b8ddbddbd179e3bcc05fd` (shorter retention, expires December 4, 2026 UTC).
- All tests and runner assertions passed, including the exact 12 complete physical replays, no unexpected or partial records, fixed-model evaluation, and explicit `prospective_superiority_established=false`.

## Measured outcomes

All numbers were printed from the unmodified new physical study report in [run 45922944490](https://github.com/katlaang/predict-shield/actions/runs/45922944490).

| Decision policy | Mean cost (lower better) | Replays with independently measured residual exposure resolved | Failed legitimate HTTP requests | Measured disruption-budget breaches |
| --- | ---: | ---: | ---: | ---: |
| **Learned selector** | **0.40784** | **0 / 3** | 0 | 0 |
| Fixed restart if permitted | **0.27005** | **3 / 3** | 50 | 0 |
| Fixed resynchronization | 0.40784 | 0 / 3 | 0 | 0 |
| Fixed monitor-only | 0.42614 | 0 / 3 | 0 | 0 |

The baseline `restart_if_allowed` had **lower measured weighted cost and resolved every repeated episode**, although it caused 50 legitimate HTTP request failures across those episodes. The AI recommended less disruptive choices but failed to resolve the residual security exposure in all three episodes.

The score uses the existing utility weights: 0.50 for observed gateway-path exposure, 0.25 for independently measured residual security exposure and 0.25 for failed legitimate requests divided by the predeclared allowed-failure budget. The weights were **not** chosen to favor either policy after viewing the new data.

## Meaning and next scientific step

- This result **does not establish consistent AI decision superiority** and adds a fresh negative example to the earlier historical trade-off.
- It contains only **one distinct configuration group** with three repeated episodes. A group-level confidence interval or broad claim of inferiority is not supported.
- The learned model was trained on the previous campaign, with the fault families and physical lab design shared. Different seeds/configuration settings do not establish new attack types or generalization to a different infrastructure provider.
- Investigation hypothesis: the learned selector may over-penalize predicted restart disruption and underweight exposure removal. **That is a hypothesis, not a verified cause.** Any change to policy weights, model features, safety upper-bound or action thresholds must be made on development data and evaluated on a newly held-out configuration cohort. Do not tune on this failed pilot and call it confirmation.
- A safety gate that abstains or prefers low disruption is not proof of effective remediation. Future primary endpoint must include direct security exposure resolution **and** the disruption budget, not only the composite score.
- The same physical laboratory may be useful for internal engineering, but field effectiveness requires independent U.S. operator authorization, real asset inventory and third-party verification.

**Current status:** New physical evidence is recorded and negative for learned-versus-fixed restart in this configuration. A larger prospective configuration-group evaluation, cross-fault robustness and real-world benefit remain unproven.
