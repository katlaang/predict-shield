# Exploratory paired defense decision analysis (2026-11-26)

**Evidence classification: RETROSPECTIVE EXPLORATORY. Not a prospective confirmation of AI superiority. No new physical mitigation was executed in this analysis.**

## Provenance

- Source data: the previously executed 1,200-trial, four-action physical Compose/Kafka experiment, run [44879497946](https://github.com/katlaang/predict-shield/actions/runs/44879497946), with four independent streams (pre-action, verification, operations, and oracle).
- Downloaded historical evidence artifact: `mechanism-scored-records`, GitHub artifact ID `14701694880`, ZIP digest `sha256:08a8bb16ba3b50447510c15194acbb6a4c41534062c3fcf1aead626a9a7431e3`. Source record provenance was checked by `train.load_executed_dataset`; model was trained locally in the runner, not loaded from an external pickle.
- Scoring run: [45920476469](https://github.com/katlaang/predict-shield/actions/runs/45920476469), `Paired adaptive-defense research evaluation tests`, conclusion **success**.
- Derived aggregate artifacts: `historical-paired-defense-comparison`, artifact ID `15163873503`, ZIP digest `sha256:207adffb3715d555c5776e6564b629b29b415adf072540c847aa489e79142e18` (GitHub retention through 2026-12-27).
- Source code: `experiment-b/mechanism-lab/paired_defense_eval.py`, `train.py`, `action_utility.py`; tests `test_paired_defense_eval.py`. The `train.py` import list was corrected to admit the already-registered `consumer_paused` physical fault from the locked v3.1 protocol, without allowing injected fault labels into the model.

## Evaluation method

The archived 100 configurations remained split by configuration: 60 training, 20 calibration, 20 held-out test. There were three replays per configuration, all four action arms measured in the original physical campaign. The learned regression bundle was refitted on the prior training records and calibrated on the prior calibration partition. **This is not a fresh independent test**, because the 20 historical test configurations and broad results had already been examined during framework development.

At decision time, every policy received the same operator-observable pre-action projection, taken from the matching `monitor_only` replay. The chooser had no direct access to the hidden fault identity, post-action verification or independent oracle labels. Policy-allowed actions were `resync_policy`, `gateway_restrict`, `monitor_only`, and `restart_enforcer` only when explicitly permitted. A learned policy must abstain outside its training feature bounds. Its predicted failed-request count plus a grouped calibration radius must not exceed the declared disruption allowance for a mutating action. Abstention or forbidden action recommendations are explicitly counted and evaluated as nonmutating `monitor_only` fallback, **not as a free or guaranteed safe resolution**. The actual executor and production authority are not invoked.

The fixed utility weighting, from existing `action_utility.py`, is:

```
cost = 0.50 * observed_path_exposure_fraction
     + 0.25 * observed_security_exposure_indicator
     + 0.25 * observed_failed_legitimate_requests / declared_failure_allowance
```

Lower cost is better, but **the weight choices affect the ranking**. The hindsight-best eligible action is used only for computing regret after a decision, never for the model's choice.

## Results: historical test configurations only

All values were printed by [run 45920476469](https://github.com/katlaang/predict-shield/actions/runs/45920476469), scored on **20 configuration groups and 60 paired replay episodes**.

| Policy | Mean configuration cost | Mean regret to hindsight-best eligible | Episodes with oracle-verified resolved security exposure | Failed legitimate requests | Measured disruption-budget breaches | Selector abstentions / prohibited recommendations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Learned selector | **0.26764** | **0.05251** | **28/60** | 94 | 0 | 0 / 0 |
| Fixed monitor-only | 0.30915 | 0.09402 | 12/60 | 0 | 0 | 0 / 0 |
| Fixed resynchronization | 0.31166 | 0.09653 | 12/60 | 0 | 0 | 0 / 0 |
| Fixed restart if permitted, otherwise monitor | 0.29750 | 0.08237 | **45/60** | **700** | **7** | 0 / 0 |

**Interpretation:** Under this lab utility and historical replay, the learned selector had a lower mean cost than the three fixed comparators. It caused fewer observed request failures and no measured disruption-budget breaches, compared with the restart-if-permitted policy. **It also selected fewer actions that resolved security exposure: 28/60 compared with restart's 45/60.** Therefore this is a measurable security/disruption trade-off, not blanket defensive superiority or proof of improved resilience.

No paired confidence interval, preregistered minimum effect, or statistical significance test was established in this analysis. Repeats in a configuration share conditions, so treating all 60 episodes as independent would overstate precision.

## Exact limitations

1. This study is **retrospective**, after the old campaign and its findings were already available. It must not be relabeled as a new prospective or independently unseen-configuration confirmation. The 20 originally held-out groups have been consumed for development.
2. The AI policy's predicted mean and calibration intervals do not guarantee real production safety under distribution shift. The experimental impact gate is not the system's independent runtime authorization mechanism.
3. The four action outcomes are separately executed **matched lab replays**, not simultaneously observed counterfactual field outcomes. The policy receives the canonical pre-action view from the monitor arm.
4. The utility is weight-sensitive. Report direct security success and disruption metrics beside any composite cost.
5. The result is limited to a four-enforcer disposable Kafka/Compose authorization lab. It does not cover live broadband, electric utility, transportation, health or other infrastructure sites.
6. A zero counted policy violation in an offline chooser is not proof of an operationally safe automated executor. Real authority outages still require separate independent evidence, as tracked in [issue #36](https://github.com/katlaang/predict-shield/issues/36).
7. The CI aggregate artifact expires; this permanent report keeps the limited measured summary and original run references, but is not an archival substitute for independently held raw evidence.

## Next prospective experiment

Pre-register a new model, utility, safety stopping rules, fixed baselines, non-overlapping fault configurations and test conditions **before** generating and seeing results. Compare paired selected-action cost and direct security-success outcomes with grouped uncertainty and disruption noninferiority, and separately execute bounded physical actions with a truly independent oracle. Preserve a negative or inconclusive result. Do not claim critical-infrastructure effectiveness without operator authorization and independent assessor evidence.

**Final status: lower historical composite cost observed; AI defense-selection superiority and U.S. critical-infrastructure effectiveness remain unproven.**
