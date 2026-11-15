# PREDICT-SHIELD: Train the decision model, not another subsystem

This **training-only development** milestone directly addresses the negative original model-vs-strong-rule outcome. No new security products, CVE scanners, network adapters or execution engines are created.

## Original real measurements

The actual 1,200-action physical Java/Kafka lab campaign was [GitHub Actions run 43629488209](https://github.com/katlaang/predict-shield/actions/runs/43629488209), archived in five independently audited physical shards, with 60 train, 20 calibration and 20 originally held-out configuration groups, three action repetitions and four action alternatives per group.

The old Random Forest model had mean hindsight regret **0.003291850218750362** on the original held-out groups, compared with **0.0027853271145825884** for its calibration-locked strongest non-AI baseline, **monitor-only**. Paired relative 95% bootstrap interval was **[-0.4991502881745712, 0.06508234279024212]**, including zero and an AI deficit. **No prior AI superiority was established.** The existing full-v3 protocol and its measured results remain unchanged.

## What we actually changed

Instead of training four regressors on separate outcome components and summing their noisy estimates, `paired_action_value_training.py` learns the **direct difference in measured security/disruption cost between each eligible intervention and monitor-only**, using the same independently configured physical fault and repetition.

Only the **pre-action operator telemetry** of a common monitor-side reference is used in every counterfactual candidate prediction. Injected fault identity, target, private oracle observations and post-action outcomes are excluded from model inputs. Outcomes derive from the archived real physical replays and the existing declared research utility:

`0.50 × time-integrated upper-bound exposure + 0.25 × unresolved authorization exposure + 0.25 × (actual failed legitimate requests / declared allowance)`.

The development model uses **HistGradientBoostingRegressor**, frozen settings `max_iter=120`, `max_leaf_nodes=10`, `learning_rate=0.05`, `l2_regularization=1`, `random_state=221`. Intervention requires predicted benefit over monitor-only exceeding **0.01 research utility units**; otherwise it abstains to monitor. Restart is excluded whenever independent change policy forbids it. None of these settings creates operational action permission or a production-calibrated risk estimate.

Five-fold, whole-configuration cross-validation uses only the 60 historical train groups. The model is then fit on those 60 groups and retrospectively tested on 20 historical calibration groups, with all seven existing non-AI comparators included. The original 20 test groups are **not used for model fitting or evaluation in this workflow**, because their outcomes have already been examined in earlier research. No old test result will be rebranded as a new independent confirmation.

**Methodological caution:** This model choice was guided by exploratory experiments on historical train data. The 5-fold training-group results therefore show model development, not independently preregistered confirmatory evidence. The calibration groups were also previously used for baseline selection. Even positive historical improvement remains exploratory. Real decision superiority requires another prospectively registered independently measured physical campaign with completely fresh conditions.

The GitHub Actions workflow `.github/workflows/paired-measured-action-training.yml` downloads the original audited five shards, validates source hashes and 60/20 split, trains actual numeric model weights on real measured outcomes, archives the fit model artifact and its SHA-256, computes all train-fold comparisons and historical calibration paired group bootstrap intervals. It refuses to drop difficult groups, fabricate outcomes or report field effectiveness.

**Security:** The archived joblib model is pickle-derived and can execute code during unsafe loading. It is **not a production service artifact**. It must be loaded only from trusted provenance after independent digest verification. The learned policy is strictly a read-only selection research artifact; the existing independent safety gate is required for any lab actuation.

**Next independent validation:** Freeze the trained candidate, conduct new physical configurations across additional fault families and challenging partial-visibility states, independently measure the four eligible action outcomes and legitimate-service disruption, then compare it prospectively against the strongest registered deterministic baseline. Do not choose the comparator using the new test labels.

No 99.9% discovery or decision success target, independently confirmed AI superiority, or actual U.S. critical-infrastructure site effectiveness is asserted here.
