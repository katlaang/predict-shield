# PREDICT-SHIELD: Actual trained AI action-benefit study and prospective physical validation

**Recorded:** November 15, 2026. Evidence is from two complete GitHub Actions workflows and their original downloaded machine-readable result artifacts. Models and physical action records were not recreated for this report.

## Source code and actual execution provenance

- **Trained AI:** merged [PR #96](https://github.com/katlaang/predict-shield/pull/96), merge commit `4ac091e4cd9afd3cc50c54398b849da9fcea6a87`; [GitHub Actions run 43682077804](https://github.com/katlaang/predict-shield/actions/runs/43682077804), successful. Actual saved model and training report: artifact `paired-real-physical-action-value-model-and-historical-validation`, ID `14149041182`, ZIP SHA-256 `a9683a4052f7e21b70cdde120aec7a969e6eac156668545f837a6e700af15d2b`. Model's own joblib file SHA-256: `35a040b26a935bfb529f6247dbd0be1a01288294f8fb7089d4de60366adf3f92`. Training report's internal SHA-256: `666b6668030ff7a9e24d510198343abc45f797a5372c5cd917ecf85f9a9494cc`.
- **Genuinely new physical testing:** merged [PR #97](https://github.com/katlaang/predict-shield/pull/97), merge commit `e144db63d7b78c9f1055eb5cd63121ba1bd1f2ad`; [GitHub Actions run 43682440153](https://github.com/katlaang/predict-shield/actions/runs/43682440153), successful. Original full new lab comparison report: artifact `prospectively-frozen-ai-vs-seven-rules-fresh-192-physical-results`, ID `14149026967`, ZIP SHA-256 `06b89f94a17447eadb678ea98a5cadc76c79aebea76cdea221d726e5d79dae77`; result JSON's internal SHA-256 `6fb9c14f7abfb795a4b0f1dd27c4957584b075c618844d28882be4437e89a225`. The three individual audited source artifacts were `new-paired-action-real-physical-shard-0`, `-1`, `-2`, with respective artifact ZIP SHA-256 hashes `b369aea4fb4406714a1c65ecae305352af87653e85d14d8f268c371b9cd0f56f`, `00abea0ec076c952421f7280d845ed208d1bc4ae8e031a5950128c8592060cbc`, and `501d5ca3055e85c6cf08220737621c0d091034de80cf5d4ed0215ef6ff45e6c0`.
- **Original real training source:** [full 1,200-action Java/Kafka physical campaign, run 43629488209](https://github.com/katlaang/predict-shield/actions/runs/43629488209), five independently audited source shards. These are **software-lab physical network/action replays**, not installed ISP router hardware or a participating U.S. critical-infrastructure operator.

## Experiment 1. Direct measured action-effectiveness learning

The earlier four-outcome Random Forest decision model had **0.0032918502** hindsight regret on the original 20-group test, worse than its calibration-locked strongest deterministic `fixed_monitor` comparator at **0.0027853271**. No AI superiority was established.

The new research model directly learns **actual observed benefit of intervening versus monitor-only** from the same configured physical fault/repetition, with each alternate action's observed outcome independently recorded. Its features include only pre-action operator-visible observations and candidate identity. The model cannot see injected fault identity, private oracle truth, or future outcomes. Eligible action masks prohibit restart if the change freeze disallows it.

Fixed model (no evaluation-time changes): `HistGradientBoostingRegressor(max_iter=120, max_leaf_nodes=10, learning_rate=0.05, l2_regularization=1, random_state=221)`; minimum predicted advantage to intervene **0.01** research utility units. All model inputs and outcomes derive from real Java/Kafka lab replays; no synthetic outcome labels were used for fitting.

- 60 original training configuration groups, **720 measured action rows**, yielding **540 matched intervention-benefit examples**.
- Five-fold whole-configuration *train-only* development CV: mean monitor-minus-AI regret **+0.0037047636**. Folds vary, one essentially tied/slightly negative. This is a tuning/development result, **not** independent validation.
- Historical 20 calibration configuration groups, **240 measured action rows**: AI mean regret **0.0241255681**, fixed-monitor **0.0353422106**. Point-estimate relative regret reduction ≈31.7%. The paired 95% interval on absolute reduction includes zero (approximately **−0.00342 to +0.03791**). Historical groups were examined in earlier research and cannot be treated as new independent confirmation.

## Experiment 2. Freshly configured physical action comparison

After freezing the entire model, model file digest, prediction threshold, seven rule policies, and experiment manifest:

- Ran **24 new configured conditions**, with separate `fresh-benefit-...` IDs and new random registration seed `20261115071`. Three complexity strata (SIMPLE, INTERACTION, PARTIAL_VISIBILITY); four actual fault families (loss, delay, duplicate, reorder), two configurations per stratum/fault. They do not reuse the 60 original training configuration IDs or the 20 historical calibration/test IDs.
- Independently executed all four actual defenses (`resync_policy`, `restart_enforcer`, `gateway_restrict`, `monitor_only`) under each of **two repeats per configuration**, for **192 audited physical replays** and **48 offline AI-v-rule choices**.
- Every shard passed its four-stream physical audit. Neither private oracle data nor fault labels entered the model's pre-action feature vectors.
- The AI selected **32 monitor-only, 10 resync-policy, six restart-enforcer** actions, with **zero** selected actions exceeding the declared *laboratory* legitimate-service failed-request allowance.
- Exact research utility remains the registered `0.50 × time-integrated path exposure fraction + 0.25 × remaining authorization exposure indicator + 0.25 × failed legitimate requests / declared error allowance`. Lower regret is better.

### Primary fresh measurements

| Policy | Fresh 24-group mean hindsight regret | AI-v-policy comparison |
| --- | ---: | --- |
| **New frozen paired-action AI** | **0.0042847329** | Research model |
| Previously strongest `fixed_monitor` | 0.0208292479 | AI relative regret **79.43% lower at point estimate** |
| `fixed_resync` | 0.0222734134 | AI relative regret 80.76% lower at point estimate |
| `engineering_rule` | 0.0911641699 | AI relative regret 95.30% lower |
| `observable_telemetry_rule` | 0.0949178041 | AI relative regret 95.49% lower |
| `train_tuned_rule` | 0.0749320033 | AI relative regret 94.28% lower |
| `fixed_restart_or_gateway` | 0.2606041415 | AI relative regret 98.36% lower |
| `fixed_gateway` | 0.2834848270 | AI relative regret 98.49% lower |

The **absolute paired regret improvement versus fixed-monitor was 0.0165445150**. However, the ordinary two-sided 95% paired configuration-bootstrap interval was approximately **[−0.00054979, +0.04178682]**, and the predeclared multiplicity-adjusted one-sided relative lower bound was **−0.66911**. **Both permit no true improvement**. The strict predeclared 10%-improvement threshold was supported against **five of seven** non-AI baselines, but **not** against previously best fixed-monitor or fixed-resync.

**Official result:** `lab_paired_action_benefit_superiority_supported_under_frozen_protocol=false`. This remains the scientific conclusion irrespective of the favorable 79.43% point estimate. Do not silently substitute unadjusted statistical tests or a weaker comparator to manufacture a positive result.

### Why no 99.9% or general field claim

These are 24 different software-lab operating configurations within the **same four-JVM Kafka deployment**, not independent U.S. critical-infrastructure organizations. Two repetitions per configuration, each containing four measured action replays, are not two independent operator incidents. A cost-weighted decision regret is not the same quantity as 99.9% incident detection accuracy, 99.9% policy correctness, or customer service availability.

The comparison was **offline**: real action outcomes were independently measured in the testbed for all four candidate choices, then the **previously frozen** AI scored the observable pre-action context and was evaluated against those saved outcomes. This was **not** online AI-driven autonomous production dispatch or independent operator-field remediation.

## What this evidence supports

**Demonstrated:** the user-built PREDICT-SHIELD action-value AI was trained on independently measured real software-lab action consequences; the fixed resulting policy obtained **lower average regret than all seven traditional policies** on 24 fresh lab configurations, and no AI-selected action exceeded this experiment's declared error budget.

**Not established:** statistical superiority against the strongest rule under the frozen familywise objective; transferability across independent deployments or fault families outside this study; actual critical-infrastructure field effectiveness; a 99.9% reliability result. No separate external organization independently signed the source outcomes.

**Next scientifically meaningful work** is more independent physical configurations from different mechanisms/operators, with enough statistical power to distinguish modest improvements over very low-regret strong conventional baselines. A change to model hyperparameters or decision margin after viewing these fresh results requires a **new prospectively separated study**, with the present observations retained as development data, never retitled untouched confirmatory test.
