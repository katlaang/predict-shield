# V3.1 five-configuration exploratory physical pilot: observed results

**Observed:** November 14, 2026. **Status:** completed independently audited exploratory subset, final six-family feasibility **INCONCLUSIVE**.

## Provenance

- Physical pilot PR: [#35](https://github.com/katlaang/predict-shield/pull/35)
- Merge commit: `bbdf94c6ed16c5ed278b88a37ce7c7cb971cf7f7`
- [GitHub Actions real physical pilot run](https://github.com/katlaang/predict-shield/actions/runs/43599751222), job `132461767177`
- Manifest: `experiment-b/mechanism-lab/pilot_v31_plan.py`, fixed seed `20261114`, frozen in PR source before execution
- Full action executor: `run_v31_subset.py`
- Evidence: per-action physically measured Kafka/JVM, actual traffic, independent scope verification, separate oracle; `export_v31_pilot.py` verifies all four stream files and uses the locked primary 0.50/0.25/0.25 objective to derive each action cost
- Group-level evaluator: `feasibility_v31.py`, corrected under PR #32 to avoid counting repeats as independent configurations
- Raw privileged trial records were kept inside disposable CI only, and cleaned after the sanitized diagnostic artifact was uploaded. This summary does not reproduce sensitive oracle detail.

## Executed versus registered

| Field | Observed |
| --- | --- |
| Independent operating configuration groups | **5** |
| Repetitions per configuration | **2** |
| Candidate physical remediation actions per repetition | **4** |
| Actual separately audited replays | **40 of 40** |
| Paired decision instances | **10** |
| Physical fault families | loss, delay, duplicate, reorder, consumer_paused |
| External authority outage | **not included** |
| Learned AI models evaluated | **0** |

## Actual feasibility diagnostics

| Proposed gate | Observation | Interpretation |
| --- | --- | --- |
| At least 30% of independent configurations differ from always resync in hindsight | **2/5 = 0.40** | Passes **this subset's** numerical diversity criterion only |
| At least two distinct unique optimal actions in PARTIAL_VISIBILITY across configurations | **Only `monitor_only`** | **Not satisfied** |
| Precision relative to the hypothetical 10% fixed-regret improvement | `oracle_gap_precision_diagnostic_inconclusive` | **Not satisfied**. This is not a paired future-model power calculation |
| Complete representative six-family v3.1 mechanism | External authority outage absent | **Not satisfied** |
| Complete preregistered v3.1 experiment | Not run | **Not satisfied** |

The CI report declared `EXPLORATORY_SUBSET_INCONCLUSIVE` and `final_v31_feasibility_evaluated=false`. The workflow succeeded because physical measurement, four-stream integrity and reporting worked, **not** because an AI predictor won or the full feasibility threshold was passed.

## Interpretation and decision

The earlier five-config v3 pilot was dominated by self-healing behavior. The new v3.1 exploratory subset independently observed **some** departure from always-resync (two of five groups), but did not demonstrate multiple distinct best decisions in PARTIAL_VISIBILITY or convincing precision. Five configurations are too few to infer the population frequency of consequential decisions. The physical fault family mix is incomplete, and operator relevance beyond a disposable laboratory has not been validated.

**Do not modify the scenario mixture to make a learned model look superior.** Keep the negative/inconclusive report in the research record. The next legitimate work is to implement the authority-outage outcome collector tracked in [issue #36](https://github.com/katlaang/predict-shield/issues/36), including separately witnessed policy state, full direct physical observations, conservative UNKNOWN semantics, and complete action eligibility and disruption metrics. Then independently predeclare a representative six-family feasibility sample and conduct power/precision planning before choosing whether to freeze and run the 150×4×2 final campaign.

This report supports documented progress on experiment integrity and policy-governed defense but does not establish superior AI efficacy or independent real-world critical-infrastructure validation.
