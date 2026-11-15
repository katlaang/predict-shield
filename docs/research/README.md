# Research record: index

This directory holds two different kinds of document, and they should not be read as the same thing:

- **A protocol** is written and committed *before* a study runs: what will be measured, against what baseline, and what counts as success. Its file name usually says `PROTOCOL` or `SPEC`.
- **A result** is written *after* a study runs, from the data it produced. It should name its commit, its data files, and what it did not establish, not just what it found.

A result that was not preceded by a committed protocol is weaker evidence, because the comparison and the success bar could have been chosen after seeing the numbers. Where that is true below, it is noted.

## Current status, by research question

The white paper's three research questions, and the strongest evidence for each as of the dates shown. Full detail is in the linked file; nothing here should be quoted on its own as the result, since every number below carries a confidence interval or a scope limit in the source document.

### RQ1 — Active verification: does an independent check outperform self-reported status?

| Result | Finding |
| --- | --- |
| [`MEASURED_1200_AI_AND_240_FAULT_RESULTS_2026_11_14.md`](MEASURED_1200_AI_AND_240_FAULT_RESULTS_2026_11_14.md) | 1,200 physical replays: independent verification catches regressions self-report misses; AI-selected actions did not outperform the fixed-monitor baseline. |
| [`PHYSICAL_MISSING_TELEMETRY_AI_COMPARISON.md`](PHYSICAL_MISSING_TELEMETRY_AI_COMPARISON.md) | ISP missing-link detection: AI and a deterministic rule tied, 78/80. |

### RQ2 — Safe response selection: does a learned action-value model beat a strong fixed rule?

This is the active line of work. Two prospective physical studies now exist, in this order:

| Result | Configurations | AI point regret reduction vs. strongest baseline | Statistically established? |
| --- | --- | --- | --- |
| [`MEASURED_PAIRED_ACTION_AI_DECISION_RESULT_2026_11_15.md`](MEASURED_PAIRED_ACTION_AI_DECISION_RESULT_2026_11_15.md) | 24 fresh, 4 fault families | 79.4% | **No** — 95% interval includes zero |
| [`MEASURED_FIVE_FAMILY_FROZEN_AI_RESULT_2026_11_15.md`](MEASURED_FIVE_FAMILY_FROZEN_AI_RESULT_2026_11_15.md) | 60 fresh, 5 fault families (frozen model, same one as above) | 10.4% | **No** — 95% interval includes zero |

Read together, not separately: the same frozen model's advantage was not stable between the two studies, and neither reached its preregistered bar. **Do not cite the 79.4% figure on its own** — it is the smaller, less-replicated of the two measurements. The second study also found one case where the model's selected action exceeded the declared service-disruption budget, because the budget was one term in a weighted score rather than an independently enforced hard limit. That is a design finding, not a performance one, and is the reason the pipeline's action proposer (`engine/predict_shield/action_proposer.py`) is only ever offered actions the policy gate has already filtered by budget, rather than scoring the budget itself.

Supporting protocols and earlier, smaller pilots on the same question: [`AI_DECISION_VALUE_AND_INFRASTRUCTURE_VALIDATION_PROTOCOL.md`](AI_DECISION_VALUE_AND_INFRASTRUCTURE_VALIDATION_PROTOCOL.md), [`MEASURED_PAIRED_ACTION_VALUE_MODEL_TRAINING.md`](MEASURED_PAIRED_ACTION_VALUE_MODEL_TRAINING.md), [`PROSPECTIVE_FROZEN_AI_DECISION_PHYSICAL_TEST.md`](PROSPECTIVE_FROZEN_AI_DECISION_PHYSICAL_TEST.md), [`SECOND_FROZEN_AI_FIVE_FAMILY_PROSPECTIVE_PROTOCOL.md`](SECOND_FROZEN_AI_FIVE_FAMILY_PROSPECTIVE_PROTOCOL.md), [`PHYSICAL_TRAINED_AI_PILOT_PROTOCOL.md`](PHYSICAL_TRAINED_AI_PILOT_PROTOCOL.md), [`ACTUAL_AI_DECISION_PILOT_96_PHYSICAL_2026_11_14.md`](ACTUAL_AI_DECISION_PILOT_96_PHYSICAL_2026_11_14.md), [`TRAIN_ONLY_AI_STABILITY_2026_11_14.md`](TRAIN_ONLY_AI_STABILITY_2026_11_14.md), [`PHYSICAL_OUTAGE_REPEATED_PILOT_2026_11_14.md`](PHYSICAL_OUTAGE_REPEATED_PILOT_2026_11_14.md), [`V31_AUTHORITY_OUTAGE_ACTIONS_2026_11_14.md`](V31_AUTHORITY_OUTAGE_ACTIONS_2026_11_14.md), [`V31_CONSUMER_PHYSICAL_RESULTS_2026_11_14.md`](V31_CONSUMER_PHYSICAL_RESULTS_2026_11_14.md), [`V31_FIVE_GROUP_PILOT_2026_11_14.md`](V31_FIVE_GROUP_PILOT_2026_11_14.md).

### RQ3 — Continuous assurance / threat prioritization: does a learned model rank risk better than EPSS or a fixed rule?

| Result | Finding |
| --- | --- |
| [`EXPLORATORY_MODEL_RESULTS_2026_11.md`](EXPLORATORY_MODEL_RESULTS_2026_11.md) | Beat EPSS in one monthly window, lost in the next. No stable advantage shown. |
| [`EXPLORATORY_CHRONOLOGICAL_MODEL.md`](EXPLORATORY_CHRONOLOGICAL_MODEL.md), [`THREAT_INTEL_BACKTEST.md`](THREAT_INTEL_BACKTEST.md), [`THREAT_INTEL_BASELINE.md`](THREAT_INTEL_BASELINE.md), [`HISTORICAL_KEV_PROXY_BASELINE.md`](HISTORICAL_KEV_PROXY_BASELINE.md), [`PINNED_HISTORICAL_SOURCES.md`](PINNED_HISTORICAL_SOURCES.md) | Supporting baselines and data provenance for the above. |

### Advisory reading (new line of work, not yet a measured result)

Rule baseline measured on 120 real 2026 advisories; no model has been run yet. Tracked at `experiment-a/advisory-reading/README.md`, not in this directory, because it ships with its corpus and harness rather than a dated write-up. (That file ships with the AI-decision-layer patch; if it is not yet in your checkout, apply that patch first.)

### Vulnerability / CVE-specific model comparisons

[`REAL_LOCAL_VULNERABILITY_AI_MODEL_COMPARISONS_2026_11_14.md`](REAL_LOCAL_VULNERABILITY_AI_MODEL_COMPARISONS_2026_11_14.md), [`VENDOR_VERIFIED_VULNERABILITY_MODEL_COMPARISON.md`](VENDOR_VERIFIED_VULNERABILITY_MODEL_COMPARISON.md), [`SECOND_VENDOR_CVE_MODEL_COMPARISON.md`](SECOND_VENDOR_CVE_MODEL_COMPARISON.md), [`MEASURED_REAL_CVE_AI_REMEDIATION_2026_11_15.md`](MEASURED_REAL_CVE_AI_REMEDIATION_2026_11_15.md), [`REAL_CVE_AI_REMEDIATION_LAB_PROTOCOL.md`](REAL_CVE_AI_REMEDIATION_LAB_PROTOCOL.md), [`ACTUAL_LOCAL_AI_INFERENCE_SMOKE.md`](ACTUAL_LOCAL_AI_INFERENCE_SMOKE.md) — a separate thread from the Experiment B action-value work above; not yet reconciled with `advisory_reader.py`.

### ISP / telecom asset discovery

[`ISP_MEASURED_EVIDENCE_LEDGER_2026_11_14.md`](ISP_MEASURED_EVIDENCE_LEDGER_2026_11_14.md), [`ISP_REAL_SNMP_DISCOVERY_PILOT.md`](ISP_REAL_SNMP_DISCOVERY_PILOT.md), [`ISP_REAL_TOPOLOGY_GROUPED_BENCHMARK.md`](ISP_REAL_TOPOLOGY_GROUPED_BENCHMARK.md), [`ISP_CONTROLLED_DEFENSE_EXPERIMENT.md`](ISP_CONTROLLED_DEFENSE_EXPERIMENT.md), [`GNMI_MTLS_PHYSICAL_LAB.md`](GNMI_MTLS_PHYSICAL_LAB.md), [`PHYSICAL_ISP_GRAPH_AI_RISK.md`](PHYSICAL_ISP_GRAPH_AI_RISK.md), [`TELECOM_GRAPH_RISK_MODEL.md`](TELECOM_GRAPH_RISK_MODEL.md), [`TELECOM_AI_LINK_DISCOVERY_PROTOCOL.md`](TELECOM_AI_LINK_DISCOVERY_PROTOCOL.md), [`TELECOM_LOCKED_SUPERIORITY_PROTOCOL.md`](TELECOM_LOCKED_SUPERIORITY_PROTOCOL.md) — includes the 99.9% target, now withdrawn (see `../development/ROADMAP.md`).

### Verification mechanics

[`REVERIFICATION_SCHEDULER.md`](REVERIFICATION_SCHEDULER.md), [`VERIFICATION_FEEDBACK_CYCLE.md`](VERIFICATION_FEEDBACK_CYCLE.md)

### External field validation (not yet attempted — protocols only)

[`EXTERNAL_PILOT_VALIDATION.md`](EXTERNAL_PILOT_VALIDATION.md), [`EXTERNAL_US_CRITICAL_INFRA_FIELD_VALIDATION_PROTOCOL.md`](EXTERNAL_US_CRITICAL_INFRA_FIELD_VALIDATION_PROTOCOL.md) — no organization outside this lab has run any part of PREDICT-SHIELD. Everything above is a single four-JVM laboratory, not independent sites.

### Design documents, not results

[`PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md`](PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md) was written 2026-11-09 against an older commit, before the language-model decision layer (`engine/predict_shield/language_model.py`, `advisory_reader.py`, `action_proposer.py`) existed. Treat the current engine code and this index as the source of truth for what is implemented; this spec is a historical design note. [`v0.3.0-validation-note.md`](v0.3.0-validation-note.md) is the same kind of note for an earlier, separately supplied ZIP that was never merged.

## Writing a new result

1. Commit the protocol first, in its own file, before the run.
2. Name the result file for what it measures, not a version or date alone — the pattern above (`MEASURED_<what>_<when>.md`) is fine, but check this index for an existing file on the same question before adding a new one. Several files above cover the same question at different dates; prefer extending the latest one.
3. Add the result to the table above in the same change. A result that exists only as its own file, with nothing pointing to it from here, will not be found.
