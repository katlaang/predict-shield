# PREDICT-SHIELD engineering roadmap and endeavor traceability

**As of November 14, 2026.**

## AI decision value and infrastructure effectiveness: evidence checkpoint

- **AI has been implemented and trained for historical CVE threat-ranking research.** Its September diagnostic improved on the EPSS proxy but its October exploratory result underperformed EPSS. This is not a positive AI superiority conclusion.
- **Action-effectiveness AI comparison code is now implemented (PR #51), not empirically demonstrated.** A physical-data trainer requires a complete 1,200-action four-stream lab dataset. Once data exist, its evaluation selects the strongest eligible non-AI comparator on calibration configurations, tests a random-forest selector on 20 separate held-out configuration groups, and requires group-paired bootstrap evidence of at least 10% regret improvement against all seven predeclared deterministic comparators under a Bonferroni safeguard. Current synthetic tests confirm the code contract, not superiority.
- **External U.S. infrastructure validation is prepared but not conducted (PR #52).** The sector-independent operator-study protocol and fail-closed evidence manifest check demand real operator permission, independent assessor evidence, matched service baselines, and actual exposure, downtime, legitimate-request failure and false-assurance counts. Structural completeness cannot authenticate a real operator or prove impact.
- **Authority-outage action inference remains limited.** PRs #43–#50 established physical outage witnesses, four action interventions, real timed observations, conservative UNKNOWN intervals, draft six-family feasibility registration and sample-size caution. The complete six-family physical study is not authorized/frozen; no field critical-infrastructure resilience improvement has been quantified.
- **Research claims must remain separated.** Software CI success, completed exploratory laboratory actions, a positive held-out laboratory comparator result (if eventually observed), and independent operator field impact are four different evidence levels. Neither GitHub traffic nor self-reported records can bridge those levels.

 Research pre-alpha. A merged implementation or passing CI proves only the documented local or CI behavior, not superior AI performance, commercial adoption, critical-infrastructure field validation or EB-2 NIW eligibility.

## Endeavor capability coverage

| Proposed endeavor capability | Verified development evidence | Outstanding proof |
| --- | --- | --- |
| Predictive threat intelligence | Dated EPSS/KEV ingestion and official archive integrity; pinned historical sources and chronological CVE-level baseline; first fitted historical reranker in PR #27 | Independent, preregistered later evaluation with additional genuine threat signals and no test leakage; October reranker **lost** to EPSS |
| Automated cybersecurity risk assessment | Transparent asset/CVE heuristic, explicit missingness and recorded source hashes | Calibrated contextual multi-risk ranking with operational dependencies and real asset evidence; learned model must exceed strong comparator |
| Policy-governed adaptive defense | Fail-closed policy selection, error allowances, restart permission, four actual actions, real Kafka/JVM lab and physical fault mechanism smoke | Five-group v3.1 exploratory pilot completed but **final feasibility inconclusive**; complete authority-outage action collector and independent six-family feasibility before any full campaign |
| Identify, prioritize, remediate | Authorization drift identified and lab actions replayed; synthetic asset/CVE queue ranked | Integrated cross-risk prioritization with safety gate and authorization under real operational constraints |
| Independently verify outcomes | Separate oracle, scope reconciliation, actual probes, VERIFIED/NOT VERIFIED/INDETERMINATE/NOT APPLICABLE, regression tests | Independent external reproducibility, authentic observation-source attestations and full real-scope validation |
| Continuous verification | Deterministic budget-constrained scheduler and offline assessor feedback implemented; stale result cannot clear newer change | Live authenticated probe executor, durable idempotent state and measured detection-delay benchmark; trained regression prediction |
| U.S. critical infrastructure relevance | Relevant cloud-service and operational continuity testbed problem | Independent operator/pilot engagement, sector-specific adapters and measured external applicability |

## Current research milestones

| Workstream | Evidence-based status | Next acceptance gate |
| --- | --- | --- |
| Experiment B v3 mechanism | **Implemented and CI validated**, 40 real pilot replays; all four initial faults observed | Preserve v3 provenance tag and keep exploratory measurements separate from new design |
| Experiment B v3.1 design | Proposed 150 groups × four actions × two repeats generator committed; amendment and numeric feasibility evaluator committed | Five-group 40-replay pilot passed physical/audit checks but remained inconclusive: 2/5 fixed-policy mismatches, only monitor uniquely optimal in PARTIAL_VISIBILITY, precision diagnostic inconclusive, authority-outage missing. See PR #35 and research report. Next: representative six-family independent feasibility and power review before freeze |
| Persistent authority fault | Physical stop/start with resync and local-restart constraints **CI validated** | Complete issue #36: separately witnessed pre-outage policy, UNKNOWN-safe outage oracle and physical four-action cost collection; do not invent outcome labels |
| Consumer-only Kafka pause | Listener pause/resume while enforcer JVM stays HTTP healthy, physical smoke **CI validated** | Four actions physically replayed (PR #33), with restart lowest cost in one inspected condition; independent five-group subset executed (PR #35). Establish broader measured generalization before AI value claim |
| Threat baseline | Actual October 2 cut-off EPSS vs next 30-day KEV additions **measured** | Multiple truly independent temporal windows with validity constraints |
| Threat learned reranker | **Real model fitted**, June–August data; September diagnostic AP improved versus EPSS; October exploratory AP **worse than EPSS** | New uninspected prospective dates and richer features; no AI superiority claim |
| Continuous assurance | Offline scheduler + independent assessment feedback **implemented and tested** | Durable live probes, action completion vs result evidence, failure detection and regression forecasting |
| Experiment A | Physical incomplete-remediation smoke PR #30 **merged after successful real Kafka/Docker CI**, detects unresolved known hidden node even when gateway-visible paths deny | Repeated validated scenarios and independent false-VERIFIED measurement |
| External validation | Not established | Separate operator or research-lab reproduction and documented feedback |
| Historical protocol tag | v3 Git commit and blob pinned, but annotated `protocol-v3` **not independently confirmed** | Verify Git ref/annotated-tag object and create via authorized one-time workflow or manual Git, never backdate |

## Scientific reporting rules

Use precise denominators and versioned sources, distinguish physical observation from plan generation, and do not treat passing unit tests as outcome validation. Preserve negative results and report calibrated uncertainty, temporal leakage checks, action eligibility, and independent verification boundaries. A positive AI decision-value claim requires the preregistered comparator, relative threshold, and confidence interval on independent configuration groups. Do not start the 1,200-trial campaign until the revised protocol and mechanical pilot are formally frozen.

## Evidence trail

- GitHub PRs #10–#12, #14–#17, #19–#25, #27–#35, #37 and #39 document merged implementations, research observations or methodology. PR #38 is undergoing the authority-unavailable oracle hardening gate.
- `docs/research/EXPLORATORY_MODEL_RESULTS_2026_11.md` records September improvement and October loss, with source commit hashes and exact CI identifiers.
- `docs/research/V31_CONSUMER_PHYSICAL_RESULTS_2026_11_14.md` preserves one real consumer-pause action comparison; `docs/research/V31_FIVE_GROUP_PILOT_2026_11_14.md` records 40 physical replays and the inconclusive scientific feasibility outcome.
- `experiment-b/mechanism-lab/PROTOCOL_V3_AI_EVALUATION.md` is the unmodified v3 research protocol; `PROTOCOL_V3_1_FEASIBILITY_DRAFT.md` is an amendment, not a freeze.
- This roadmap is a development artifact, not an immigration legal opinion.
