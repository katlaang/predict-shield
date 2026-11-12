# PREDICT-SHIELD engineering roadmap and endeavor traceability

**As of November 12, 2026.** Research pre-alpha. A merged implementation or passing CI proves only the documented local or CI behavior, not superior AI performance, commercial adoption, critical-infrastructure field validation or EB-2 NIW eligibility.

## Endeavor capability coverage

| Proposed endeavor capability | Verified development evidence | Outstanding proof |
| --- | --- | --- |
| Predictive threat intelligence | Dated EPSS/KEV ingestion and official archive integrity; pinned historical sources and chronological CVE-level baseline; first fitted historical reranker in PR #27 | Independent, preregistered later evaluation with additional genuine threat signals and no test leakage; October reranker **lost** to EPSS |
| Automated cybersecurity risk assessment | Transparent asset/CVE heuristic, explicit missingness and recorded source hashes | Calibrated contextual multi-risk ranking with operational dependencies and real asset evidence; learned model must exceed strong comparator |
| Policy-governed adaptive defense | Fail-closed policy selection, error allowances, restart permission, four actual actions, real Kafka/JVM lab and physical fault mechanism smoke | Finish v3.1 scenario adapter and pilot; action-model training using complete real replays; demonstrate bounded service disruption |
| Identify, prioritize, remediate | Authorization drift identified and lab actions replayed; synthetic asset/CVE queue ranked | Integrated cross-risk prioritization with safety gate and authorization under real operational constraints |
| Independently verify outcomes | Separate oracle, scope reconciliation, actual probes, VERIFIED/NOT VERIFIED/INDETERMINATE/NOT APPLICABLE, regression tests | Independent external reproducibility, authentic observation-source attestations and full real-scope validation |
| Continuous verification | Deterministic budget-constrained scheduler and offline assessor feedback implemented; stale result cannot clear newer change | Live authenticated probe executor, durable idempotent state and measured detection-delay benchmark; trained regression prediction |
| U.S. critical infrastructure relevance | Relevant cloud-service and operational continuity testbed problem | Independent operator/pilot engagement, sector-specific adapters and measured external applicability |

## Current research milestones

| Workstream | Evidence-based status | Next acceptance gate |
| --- | --- | --- |
| Experiment B v3 mechanism | **Implemented and CI validated**, 40 real pilot replays; all four initial faults observed | Preserve v3 provenance tag and keep exploratory measurements separate from new design |
| Experiment B v3.1 design | Proposed 150 groups × four actions × two repeats generator committed; amendment and numeric feasibility evaluator committed | Separate fully audited physical v3.1 pilot, ensure 30% fixed-policy mismatch and two distinct PARTIAL_VISIBILITY optima, diagnostic uncertainty, then freeze |
| Persistent authority fault | Physical stop/start with resync and local-restart constraints **CI validated** | Pair across all eligible actions with independently scored real outcomes |
| Consumer-only Kafka pause | Listener pause/resume while enforcer JVM stays HTTP healthy, physical smoke **CI validated** | Persistent-loss recovery/impact comparison and full pilot grouping |
| Threat baseline | Actual October 2 cut-off EPSS vs next 30-day KEV additions **measured** | Multiple truly independent temporal windows with validity constraints |
| Threat learned reranker | **Real model fitted**, June–August data; September diagnostic AP improved versus EPSS; October exploratory AP **worse than EPSS** | New uninspected prospective dates and richer features; no AI superiority claim |
| Continuous assurance | Offline scheduler + independent assessment feedback **implemented and tested** | Durable live probes, action completion vs result evidence, failure detection and regression forecasting |
| Experiment A | Physical incomplete-remediation smoke in PR #30, **pending full CI and merge** as of this update | Repeated validated scenarios and independent false-VERIFIED measurement |
| External validation | Not established | Separate operator or research-lab reproduction and documented feedback |
| Historical protocol tag | v3 Git commit and blob pinned, but annotated `protocol-v3` **not independently confirmed** | Verify Git ref/annotated-tag object and create via authorized one-time workflow or manual Git, never backdate |

## Scientific reporting rules

Use precise denominators and versioned sources, distinguish physical observation from plan generation, and do not treat passing unit tests as outcome validation. Preserve negative results and report calibrated uncertainty, temporal leakage checks, action eligibility, and independent verification boundaries. A positive AI decision-value claim requires the preregistered comparator, relative threshold, and confidence interval on independent configuration groups. Do not start the 1,200-trial campaign until the revised protocol and mechanical pilot are formally frozen.

## Evidence trail

- GitHub PRs #10, #11, #12, #14, #15, #16, #17, #19, #20, #21, #22, #23, #24, #25, #27, #28 document merged implementations or methodology.
- `docs/research/EXPLORATORY_MODEL_RESULTS_2026_11.md` records both September improvement and October loss, with source commit hashes and exact CI identifiers.
- `experiment-b/mechanism-lab/PROTOCOL_V3_AI_EVALUATION.md` is the unmodified v3 research protocol; `PROTOCOL_V3_1_FEASIBILITY_DRAFT.md` is an amendment, not a freeze.
- This roadmap is a development artifact, not an immigration legal opinion.
