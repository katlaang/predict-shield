# PREDICT-SHIELD framework: P0–P1 living evidence and delivery tracker

**Last reviewed:** 2026-11-26 America/Chicago (GitHub run timestamps may fall on November 27 UTC)  
**Repository:** `katlaang/predict-shield`, research framework **only**. The separate commercial product/pilot repository must not be combined with this one.  
**Status semantics:** `DONE` = demonstrably merged/reported; `IMPLEMENTED_UNVALIDATED` = implemented but not independently scored; `EXPLORATORY_MEASURED` = retrospective data analysis with direct measured outcomes but no new confirmatory evidence; `PARTIALLY_VALIDATED` = a bounded physical condition passed while other required conditions remain open; `IN_PROGRESS` = active work; `READY_FOR_DATA` = protocol/harness exists, no accepted evaluation yet; `PENDING` = not started; `EXTERNAL_BLOCKED` = requires an independently authorized external actor.  
**Rule:** Do not convert a successful CI workflow, a scanner probe, a synthetically labeled event or a signed-up partner inquiry into evidence of verified cyber-defense effectiveness.

## Executive baseline

- **Measured SQL input detector:** Superviz25 original registered evaluation 308,190 / 336,281 generated sqlmap attack queries detected (91.6%); 15,881 / 3,017,390 generated benign queries alerted (0.53%). **This is not production performance.** [Measured result](../evidence/MEASURED_SUPERVIZ25_SQL_EXTERNAL_2026_11_26.md).
- **Measured Juice Shop v3:** inconclusive because 10 matched ZAP Medium/High evidence requests, fewer than required 30; 9/10 flagged, 6/2,298 generated benign requests alerted. The 40.0% unseen-family scanner-request alert rate is **not confirmed exploit recall**. [PR #172](https://github.com/katlaang/predict-shield/pull/172).
- **Measured defensive mechanism:** 1,200 lab trials identified effective and ineffective actions and independently probed outcomes. **No learned-selector-versus-fixed-policy superiority established.** [Campaign report](../evidence/MEASURED_MECHANISM_LAB_SCORED_CAMPAIGN_2026_11_21.md).
- **Negative evidence to retain:** flow detector v3 42/30,174 attack flows detected across HIKARI (0.14%); 1.36% normal alerts. [Report](../evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_V3_2026_11_23.md). Frozen DVWA request novelty flagged essentially every request on unrelated real web logs, but labels were unavailable, so not a measured false-positive rate. [Applicability report](../evidence/MEASURED_REAL_WEB_REQUEST_BURDEN_2026_11_26.md).
- **Critical-infrastructure field effectiveness and AI action superiority remain unproven.**

## Workstream ownership and next non-detection mission (2026-11-26)

**Coordination:** Detection model development, new detector experiments, Superviz26, and Juice Shop are being handled separately by Claude, as reported by the project owner. This assignment is not evidence that those tests have completed; their technical statuses remain unchanged until an auditable run is available.

**Next in-repo focus, excluding detection:**
1. **AI defense selection superiority (P0-10):** implement and evaluate a policy-gated learned action selector against fixed policies on disjoint fault configurations with independent post-action outcomes. Do not train and claim victory on the old 1,200-trial campaign.
2. **Crash-safe authorization (P0-11, #132):** persist and correctly restore policy revision/revocation after real cold restart. Fail closed when the recovered revision is missing or corrupt.
3. **Authority-outage uncertainty (P0-11, #36):** independently measure action outcomes without fabricating an oracle outcome when authority cannot be reached; keep INDETERMINATE.
4. **Independent verification coverage:** reduce abstentions by adding trusted scope/route/telemetry evidence, never by weakening the correct-verdict standard.
5. **Asset discovery/risk assessment integration:** validate discovery of runtime identity, missing inventory, service dependencies, exposure assessment and evidence-bound remediation planning on a separate lab.
6. **Operational P1 data and external assessor:** safely integrate authorized public telemetry; partner and consent remain prerequisites to field claims.
7. **Provenance:** resolve historical protocol-v3 tag (#41), recording its actual creation date and target.

**Boundary:** Keep all research work in this repository. Product UX, customer onboarding and commercialization live in the separate product pilot repository. AI defense-selection research and policy enforcement remain owned by this non-detection stream.

## P0: scientific validity, detector generalization, safe defense

| ID | Work item | Status | Completion evidence / next step | Acceptance gate |
| --- | --- | --- | --- | --- |
| P0-01 | Correct historical Superviz25 ablation rounding | DONE | [PR #171](https://github.com/katlaang/predict-shield/pull/171) merged. Isolation forest alone 73.9%, not 74.0%. | Exact source numerator and denominator retained |
| P0-02 | Preserve completed Juice Shop v3 inconclusive result | DONE | [PR #172](https://github.com/katlaang/predict-shield/pull/172) merged, source protocol and freeze intact. | Never relabel old evaluation as pass |
| P0-03 | Complete and independently audit Superviz25 baseline comparison with CRS | DONE | Corrected run [45913812903](https://github.com/katlaang/predict-shield/actions/runs/45913812903) completed successfully, report reviewed. Original [PR #175](https://github.com/katlaang/predict-shield/pull/175) closed after merge conflict; conflict-free [PR #177](https://github.com/katlaang/predict-shield/pull/177) is merged with evidence. First CRS results void. | Audit logs + sample reports, disclose test-benign oracle threshold and unmatched WAF HTTP surface |
| P0-04 | Implement test-independent calibration & no-leakage evaluation gate | IMPLEMENTED_UNVALIDATED | Tools and 29 synthetic unit tests merged in [PR #176](https://github.com/katlaang/predict-shield/pull/176); [final readiness CI 45918900974](https://github.com/katlaang/predict-shield/actions/runs/45918900974) passed. No genuine dataset scored. No genuine dataset scored. | Tests reject calibration on test, duplicate raw rows across partitions and cross-campaign split leakage |
| P0-05 | Juice Shop next-generation detector correcting response-score saturation | IMPLEMENTED_UNVALIDATED | Isolated candidate v4 fusion and unit tests under `experiment-b/framework-readiness/` merged in [PR #176](https://github.com/katlaang/predict-shield/pull/176). Original v3 freeze untouched. [Revalidation protocol](../protocols/DETECTOR_V4_REVALIDATION.md). | More robust unseen signal sensitivity with independently calibrated false alarm budget |
| P0-06 | Better multi-family independent ground truth | PENDING | Pre-register exploit outcome checks, ZAP alert joins and unknown semantics, require independent audit. | At least 30 confirmed cases **with diverse families**, or honestly inconclusive |
| P0-07 | Superviz26-SQL cross-domain, drift and limited-adaptation tests | READY_FOR_DATA | [Publisher Zenodo record](https://zenodo.org/records/21068333). [Prospective protocol](../protocols/SUPERVIZ26_GENERALIZATION.md). | Publisher-verified archive; respect identical OurAirports data overlap; separate untouched target-domain test |
| P0-08 | Second controlled vulnerable application (crAPI or VulnerableApp) | PENDING | Localhost or isolated owned environment only. | Frozen model(s), measured benign denominator, independently confirmed exploits, no public demo scanning |
| P0-09 | Ablation and matched baseline superiority | PENDING | Predefine model + request-novelty + forest + supervised + WAF, separate calibration, grouped confidence intervals. | Per-family, per-campaign benefit; report harms and failure to outperform |
| P0-10 | Learned AI defense selection versus fixed policies | EXPLORATORY_MEASURED | [Historical paired report](../evidence/EXPLORATORY_PAIRED_DEFENSE_2026_11_26.md), [CI run 45920476469](https://github.com/katlaang/predict-shield/actions/runs/45920476469). On 20 prior groups/60 paired replays: AI cost 0.26764 vs restart-if-permitted 0.29750, **but security resolved 28/60 vs restart 45/60**. AI 94 failed legitimate requests and 0 budget breaches vs restart 700 and 7. [PR #178](https://github.com/katlaang/predict-shield/pull/178). **Prospective superiority remains unproven.** | Freeze on configurations, same pre-action evidence, matched actions, policy validity, independent outcome measures |
| P0-11 | Physical authority outage uncertainty and cold-restart durability | PARTIALLY_VALIDATED | Existing durable store and [physical cold-restart CI 45920083955](https://github.com/katlaang/predict-shield/actions/runs/45920083955) passed, preserving trial/revision/revocation across Docker stop/start and **INDETERMINATE** outage status. [PR #178](https://github.com/katlaang/predict-shield/pull/178) adds replay/unrevocation and fsync hardening; [issue #132](https://github.com/katlaang/predict-shield/issues/132) still needs repeat/interrupted-write validation, and [outage issue #36](https://github.com/katlaang/predict-shield/issues/36) remains blocked. | No false VERIFIED when authority down; survive real stop/start without stale permit |
| P0-12 | Prospective independent detection cohort | PENDING | [Issue #130](https://github.com/katlaang/predict-shield/issues/130). | New source-pinned cohort, independent labels where accuracy claimed, frozen test, full negative/abstention reporting |

## P1: operational data and independent validation

| ID | Work item | Status | Source / next step | Acceptance gate |
| --- | --- | --- | --- | --- |
| P1-01 | Audit UGR'16 historical Spanish ISP NetFlow | READY_FOR_DATA | [Publisher](https://nesg.ugr.es/nesg-ugr16/); confirm redistribution/computational-use rights; publisher attack windows do not make all non-window flows proven benign. | Legal/usage review, pinned hash/source, capture-group split, known/unknown label report |
| P1-02 | Audit LANL 58-day multistream events | READY_FOR_DATA | [LANL primary source](https://csr.lanl.gov/data/cyber1/); red-team records are partial positive ground truth, other events are not automatically benign. | Legal/source checks, stable entity joins, leak-free time-based split, scenario-level claims only when appropriate |
| P1-03 | Audit MAWILab backbone traces/annotations | PENDING | [MAWILab](https://www.fukuda-lab.org/mawilab/); verify primary-source archive usage/access before download. | Trace permission, source provenance; anomaly annotations not relabeled as verified incidents |
| P1-04 | Build real telemetry provenance and label admission gate | IMPLEMENTED_UNVALIDATED | [Protocol](../protocols/OPERATIONAL_TELEMETRY_P1.md), `experiment-b/framework-readiness/` and [readiness CI](https://github.com/katlaang/predict-shield/actions/runs/45918572425). Source rights and real data still unverified. | Source hash checks, permission gate, capture split isolation and unknown-label preservation |
| P1-05 | Authentication, secure ingestion and continuous scoring adapter | PENDING | [Issue #135](https://github.com/katlaang/predict-shield/issues/135). | Versioned safe artifact, authenticated source, schema/late-event handling, latency/alert burden monitoring |
| P1-06 | Adaptation/drift under realistic application changes | PENDING | Real-web-log mismatch and HIKARI failures are baselines, not positive results. | New registered, grouped prospective evaluation with source-specific calibration and untouched holdout |
| P1-07 | Identify authorized ISP/operator partner and independent assessor | EXTERNAL_BLOCKED | [WISPA](https://www.wispa.org/) and research laboratories; [issue #129](https://github.com/katlaang/predict-shield/issues/129). | Written authority, bounded read-only scope, non-model-controlled evidence, signed external assessment |
| P1-08 | External testbed access (optional) | EXTERNAL_BLOCKED | [NSF FABRIC](https://www.whatisfabric.net/use-fabric/get-started), registration and project approval required. | Approved research project and reproducible isolated experiments; **not** field effectiveness |
| P1-09 | External field shadow-mode evaluation | EXTERNAL_BLOCKED | [Field protocol](../evidence/EXTERNAL_US_CRITICAL_INFRA_FIELD_VALIDATION_PROTOCOL.md). | Genuine operator observations, benign denominators, assessor-held evidence, no production action without separate approval |

## Completed in this work session / to update upon merge

- [x] PR #171 merged. Evidence rounding corrected.
- [x] PR #172 merged. Inconclusive Juice Shop evidence preserved.
- [x] Corrected CRS run 45913812903 independently checked against committed summary. PR #175 conflicted; [integration PR #177](https://github.com/katlaang/predict-shield/pull/177) is the merge path.
- [x] [PR #177](https://github.com/katlaang/predict-shield/pull/177) merged after successful Superviz baseline, Python, Java/Docker and provenance CI.
- [x] [Final readiness unit tests](https://github.com/katlaang/predict-shield/actions/runs/45918900974) passed after fixing malformed JSON input handling. One earlier unrelated Java/Docker run encountered Maven Central HTTP 429; newer integration checks are tracked separately.
- [x] [PR #176](https://github.com/katlaang/predict-shield/pull/176) merged into master. Final [framework-readiness CI 45918900974](https://github.com/katlaang/predict-shield/actions/runs/45918900974) passed 29 synthetic tests; these do not measure attack-detection efficacy.
- [ ] Source permissions for UGR'16, LANL and MAWILab confirmed in writing where necessary.
- [ ] New third-party dataset actually acquired, checksum verified and accepted for evaluation.
- [x] Candidate v4 fusion implementation and deterministic saturation tests added, without changing v3.
- [ ] Candidate v4 fitted to real benign development data, frozen and prospectively evaluated.
- [ ] AI-vs-fixed-defense prospective experiment completed; **model superiority remains unproven**.
- [x] Offline paired-defense evaluator passed its unit tests; prior physical records were replayed in [CI 45920476469](https://github.com/katlaang/predict-shield/actions/runs/45920476469), recording lower AI composite cost but fewer resolved exposures than fixed restart. See [permanent report](../evidence/EXPLORATORY_PAIRED_DEFENSE_2026_11_26.md); prospective test still pending.
- [x] Lab authority cold-restart [CI 45920083955](https://github.com/katlaang/predict-shield/actions/runs/45920083955) passed. Store hardening in PR #178 added stale-revision, same-trial unrevocation and corrupted-state protections. Repeated fault-injected crash validation and outage action comparison remain pending.
- [x] [PR #178](https://github.com/katlaang/predict-shield/pull/178) merged: historical paired defense analyzer, matched fixed-policy comparisons, calibrated disruption-bound gate, and durable-authority revision hardening.
- [x] [Physical authority cold restart CI 45920083955](https://github.com/katlaang/predict-shield/actions/runs/45920083955) passed. Full outage four-action experiment and repeated crash/fault-injection remain pending.
- [x] [Historical AI action replay CI 45920476469](https://github.com/katlaang/predict-shield/actions/runs/45920476469) passed on 20 old test configurations; [permanent measured report](../evidence/EXPLORATORY_PAIRED_DEFENSE_2026_11_26.md) records lower weighted AI cost **but fewer resolved episodes than restart**.
- [ ] New pre-registered, untouched AI-versus-fixed-policy physical evaluation completed; retrospective results cannot satisfy this gate.
- [ ] Any external operator has signed participation and independent assessment.

## Source caveats and data governance

1. Publicly downloadable is not the same as licensed for every intended use. Record publisher, URL, license/terms, access date and hash before ingesting; keep data local and avoid committing raw telemetry or credentials.
2. UGR'16 contains actual ISP background traffic, but attacks and normality are not exhaustively independently labeled. LANL's known red-team events do not establish that all other events are benign. MAWILab annotations are not independent exploit confirmation.
3. The Superviz26-SQL OurAirports domain overlaps Superviz25 data verbatim. Overlap must be removed or reported in any novelty claim.
4. Separate `event / request`, `capture / campaign`, `host-day` and `operator-site` units. CIs computed over dependent rows alone overstate precision.
5. Neither a successful attack scanner request nor a ZAP alert proves an attack succeeded. Independent application/state evidence is required for confirmed exploits.
6. Offline scientific comparisons must use held-out calibration separate from final evaluation. Do not choose thresholds on the final test's benign scores.
7. Report accurate status, including INDETERMINATE/UNKNOWN, on every experiment, public site and operator.

## Tracker maintenance contract

Every change to a P0/P1 milestone should update this document **in the same PR**: status, date, exact run IDs, source and protocol hashes, pass/fail criteria and what the evidence does *not* establish. Never mark `DONE` from an action being planned or a workflow starting. Keep unverified future runs marked PENDING/IN_PROGRESS. New experiments may add child rows but must not silently change registered old thresholds or remove negative results.
