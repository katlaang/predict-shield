# PREDICT-SHIELD Protect: Operator Pilot v1

**Status:** Product scope and delivery gates, not a claim of production readiness.  
**Primary customer:** Small infrastructure teams operating internet-facing applications and containerized services who need to find and safely resolve high-priority exposures without a large SOC.  
**Architecture:** Sector-independent engine. First supported adapter is Docker-hosted applications and their web-facing services. ISP, telecom, cloud and OT-specific adapters are subsequent releases.

## Customer promise

"Connect the infrastructure you are authorized to protect. See actionable security cases, why they matter, what defense is permitted, and independently verified evidence that a fix worked without unnecessarily disrupting service."

PREDICT-SHIELD sells **verified resolution of operational cyber risk**, not benchmark detection accuracy. Detection models and benchmarks remain quality and safety dependencies, not the core customer workflow.

## One complete customer journey (release scope)

1. **Install safely:** An operator deploys a documented, self-hosted single-organization service, signs in, and registers an environment and allowed assets. Installation must not expose a public administrative service or require a third-party production target.
2. **Connect read-only:** Collect an authorized Docker/runtime inventory and independent network observation when available. Show last observed time, source, and explicitly unknown/incomplete scope. Never claim complete asset coverage from a single adapter.
3. **Open a security case:** Ingest an independently sourced vulnerability advisory or authenticated alert. Link observed asset, evidence IDs, applicability status, affected service, and source timestamps. Never turn an advisory text match into a confirmed exploitable vulnerability.
4. **AI triage:** Analyze the case with an auditable model version, explain evidence and uncertainty, suggest *catalog-registered* defenses, and show at least one non-AI or fixed-policy alternative. Unknown model confidence is displayed as unknown, not fabricated.
5. **Approve or reject:** Show predicted risk reduction, potential service disruption, proposed verification, and the exact target. Policy gate decides eligibility; operator provides cryptographically bound approval whenever required. Default mode is read-only.
6. **Apply within scope:** Run only existing approved, bounded execution adapters. Log start, refusal, failure and rollback. No arbitrary shell commands from AI output. Operators can always choose no action.
7. **Verify independently:** A separate checker verifies both the vulnerability/undesired behavior and required service health. A change acknowledgement is not proof. Outcome is VERIFIED / NOT VERIFIED / INDETERMINATE / NOT APPLICABLE where applicable; rollback on a failed or indeterminate protected-action check under the registered policy.
8. **Export evidence:** Download an immutable case timeline with discovery source, finding, proposal/model fingerprint, gate/approval, actual action, verification, rollback if any, and checksums. Mark any missing source as missing.

The product's primary screen is a **case queue** (Open, Awaiting evidence, Awaiting approval, Verifying, Resolved and Verified, Failed/Rolled back) with one-click access to evidence. It is not a wall of model scores.

## Core records

- **Asset:** environment, scoped identity, owner, service, source, timestamp, inventory completeness.
- **Finding:** external source, advisory/detection ID, asset binding, applicability evidence, observed timestamp, confidence limits.
- **Case:** ID, risk explanation, state, evidence IDs, service impact, decision owner.
- **Action plan:** model/version, alternatives, expected consequence and uncertainty, registered action, policy decision, verification plan.
- **Execution:** bound approval, exact action, start/end, immutable receipt, refusal/failure/rollback.
- **Verification:** independent check source, service-health check, factual outcome, evidence digest.
- **Audit event:** actor, timestamp, case, transition, input/output references, integrity proof.

Persist case state durably. The existing in-memory live feed may supply the UI but must not be the sole system of record.

## Engineering scope, in order

### P0: A useful, safe pilot

- [ ] **Self-hosted install:** One documented deployment path, sample configuration, health check, secure secret handling, backups, upgrades and removal. No reliance on Actions or demo scripts for day-to-day operation.
- [ ] **Operator access:** Authentication and authorization, one organization with least-privilege roles (viewer, operator, approver), TLS at the trust boundary, restricted audit export.
- [ ] **Read-only discovery:** Register approved Docker environment, collect inventory automatically, persist it and show unknown assets / missing metadata / coverage gaps. Do not require broad host root or an unaudited public Docker socket.
- [ ] **Findings-to-cases:** Wire real asset, advisory and authenticated detection evidence into a durable case queue; explicit stale, unverifiable, inapplicable and unknown states; deduplication and reassessment.
- [ ] **AI decision support:** AI-generated explanation and selection over bounded actions using verified evidence; strict model output validation; deterministic policy approval; fallback to non-AI recommendations and abstention.
- [ ] **Controlled change:** At least one end-to-end supported remediation type, default dry-run, signed human approval for production action, idempotent execution, service check, rollback and independently measured verification.
- [ ] **Customer dashboard/API:** Asset list, prioritized case queue, evidence details, model/proposal, risk/impact rationale, approval state, verification and export. Never preload fabricated live results.
- [ ] **Pilot observability:** Collect errors, job status and failure explanations; retry safely; alert on stale/failed connectors; redact secrets and personal data.

### P1: External pilot readiness

- [ ] Cross-host deployments, restore/recovery test, retention/deletion controls, security review, API access controls and rate limits.
- [ ] Run a customer-authorized shadow-mode discovery and findings evaluation before any production mutation.
- [ ] Execute one explicitly approved low-risk remediation in a pilot environment with rollback and independent verification.
- [ ] Obtain operator feedback, establish manual baseline, and report per-case time-to-triage, resolution time, action success, verifier outcomes, downtime, operator effort and unexpected changes.
- [ ] Publish factual case studies with owner consent; never expose customer asset identifiers or secrets in public evidence.

### Deferred (not pilot blockers)

- Automated penetration testing of third-party production sites, unsupervised disruptive changes, general OT actuation, broad multi-cloud support, multi-tenancy/billing, generic agentic shell execution, and claims of superior AI defense selection.
- Sector-specific telecom/gNMI/SNMPv3 and grid integrations after the common workflow has a validated pilot.

## Existing components to retain and integrate

| Existing implementation | Product use | Remaining gap |
|---|---|---|
| `engine/predict_shield/asset_discovery.py` | Docker inventory and independent-snapshot reconciliation | Secure connector deployment, scheduling, persistent history and customer UI |
| `engine/predict_shield/pipeline.py` | Evidence-grounded AI case planning | Durable cases, customer inputs, lifecycle integration |
| `engine/predict_shield/change_execution.py` | Scoped action/approval/rollback mechanisms | Real target adapter, service-specific authorization, field reliability |
| `engine/predict_shield/live_feed.py` and `demo/live.*` | Real-time events and read-only status | Authenticated durable API and product case screens |
| `dashboard/index.html` | Topology prototype | Product navigation, real customer inventory, backend, bundling |
| `showcase/` | Product information and pilot interest | Keep separate from authenticated operator console |
| `experiment-b/` | Detector quality, ablations, policy gate and mechanism evidence | Only product-relevant release tests should block shipping |

Current repo README explicitly labels the system a *working lab prototype, not a finished product*, and identifies operator validation as missing. These are implementation targets, not claims of completion.

## Release gates

**Internal product demo**: A new operator can install and complete a full *lab* case from discovered asset to independently verified fix, with UI and evidence export, using no fabricated live measurements.

**Controlled external pilot**: Named authorized operator, bounded scope, read-only assessment first, approval before any production change, authenticated console, persistent case history, rollback exercise, and a documented outcome report.

**Commercial beta**: Pilot deployment/upgrade/backup/restore validated; independent security review, support and incident procedures, acceptable data handling, adoption and measurable operational value confirmed. No GA claims before these are met.

## Evaluation policy

Every training or detection experiment must answer a product question: What customer case does it improve? Against which simpler baseline? At what false-alarm or service-disruption cost? What is the frozen holdout and reproducible evidence? A failed result stays visible. Do not equate scanner probes with confirmed exploits, benchmark metrics with customer resilience, or successful CI with production readiness.

**Initial commercial hypothesis (to validate, not assumed):** Small infrastructure operators will value a verified security-case workflow that reduces human triage effort and failed fixes. Interview prospective operators and collect willingness-to-pay evidence before selecting prices.

## Immediate implementation target

Deliver the **single-environment, read-only case queue** using real discovery and advisory/detection evidence, with a persistent audit trail and explicit verification status. Follow it with approval and one bounded remediation adapter. Build customer onboarding and end-to-end acceptance tests as part of the feature, not after it.
