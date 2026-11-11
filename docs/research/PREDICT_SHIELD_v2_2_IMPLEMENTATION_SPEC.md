# PREDICT-SHIELD v2.2 | AI-Centered, Verification-Grounded Implementation Specification

**Status:** Implementation contract, proposed and not yet validated  
**Prepared:** 2026-11-09  
**Design baseline:** v2.1 as identified by the project owner and external reviewer; the complete v2.1 text was not independently available in this review. The separately available v2.0 design was inspected.  
**Inspected code baseline:** katlaang/predict-shield, master, commit a8d010760ae1135155aad2b96af569cbe6160ea9 (2026-11-05).  
**Scope:** Laboratory-only interconnected IT and cloud-service controls. Not operational technology, unrestricted autonomy, production authorization, or demonstrated national-scale impact.  
**Source of truth:** the inspected repository and dated experimental records establish implementation status; earlier design notes are not execution evidence.

## 1. Decision and research objective

Keep the existing assessment -> decision -> controlled action -> independent verification -> continuous assurance architecture. Make **AI central to prediction and defensive selection** by replacing defined estimators behind typed interfaces. Keep a separately evaluated deterministic fallback, independent policy engine, and verifier. AI must never assert its own outcome, approve forbidden actions, or alter immutable experimental labels.

**Primary November AI model:** action-effectiveness and disruption prediction for Experiment B.  
**Exploratory November model:** control-regression prediction for re-verification priority.  
**Subsequent work:** contextual threat forecasting using temporal EPSS/KEV and environment context, plus evidence-gap probe recommendation. A dated EPSS feed alone is not a model developed by PREDICT-SHIELD.

Primary hypothesis: learned estimates using only pre-action features produce better safety-aware action ranking than deterministic selection and condition-average baselines **without increasing false assurance or service-limit violations**. Report a negative finding if no advantage appears.

## 2. Current repository audit, not a new implementation claim

At the inspected commit:

- engine/predict_shield/assessment.py implements a small Python scoped-evidence evaluator; engine/tests/test_assessment.py contains 10 unit tests.
- experiment-b has two Java/Spring Boot laboratory instances, an explicit localhost-only correction endpoint, Python HTTP probes, 8 mock-transport unit tests, a Compose file, and integration smoke/CI definitions.
- The Java lab uses static divergent authorization state. It does **not** yet include Kafka propagation, real identities, a learned estimator, measured action disruption, a two-source inventory oracle, or a demonstrated full v2.2 experiment.
- docs/research/v0.3.0-validation-note.md reports 38 passed tests in a **separate supplied ZIP not merged** into this repository. These are not evidence of the current repository's integrated AI execution.
- **Blocking correctness finding:** assessment.py currently returns INDETERMINATE immediately on mixed valid positive and negative observations, *before* checking for an independent failed observation. Under v2.0 INV-02, an authoritative independent refutation must produce NOT VERIFIED even alongside a supporting self-report. Add a regression test before changing this precedence. Source and trust policy must be explicit.
- Existing run.py assumes only two configured endpoint URLs and treats two HTTP 403 responses as VERIFIED. This is acceptable as a narrow lab fixture only, not as proof of independent target enumeration or authenticated provenance.

No application implementation changes are claimed by this document alone.

## 3. Contracts and separation of authority

### 3.1 Typed objects

All objects carry schema version, case ID, run ID, snapshot or parent IDs, UTC timestamps, source identity, and integrity metadata as applicable.

- **ControlAssertion:** assertion_id, desired effective state, subject/resource/operation, declared scope, applicability policy, freshness policy, policy version.
- **ScopeSnapshot:** target IDs, source inventories, identity reconciliation, scope confidence, observed times and coverage exclusions.
- **Observation:** target/assertion IDs, observed property and outcome, collected_at, origin, method, source trust tier, replay nonce, integrity proof, and failure reason.
- **CandidateAction:** action_id, target set, required authority, risk and service-health postconditions, reversibility, preconditions, policy class, impact set.
- **ActionPrediction:** evidence_snapshot_id, model_name, model_version, training_data_fingerprint, computed_at, as_of, candidate_id, residual-risk point and interval, per-service disruption point and upper interval bounds, coverage diagnostics, OOD flag.
- **DecisionRecord:** policy version, compared candidate IDs, excluded candidates and reasons, proposed action, approval authority if required, constraints evaluated, selected outcome, complete prediction provenance.
- **ExecutionAttempt:** issued capability scope/expiry, action request hash, acknowledgment, observed state-transition attempt, error, rollback request; the acknowledgment is never a VERIFIED result.
- **VerificationAssessment:** per-target observations, scope proof, four-way outcome, conflict, missing evidence, expires_at; signed or independently anchored record when such infrastructure is implemented.
- **AssuranceEntry:** assertion version, last supported outcome, verified_at, expires_at, next_probe_due, stale flag, reason for overdue work.
- **ModelTrainingExample:** references to the four separate records described below; do not flatten oracle truth into verifier output.

### 3.2 Four distinct records and their meanings

1. **Pre-action prediction:** what the model predicted based on evidence available before the intervention.
2. **Verifier assessment:** VERIFIED, NOT VERIFIED, INDETERMINATE, or NOT APPLICABLE, with exact coverage and trust conditions.
3. **Independent laboratory oracle:** actual scope and enforcement state, obtained from an experimental mechanism hidden from the model and normal verifier.
4. **Operational outcome:** measured residual exposure, error counts, latency, availability, recovery time, and policy-limit usage after intervention.

Keep these linked but independently stored and versioned. An INDETERMINATE verifier verdict is **not** automatically a negative example or censored time-to-event observation. Censor only when a precisely defined event has not been observed before the observation window ends; use separate labels for unknown oracle state and incomplete follow-up. Prevent post-action features, future feed publication dates, and oracle state from leaking into predictions.

### 3.3 AI boundary

The learned model can estimate action effects, uncertainty, risks, and regression hazard. It can recommend which probes to schedule and which policy-valid action is preferable. It **cannot** execute, change policy, generate an authoritative observation, certify VERIFIED, convert INDETERMINATE into VERIFIED, or override a prohibition.

The deterministic policy gate, action runner, observation collectors and case outcome reducer use separate identities and explicit permissions. No LLM orchestration is required in the November MVP.

## 4. Required invariants and implementable checks

- **INV-01:** No VERIFIED without fresh, trusted affirmative checks for every applicable target and verified scope completeness.
- **INV-02:** A fresh authoritative independent refutation produces NOT VERIFIED even when lower-trust self-reports disagree. Preserve a conflict flag. Untrusted contradictions alone cannot overturn a trusted assessment.
- **INV-03:** Reconcile target inventory from independent sources according to a declared target identity, membership comparison and observation-time tolerance. A material unresolved target omission yields INDETERMINATE absent a known refutation.
- **INV-04:** PROHIBITED candidates are never dispatched. Test at the executor boundary, not only in UI/controller.
- **INV-05:** Automatic execution requires trusted per-service impact upper bounds below all hard remaining error-budget limits. Unknown, zero, stale, or untrusted budget evidence prevents automatic execution.
- **INV-06:** Actuation identity, probe identity and oracle/test identity are distinct; executor self-report alone can never close a case.
- **INV-07:** VERIFIED is explicitly time-bound. Once expired, display STALE or DUE rather than continuing to show current VERIFIED. Rechecking requires fresh evidence.
- **INV-08:** Scheduler is allowed only to order authorized probes; it cannot change case outcomes, policies or actions.
- **INV-09 (v2.2):** An uncertainty or evidence precondition failure yields ESCALATE FOR EVIDENCE, **not** APPROVAL. Approval applies only when the evidence is adequate and the known action class requires a human decision.
- **INV-10 (v2.2):** The system records post-action security state **and** per-service service-health outcomes, including any service-limit breach.
- **INV-11 (v2.2):** Model predictions and evaluation labels are based on strictly separated time windows and data partitions; evaluation oracle state is not exposed as pre-action input.

Per-target outcome precedence: known applicable authoritative failure -> NOT VERIFIED; otherwise unresolved scope or required missing/untrusted evidence -> INDETERMINATE; otherwise fresh complete trusted affirmation -> VERIFIED. NOT APPLICABLE requires positive documented applicability proof for that target and is excluded from applicable scope. A fully not-applicable assertion may be NOT APPLICABLE only with complete documented scope evidence.

## 5. Learned estimators and conservative decisions

### 5.1 Estimator interface

Inputs: a versioned evidence snapshot, proposed candidate actions, per-service remaining error budgets and an as-of timestamp.

Outputs: one prediction per candidate, including expected residual risk R(a), lower and upper plausible risk bounds, per-service impact delta_err(s,a) intervals, confidence/calibration metadata, model version and training fingerprint.

Estimated pre-action quantities must be independent from post-action measurements. Residual risk and disruption are **different quantities**, not interchangeable probabilities.

### 5.2 Disruption hard gate and ranking

For each affected service s, define B_remain(s) as the measured remaining budget for the same accounting window and delta_err_upper(s,a) as the conservative estimated additional failed or late requests due to candidate a.

HardBudgetOK(a) is true only if all required service budgets and supported upper bounds are known and delta_err_upper(s,a) <= B_remain(s) for **each affected service**, with separate limits for other applicable SLOs.

For ranking eligible candidates, use the bounded score D(a) = sum_s w_s * min(1, delta_err_point(s,a) / B_remain(s)) / sum_s w_s, where s ranges over the **declared affected-service closure**, not arbitrary unrelated graph nodes. The selector ranks eligible actions by S(a) = R(a) + lambda * D(a), with lambda preregistered and tested for sensitivity. Scores never override hard policy constraints.

Preregister the affected-service set, error-budget window, target coverage, normalization of exposure and impact, and uncertain-input escalation rules. The lab oracle may score estimate errors but must never supply action selection inputs.

### 5.3 Uncertainty method

Begin with simple interpretable supervised models and a deterministic fallback. Estimate outcome intervals with held-out or calibration-split quantile/conformal methods where supported. Do not treat ordinary conformal marginal coverage as a per-service guarantee, especially under distribution shift. Missing calibration support, OOD conditions, extreme interval width or unavailable upper bounds -> ESCALATE, not AUTO-EXECUTE. Human approval does not repair missing evidence. Hard service limits are checked on conservative upper bounds.

### 5.4 AI model acceptance

The learned model must beat at least one strong applicable baseline on a preregistered primary outcome while remaining non-inferior on safety constraints. Include condition-average/lookup predictions as a baseline, not only fixed rules. A trained model that does not beat a table is still machine learning, but its **incremental benefit is unproven**. Do not claim superiority if confidence intervals or sample size cannot support it.

## 6. Experiment B experimental protocol

### 6.1 Controlled scope

Use the current localhost-only Java lab as the starting fixture. Extend to at least three distinct enforcement targets if needed for scope-completeness tests; do not assert three exist in current code. Deliberately inject stale permissions, delayed/lost/duplicate/reordered propagation, cache rebuild without a change event, unreachable probes and failed corrections. External deny tests with dedicated restricted test identities must assess effective authorization independently of the target's own status endpoint.

The laboratory oracle records the true effective policy and target membership separately from both the policy store and the normal probes. Test assumptions about compromised target reporting and unknown instances.

### 6.2 Avoid a 12-cell lookup disguised as learning

Vary traffic load, cache TTL, enforcement-point count, redundancy, propagation delay, dependency depth and action-specific service health continuously or over sufficiently rich predefined ranges. Replay comparable seeded initial conditions for each *permitted* candidate action in separate clean lab resets to obtain outcome labels without using counterfactual action claims from a single run. Hold out whole combinations and fault families, not merely randomly sampled rows from the same exact scenario.

### 6.3 Action and scheduler baselines

Primary action baselines: (a) safe fixed playbook, (b) deterministic R + lambda D selector, (c) condition-average action prediction, (d) learned estimator with identical policy gate. Compare on service-limit violations, independently measured residual exposure and safety-aware utility.

Verification baselines: full-scope post-change checking, realistic periodic full-scope checks, and change-triggered rechecking. Self-report closure is a weak negative control, not the principal state-of-practice comparator.

Scheduling baselines under the **same measured probe-cost budget**: fixed interval, change-triggered, deterministic prioritization, exploratory learned hazard prioritization. Sweep from constrained to abundant probe budgets and show conditions where learned scheduling adds no benefit.

### 6.4 Measures and labels

- False VERIFIED rate = cases declared VERIFIED while oracle establishes at least one applicable failed target / cases declared VERIFIED with evaluable oracle truth. Report denominator, confidence intervals and unresolved oracle cases separately.
- Missed NOT VERIFIED = oracle-failing cases not detected as NOT VERIFIED within the stated observation window, separated into INDETERMINATE and falsely VERIFIED cases.
- INDETERMINATE rate and avoidable INDETERMINATE rate, with preregistered oracle-based definition of "avoidable."
- Time to evidence-based outcome, silent-regression detection latency, right-censoring for unfinished time-to-event trials only when appropriately defined.
- Prediction quality: per-action residual-risk error, service-impact quantile coverage and calibration diagnostics; alert when upper bounds fail their intended coverage.
- Utility: exposure-time-weighted residual risk, service-limit breach frequency/severity, recovery time and full operation cost.
- Probe costs: measured latency, rate/resource/identity impact; any simulated scarcity parameter must be clearly labeled an experimental assumption.
- Model generalization across held-out factor combinations, fault types and shifted fault distributions.

Record failed cases, model null results, exclusions and CI logs. No invented adoption, operators, performance gains or peer-review findings.

## 7. Protocol for verifier-versus-oracle evaluation

Compute a confusion matrix only over applicable targets/cases with available oracle truth; retain separate unknown-oracle cases. Stratify error by stale inventory, hidden target, conflicting observation, target compromise, probe timeout and policy cache drift. If verifier outcome is INDETERMINATE while the oracle knows failure, report it as abstention and, only where operationally appropriate, missed detection within the time window, not a false negative binary label by default.

No testbed prediction or validation claim can substitute for independent operational evidence.

## 8. Audit and reproducibility contract

Record run ID, git commit, image digests, fixture version, random seed, model fingerprint, training/calibration/test splits, policy version, evidence IDs, action authorization, oracle labels and service-health measurements.

Store append-only event records with hash-linked ordering. For claims of actual tamper evidence, add protected signing material and periodic externally anchored checkpoints; a mutable local hash chain alone is not sufficient. No such production-grade audit mechanism is claimed for the current repository.

The CI workflow must separately report: static/unit tests, integration launch, fault injection, full-scope verification, safety negative tests, model evaluation, and experimental metric generation. Never aggregate them into a single misleading "pass rate."

## 9. November implementation milestones and gates

**Nov 9-11: v2.2 contract.** Typed records, precedence tests, trained-estimator interface, deterministic fallback and preregistered comparisons. Review existing v2.0/v2.1 discrepancies before claiming v2.2 replaces the authoritative v2.1 text.

**Nov 12-18: Experiment B end to end.** Keep current Java/Python/Compose code where working. Add controlled action comparison and measured post-action security/service health. Gate on tests for INV-01 through INV-06 and INV-09/10. No production endpoints.

**Nov 19-25: AI experiment.** Train an interpretable action outcome estimator; validate against held-out conditions and table/fixed baselines. Implement silent regression and budget sweep. Learned regression prediction is exploratory unless data support and evaluation are adequate.

**Nov 26-30: reproducible results.** Repeated seeded runs, all negative cases, tagged commit, structured result tables, explicit observed/implemented/planned statuses, written limitations. If time runs short, prioritize a rigorous Experiment B over a superficial Experiment A; defer the latter's full evaluation to December.

**December:** contextual predictive threat model with temporally valid real data, comprehensive regression hazard evaluation, expanded Experiment A, adversarial evidence trust testing, broader prior-art comparison, and independent technical review.

## 10. Immediate implementation acceptance tests

- A lower-trust positive executor claim cannot outweigh a current authoritative failed probe; outcome NOT VERIFIED and conflict recorded.
- A model that predicts a high-confidence safe action cannot dispatch it when policy forbids it.
- Unknown upper-bound disruption, missing remaining error budget or OOD context blocks automatic dispatch.
- Inadequate evidence -> ESCALATE FOR EVIDENCE; no human approval bypass.
- After action acknowledgment, the case stays unverified until independent probes actually establish its outcome.
- A reopened failed control invalidates its previously current VERIFIED assurance state.
- Every action produces measured service-health observations or an explicit measurement-failed state, never silent success.
- A missing/unregistered target causes INDETERMINATE unless a trusted refutation already establishes NOT VERIFIED.
- Model training and evaluation labels are disjoint by case/seed/group as registered; future observations cannot be used as pre-action features.
- Model and deterministic baselines use identical cases, costs and policy gates, with reported failures and unavailable evidence.

## 11. Evidence and communications status

This is a **design/specification artifact**, not execution evidence. Published research materials must distinguish planned capabilities, inspected source behavior, independently executed tests, measured results, external validation, and observed limitations. Nothing here establishes superiority, scientific novelty, or production operational safety.

**Next concrete step:** implement the typed prediction and record contracts; repair the independent-refutation precedence bug with regression tests; then extend the existing Experiment B lab to produce matched action-outcome measurements.
