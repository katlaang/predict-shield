# External U.S. Critical-Infrastructure Validation: Study Protocol and Evidence Requirements

**Status as of November 15, 2026: NOT STARTED.** No participating U.S. critical-infrastructure site has been verified; no operator consent, signed change authorization, independent field measurements, or external assessor report has been obtained. This is a preregistration/readiness artifact **only**, not evidence that PREDICT-SHIELD works in a real critical-infrastructure deployment.

## Scientific questions, separately reported

1. **Applicability and remediation:** Can PREDICT-SHIELD identify a truly affected component/configuration and, after proper authorization, independently confirm that a permitted remediation removes the actual exposure?
2. **AI decision value:** Given the same available information, candidate defenses, action costs and safety constraints, does a *frozen* AI policy choose better defenses than a competent, pre-registered rule or expert playbook?
3. **Operational impact:** Does the action preserve legitimate traffic, service availability and safety budgets at the particular site?
4. **Transferability:** Does performance hold in entirely separate operators, network sectors and fault families, and not just in repeated replicas of one deployment?

A demonstration of Question 1 is **not** proof of Questions 2-4. A vendor-version match alone is **not** independent runtime vulnerability verification.

## Governance before any live operator test

- A named U.S. critical-infrastructure owner/operator and designated accountable change approver must sign a **site-specific written scope and consent**. Verify actual ownership, authority and environment; never infer it from a person's employer or industry membership.
- Record permitted assets/identifiers, exact maintenance window, access restrictions, approved action list, human approval tiers, service-level limits, safety-critical dependencies, no-go conditions, and immediate rollback owners.
- Require a **nonproduction mirror or operator-approved staging environment first**. Escalate to a production-environment action only after formal operator authorization and a demonstrated, tested rollback plan.
- A separate assessor must define ground-truth methods and independently retain observations. Model and actuator cannot be their own truth source.
- Enforce data minimization. Do not export customer PII, private routing tables, sensitive network configurations, critical facilities or unredacted security credentials to a public GitHub repository or public AI service.
- For a live site, configure a **non-mutating dry-run** before any remediation. If any required independent evidence, budget, authorization, rollback test or source attestation is absent, record `ABSTAINED` and make no change.
- Align with NIST SP 800-61 Revision 3 (April 2025), which integrates incident response and cybersecurity risk management: https://csrc.nist.gov/pubs/sp/800/61/r3/final .

## Prespecified experiment and strong comparisons

- Select the threat/vulnerability families and candidate sites **before looking at held-out outcomes**. Label cases from the operator's independent authenticated observations and version/configuration-specific functional checks where safe.
- Freeze model weights or API revisions, prompts, retrieval corpus, calibration, action effect predictor, thresholds and action catalogs. Log SHA-256 digests and independent source identities; digests alone are not signed attestations.
- Evaluate on **matched incidents or randomized equivalent nonproduction replicas** with independent before/after observations. Track order, state contamination, risk and disturbance; retain every attempt and abstention.
- Required primary outcomes: independently observed vulnerability/exposure closure; validated remediation correctness; percentage of permitted actions actually executed; failure/rollback rate; changed legitimate traffic errors; changes in p95/p99 latency and service continuity; total time to resolve; operator override/approval; and measurable side effects.
- Report confusion matrices for detection, verified true-positive/false-positive/false-negative findings, calibration and out-of-distribution rates.
- Register stopping rules for any service impact, unexpected result, observed customer harm, scope disagreement or failed rollback. A safety stop remains a recorded trial outcome; never remove it from denominators.

## Evidence required before supporting external effectiveness

The following cannot be replaced by a screenshot, synthetic fixture, company website, GitHub traffic or a self-authored claim:

| Evidence | Independent verification needed |
|---|---|
| Real operator site and asset | Authorized contact, signed scope and verifiable operator-controlled identifiers |
| Eligibility and active vulnerability | Specific component/configuration, independent behavior/scan proof and authenticated evidence provenance |
| Safety authorization | Change ticket, permitted actions, budgets, rollback procedure and human approval where required |
| Frozen decision policy | Immutable trained model fingerprint/prompt, declared feature set and holdout plan |
| Real action execution | Operator-owned change records, accepted commands and measured outcomes, not just HTTP success |
| Post-remediation security | Fresh independent checks from different trust paths, negative/conflicting results preserved |
| Operational continuity | End-user/service-level latency, error rates, throughput, availability and disruption during/after action |
| Independent evaluator | Identity, methodology, case sampling, signed results and rights to cite sanitized evidence publicly |
| Generalization | Truly separate organizations, systems, incidents and fault families with held-out evaluation |

## Practical sequencing

**Stage 0**: Disposable open-source lab (current work). Complete actual published-CVE before/after behavior pilot, and verify a permitted action. This is **lab evidence only**.

**Stage 1**: Independently reviewed testbed or nonproduction environment administered by an external operator. The operator supplies a separate evaluator and records all candidate decisions and measured effects, including abstentions.

**Stage 2**: Authorized read-only shadow mode at a real U.S. critical-infrastructure operator. Record AI recommendations without giving PREDICT-SHIELD any control-plane mutation rights. Retain independent evidence and explicit false-positive analysis.

**Stage 3**: Only if prior gates pass, operator-approved bounded changes to a designated non-critical service within an approved maintenance window. Conduct separate independent security and continuity verification; automatically halt or roll back on limits.

**Stage 4**: Prospective external replication at independent sites/incident families. Only then consider a statistically supported claim about generalizable operational effectiveness.

## Current field-study truth ledger

- External operators with documented agreement: **0 confirmed**
- Authorized production critical-infrastructure actions: **0 confirmed**
- Independently verified production mitigations: **0 confirmed**
- Quantified production legitimate-service disruption: **UNKNOWN**
- Generalized U.S. critical-infrastructure effectiveness: **NOT ESTABLISHED**

Update these only from actual signed operator/assessor evidence and links to private-access records or permitted redacted summaries. **Do not substitute Docker/virtual network observations for operator field trials.**
