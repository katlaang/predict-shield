# Independent U.S. critical-service validation protocol

**Status: prepared for operator engagement; no independent field pilot has been completed or verified.**

PREDICT-SHIELD is concerned with strengthening U.S. critical infrastructure. Real Kafka/JVM experiments show mechanisms and operational constraints, but that does **not** prove that an American infrastructure operator experiences lower cyber-risk, fewer interruptions or greater resilience. Infrastructure effectiveness must be studied with organizations operating real relevant services, not inferred from GitHub traffic or hypothetical market size.

## Operator-facing study outline

**Scope:** A sector-independent core framework with an operator-controlled sector-specific connector. A small rural broadband provider, critical cloud/managed-service platform or another U.S. infrastructure operator is a possible partner; none is assumed to have committed. Start in an isolated, consented staging network. Production testing requires separately approved safety, scheduling and rollback governance. No automatic risky action is permitted based solely on a learned prediction.

**Registered configuration:** a learned action-effectiveness predictor behind an independent hard policy gate, using only pre-action inputs, registered eligible actions, an independently measured scope and an independent verification oracle. Actions requiring an offline authority are never eligible. A human responder's after-the-fact knowledge is never used as a model input.

**Primary evidence dimensions:**

| Domain | Observable measurement | Required provenance |
| --- | --- | --- |
| Cybersecurity exposure | Real revoked-operation access-allowed duration, with explicit unknown intervals | External probes plus independently authenticated policy inventory |
| Legitimate service protection | Failed authorized requests / attempted authorized requests and critical-service downtime | Operator telemetry with timestamped request denominators |
| Remediation completeness | Independently observed revoked/allowed state across *all* declared points, not only the gateway | Separate verifier, full inventory and hidden/missing-node accounting |
| False assurance | Count of reports saying VERIFIED when independent full-scope evidence contradicts that | Verifier decision log and independent privileged oracle |
| Recovery | Measured time to verified recovery, including failed/unknown attempts | Event publication, action timestamps, authority state and probe timelines |
| Operational harm | Exceeded error budgets, prohibited action attempted, or service impact | Independent change approval and operator incident record |

**Intervention safety and ethics:** obtain dated operator permission, define allowed fault windows and approved test principals, plan safe shutdown/rollback, set hard disruption limits and escalation. No live customer credentials or protected operational records should enter a public GitHub artifact. Consider operational sensitivities of energy, telecom, health and transportation systems; lab findings cannot be extrapolated between them without evidence.

**Analysis:** register the sample, independent site/configuration unit, fault mix, primary estimand, and uncertainty policy before collecting outcome measurements. Separate train, calibration and test across infrastructure configurations and, preferably, operators. Report all eligible intervention arms, negative cases and unknown outcomes. Use paired group-level uncertainty and avoid counting multiple repeats at one site as independent operators. An initial single-site study is external feasibility evidence, not national generalization.

## Documentary and authentication controls

The repository provides `external_pilot_evidence_audit.py`, which can validate an externally supplied record's structural completeness, measurement arithmetic, provenance hash **format**, and operator/assessor declarations. The required manifest uses **pseudonyms**, source commit, protocol and evidence SHA-256 hashes, two or more independently identified matched conditions, operator consent and safety approvals, and separately measured baseline/framework data.

**The validator cannot authenticate people, approval letters, hashes against unavailable originals, or the factual accuracy of the measurements.** It always returns `STRUCTURALLY_COMPLETE_UNAUTHENTICATED`, `critical_infrastructure_effectiveness_established=false`, and an explicit manual independent-authentication checklist. A claimed assessor name in JSON is not proof of their independence.

Run locally after obtaining actual consented evidence:

```bash
python external_pilot_evidence_audit.py \
  --manifest /secure/external-operator-pilot-manifest.json \
  --output /secure/field-evidence-documentary-audit.json
```

Do not commit raw operator data or evidence letters with signatures, emails or private identifiers to public GitHub. Preserve them through a separately approved restricted evidence process. Unit test fixtures in the repository are **synthetic and must not be cited as operator impact**.

## Claims currently supportable versus not supportable

Supported by the GitHub evidence record: implemented physical Kafka service tests, independently collected lab oracle state, real HTTP exposure/disruption measurements, and a falsifiable AI decision-value comparison protocol.

**Not supported as of this document:** independent third-party infrastructure field validation; quantified national economic benefit; or actual technology adoption at US critical-infrastructure sites. Those remain evidence milestones, not completed accomplishments.
