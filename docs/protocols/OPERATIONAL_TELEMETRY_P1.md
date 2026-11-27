# P1 operational telemetry, data governance and external validation

**Status:** publicly documented sources identified; licenses, raw data, labels, ingestion and field consent are **not independently verified here**. No public-data experiment has been run by this protocol.

## Public sources to investigate
| Source | Official primary link | Potential question | Important limits / permission gate |
| --- | --- | --- | --- |
| UGR'16 | https://nesg.ugr.es/nesg-ugr16/ | Does a model generalize to historical ISP NetFlow under traffic variation? | Real ISP collection from 2016. Attack periods are not complete per-flow truth; original site does not clearly specify unrestricted commercial/redistribution rights. Confirm allowed use before ingestion. |
| LANL multi-source cyber events | https://csr.lanl.gov/data/cyber1/ | Can AI correlate identity, process, DNS and flow behavior and identify known red-team periods? | Historical anonymized enterprise events; red-team positives are partial truth and all other events must not be assumed benign. Confirm publisher access and citation/terms. |
| MAWILab | https://www.fukuda-lab.org/mawilab/ | What anomalies recur or drift on Internet-backbone traces? | Model-generated anomaly annotations are not independent successful-attack labels; original archive usage and provenance require confirmation. |

### Before data use
1. Verify official publisher, direct download link, user/access terms, intended academic/commercial rights and any redistribution restrictions. Keep approval receipt. No downloading if rights ambiguous.
2. Pin publication/version/size/SHA-256; verify the actual bytes before parsing. Do not put raw flows or credentials in public repository or GitHub Action artifacts.
3. Document time window, capture point, traffic sampling method, ground-truth type and missingness (including whether negative class is genuinely labeled). Keep UNKNOWN where unsupported.
4. Split by host/campaign/session/site/day as appropriate, never a random event-level split that leaks identical activity across train/test. Ensure independent calibration and final test.
5. Report model hash, input schema, event denominators, absolute false alarms, per-host-day alarms when exposure is observed, latency, drift, and independently reviewed case outcomes.
6. A real-data dataset result is **not** an authorized U.S. critical-infrastructure field pilot.

## Partner and field path (external authority required)
- Potential industry outreach: [WISPA](https://www.wispa.org/), individual U.S. broadband operators; contact **not yet sent**, participation **not granted**.
- Research testbed: [NSF FABRIC](https://www.whatisfabric.net/use-fabric/get-started); registration/project approval needed. Not an operator field site.
- Existing [critical-infrastructure field protocol](../evidence/EXTERNAL_US_CRITICAL_INFRA_FIELD_VALIDATION_PROTOCOL.md) and [issue #129](https://github.com/katlaang/predict-shield/issues/129) remain governing. Operator and independent assessor must separately sign scope, authorize read-only telemetry, enforce restricted retention and independently verify signed results.
- **Current independent operator count: 0 confirmed.** No production remediation permission.

## Example initial engagement request
Ask a prospective authorized operator only for a confidential discussion of a read-only, scoped shadow evaluation. No exploit traffic or production actuator credentials. Propose a brief data availability review (which events can be supplied, privacy filters, retention, nonproduction sandbox), independent labeling of a small sample and assessor-held audit evidence. This is an invitation concept, not a sent message or consent.
