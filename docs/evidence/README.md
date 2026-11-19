# Evidence record: index

Dated results, lab protocols and design notes behind the capabilities in the main [README](../../README.md). Each result records what was actually executed and observed; a passing lab run shows the described behavior under the stated conditions, not effectiveness on a live operator network.

## Vulnerability remediation with AI-selected fixes

- [Real CVE AI remediation lab protocol](REAL_CVE_AI_REMEDIATION_LAB_PROTOCOL.md): a local model selects an allowlisted fix for a real published CVE (lodash, CVE-2020-8203), and an independent probe verifies it.
- [Measured result of that pilot](MEASURED_REAL_CVE_AI_REMEDIATION_2026_11_15.md).
- [Real local-model inference smoke test](ACTUAL_LOCAL_AI_INFERENCE_SMOKE.md).

## End-to-end response

- [Detect, plan, apply, verify, keep or roll back](END_TO_END_CHAIN.md): the unattended chain against real nginx, Chromium and Suricata, with signed approvals, signed or mTLS detection intake, sandboxed-frame isolation and the live view.

## Measured AI-generated attack detection

- [Real qwen3:4b rule-generation negative result, November 19, 2026](REAL_AI_RULE_SUGGESTION_NEGATIVE_RESULT_2026_11_19.md): all five AI replies were truncated/malformed; zero rules accepted and **zero of 33** selected attack-labelled held-out recordings detected. The independent audit validated the reporting, **not** attack-detection quality. The exact model digest and GitHub Actions artifact are recorded.
- A revised compact, schema-constrained prompt has been implemented, but later reuse of the same evaluated recordings must be marked exploratory. Fresh, independently evaluated attack and benign data are still required for detection-accuracy claims.

## Public test sources

- [Public test sources](PUBLIC_TEST_SOURCES.md): OTRF attack telemetry, cdnjs and jsDelivr files, OSV.dev, Emerging Threats Open, DVWA and real lodash releases, each plugged into the pipeline for testing.

## Policy-governed actions in the mechanism lab

- [Physical lab execution with a trained action model](PHYSICAL_TRAINED_AI_PILOT_PROTOCOL.md).
- [Four physical actions during a policy-authority outage](V31_AUTHORITY_OUTAGE_ACTIONS_2026_11_14.md).
- [Repeated authority-outage pilot](PHYSICAL_OUTAGE_REPEATED_PILOT_2026_11_14.md).
- [Consumer-only Kafka pause, observed](V31_CONSUMER_PHYSICAL_RESULTS_2026_11_14.md).

## ISP and telecom discovery and defense

- [SNMPv3 discovery pilot](ISP_REAL_SNMP_DISCOVERY_PILOT.md).
- [Read-only gNMI over mutual TLS](GNMI_MTLS_PHYSICAL_LAB.md).
- [Simulated access-control defense](ISP_CONTROLLED_DEFENSE_EXPERIMENT.md).
- [Recorded ISP discovery and defense lab evidence](ISP_MEASURED_EVIDENCE_LEDGER_2026_11_14.md).
- [Graph-aware AI risk prediction from physical inputs](PHYSICAL_ISP_GRAPH_AI_RISK.md).
- [Graph-aware risk model contract](TELECOM_GRAPH_RISK_MODEL.md).
- [AI-assisted topology link discovery](TELECOM_AI_LINK_DISCOVERY_PROTOCOL.md).

## Threat intelligence and continuous assurance

- [Threat-intelligence prioritization](THREAT_INTEL_PRIORITIZATION.md).
- [Pinned historical threat-data acquisition](PINNED_HISTORICAL_SOURCES.md) and its [source manifest](data/historical_sources_2026_10.json).
- [Re-verification scheduler](REVERIFICATION_SCHEDULER.md).
- [Verification feedback cycle](VERIFICATION_FEEDBACK_CYCLE.md).

## External validation

- [Independent U.S. critical-service validation protocol](EXTERNAL_PILOT_VALIDATION.md), with its [evidence audit](external_pilot_evidence_audit.py).
- [External critical-infrastructure field validation protocol](EXTERNAL_US_CRITICAL_INFRA_FIELD_VALIDATION_PROTOCOL.md). Prepared; not yet conducted.

## Design history

- [v2.2 implementation specification](PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md), superseded in part by the current engine.
- [Review of a separately supplied v0.3.0 archive](v0.3.0-validation-note.md).
