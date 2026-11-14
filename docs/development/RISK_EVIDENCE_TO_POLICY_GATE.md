# Discovered asset evidence to AI policy gate

The new `risk_evidence` module connects the SBOM/advisory context produced by `asset_risk_context` to the existing typed `EvidenceSnapshot` consumed by the AI decision selector.

**Safety boundary:** The asset risk-context schema contains advisory **candidates** and unauthenticated source provenance. It cannot establish a verified exploitable vulnerability, trusted independence or complete inventory scope. Therefore this integration creates a structured `ESCALATE_FOR_EVIDENCE` result with `trusted=False` and `scope_complete=False`. The existing deterministic action gate must abstain, regardless of how optimistic a model prediction might be. Synthetic tests exercise that exact end-to-end boundary.

This is incremental integration, not functioning end-to-end automated remediation. To make a case eligible for policy-constrained selection, a separately authenticated source attestation, asset scope validation, applicability examination, real service error-budget observation and calibrated model inference are required. No code in this increment upgrades these claims automatically. The context SHA-256 detects accidental JSON modification only and is not a source signature.

Future research: add observed dependency closure and validated exposure evidence, then train a risk estimator using pre-action inputs with group- and time-separated outcome labels. Preserve negative and UNKNOWN outcomes and compare learned ranking against strong deterministic baselines.
