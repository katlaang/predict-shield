# Unified AI case to existing mechanism laboratory executor

This optional bridge implements the **missing connection between a strictly screened unified vulnerability case plan and the existing experiment-B JVM/Kafka laboratory** without adding another privileged executor.

## Code and enforced boundaries

`experiment-b/mechanism-lab/unified_lab_case_adapter.py` exposes `execute_bound_lab_case()`. It is a lab-only, directly imported function, **not** an HTTP or production API. The default path uses the existing `predict_shield.lab_scope_evidence.collect_live_scope`, `lab_ai_decision.select_lab_defense`, and `lab_autonomous_execution.execute_lab_recommendation`. It never runs arbitrary shell commands from model output.

Before any action, the bridge requires:

- A fresh, individually selected unified AI case whose vulnerability applicability has independent, current affirmative evidence.
- A fixed disposable Compose project ID (`psunified` or `psailab`), distinct disposable control and oracle tokens, and a narrowly bounded lab error allowance.
- Original discovery evidence with a valid content digest, matching the plan's discovery digest.
- The proposed asset's **exact Docker container and immutable image ID** still present in a newly queried, project-scoped runtime inventory. A synthetic or missing asset ID blocks dispatch.
- A fresh, independently reconciled gateway/Docker lab scope whose immutable snapshot ID matches the plan.
- Recalculation of the learned model action predictions and independent action-gate screening from pre-action telemetry, with the selected action and model training fingerprint matching the plan.
- Only `resync_policy` or `gateway_restrict` and a fresh **ELIGIBLE_AUTOMATIC** gate result. Restart, blackholing, unknown actions, bad budgets and any safety abstention fail closed.
- The real existing executor runs the mutation using its own allowlist, then a **separate second oracle read** and gateway probe set assess authorization state.

**Critical distinction:** a revoked authorization request denied across the lab does **not** verify that the asset's software CVE has been remediated. The bridge therefore always retains `vulnerability_remediation_outcome=INDETERMINATE` and reports any positive `authorization_control_outcome` as **VERIFIED_LAB_ONLY**, never as a real CVE fix. It reports service-continuity effects as `UNKNOWN` until independently measured.

## Verification and evidence status

The bridge unit tests use dependency-injected synthetic scope, executor, model-recommendation and oracle observations to exercise both positive and negative control flows. Passing those tests proves **contract wiring only**, not actual physical action execution by this new bridge.

The external applicability `Evidence.independent` flag remains a caller-supplied assertion, not cryptographically authenticated source identity. This path is restricted to disposable local lab environments precisely because production source attestation and signing are not implemented.

Current live physical JVM/Kafka execution evidence and separate actual local Qwen inference results exist independently in the repository. **No combined live Qwen + verified real CVE + trained autonomous mitigation pilot is claimed.** Before such a pilot, instrument actual applicability verification, complete service budgets and a true independent vulnerability remediation oracle.

Run:

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
cd experiment-b/mechanism-lab
PYTHONPATH=../../engine python -m unittest test_unified_lab_case_adapter -v
```
