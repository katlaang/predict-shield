# Opt-in policy-gated autonomous remediation in the isolated Java/Kafka lab

PREDICT-SHIELD now has an **opt-in controlled laboratory execution path** from a locally SHA-256-validated trained model to an independently gated action and post-action oracle observation.

Use the `lab_ai_decision.py` CLI described in `LAB_TRAINED_AI_RECOMMENDATION.md`, and add `--execute-lab` while running the authorized disposable Compose lab. Set separate `LAB_CONTROL_TOKEN` and `LAB_ORACLE_TOKEN`; never publish them. **Only** `resync_policy` and `gateway_restrict` are eligible for automatic mutation in this initial runner. `restart_enforcer` is never automatically dispatched, and `monitor_only` has no mutation. A previously abstained or policy-rejected decision cannot be dispatched.

The post-action evidence comes from the **separate existing laboratory oracle process** plus gateway HTTP probes. The report distinguishes `VERIFIED_LAB_ONLY`, `NOT_VERIFIED_LAB_ONLY`, and `INDETERMINATE`; a POST acknowledgment alone never implies verification. Counters are retained, including non-denial and unknown HTTP results.

The caller's `--remaining-lab-budget` is an **explicit experimental allowance**, not a measured production SLO. This code is not authorized for production use, lacks an operational proof of budget availability, and does not establish that AI is superior to deterministic baselines. A genuine run through this CLI with a trained artifact and measured pre-action records still needs physical CI evidence before describing it as an executed AI-driven pilot. Do not claim any effect on U.S. infrastructure.
