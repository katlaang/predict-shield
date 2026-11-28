# Prospective defense-choice study: development and confirmation separation

**Status (2026-11-26): protocol and validation tooling only. No new physical tests, calibration, model training, or confirmatory outcomes are claimed by this change.**

## What the existing evidence permits

The historical 1,200-arm campaign is exploratory, and its test partition has been examined. It cannot be reused as a fresh unseen test. The separate withheld-publication development experiment provides one physical resynchronization-positive condition, but not independent generalization or AI superiority.

## Required study sequence

1. **Source-verified development scenarios:** independently reset and physically reproduce (a) withheld desired-policy publication, (b) consumer paused or not running, (c) persistent event loss, and (d) self-healing delay/short TTL. Use multiple independent configuration groups per family, not repetitions of one configuration. Preserve raw pre-action Kafka committed offsets, consumer-group assignments, real listener running/paused status, desired/applied revisions, and gateway outcome. Do not expose fault injection labels or oracle results to the model or expert comparator.
2. **Action measurements:** for each configuration and repeat, reset the lab and independently execute each of monitor-only, policy resynchronization, enforcer restart and gateway restriction where test authority permits. Unapproved physical action arms may be separately characterized in an explicitly isolated development lab, but must never count as eligible deployment decisions. Record authorization state before execution, measured failed legitimate requests, exposure and independently verified post-action direct-target outcomes. Distinguish service availability from verified security remediation.
3. **Calibration on development data only:** assess prediction intervals by held-out *configuration groups*, separately for security outcomes and failed requests. If nominal 90% intervals cover only 70%, fail the reliability screen and document the shortfall. Adjust uncertainty on a separately designated calibration partition only. Do not reuse that calibration partition for final confirmation.
4. **Freeze before confirmation:** pin model SHA-256, feature schema, independent telemetry contract, expert baseline code, utility weights, failure budget and authorization policy, configuration family allocation, sampling/replication count, stopping rules, primary and secondary endpoints and a cryptographic protocol digest. Publish the lock before collecting fresh confirmatory outcomes. The experienced 1,200-arm cohort must be excluded.
5. **Prospective comparisons:** run AI and an explicitly documented strong expert rule on *identical* frozen pre-action evidence. Compare grouped paired cost, direct verified security resolution, failures, budget breaches, prohibited actions, abstentions and escalation. Where uncertainty is high, abstention or escalation is a legitimate outcome, not a model win. Report per-family results. Use group-level uncertainty analysis with a predeclared margin; do not treat repeated episodes in one configuration as independent.
6. **Confirmation gate:** a positive claim requires an independently fresh frozen test, complete source/oracle joins, successful safety screens, predeclared cost improvement with uncertainty support, and no unacceptable worsening of verified security outcomes or disruption. A partial, negative or inconclusive outcome is still reportable evidence.

## Runnable audit

`experiment-b/mechanism-lab/prospective_defense_audit.py` reads two independently preserved JSON files, physical arms and **already frozen** policy decisions. It rejects duplicate/missing action arms, unverified oracle outcomes, mismatched pre-action evidence, invalid restart authorization and incomplete policy comparisons. It outputs descriptive group-level cost and raw security/disruption outcomes. The audit cannot confer preregistration after results are seen, cannot certify the model or control a live executor, and by design never asserts superiority.

This initial audit uses an **illustrative, explicitly provisional** cost of 0.75 × measured exposure plus 0.25 × failed requests / approved allowance. The definitive utility and independent endpoints must be frozen in the signed protocol before confirmatory testing; do not replace the utility used in historical reports without declaring the change. For decision effectiveness, retain separate direct resolution and failure-burden results even if composite cost improves.

## Next blockers

- Real broker offsets and listener health require trustworthy collection, not inferred ground truth.
- More than one independent resynchronization-positive configuration is needed.
- A matched strong expert comparator must be implemented and frozen.
- New configuration groups, a sealed split and independent oracle execution are required.
- No U.S. critical-infrastructure field effectiveness claim is justified.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
