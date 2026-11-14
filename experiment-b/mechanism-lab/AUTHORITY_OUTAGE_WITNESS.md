# Authority-outage policy witness: physical bounded-observation milestone

This experimental mechanism is designed to resolve one portion of [issue #36](https://github.com/katlaang/predict-shield/issues/36) without inventing policy truth when the external authority is offline.

A real test first registers an isolated policy trial, injects missed Kafka revocation at enforcer-b and independently reads the **live desired revoked revision** through the privileged oracle while the authority remains online. It commits the exact trial identifier, revision, observation time and declared four-node inventory to a SHA-256 digest. A historical witness is not a guarantee that the desired state remains unchanged after the service stops.

The test then **physically stops the Docker authority**, queries all four enforcement nodes through the separate oracle and reports direct HTTP allow/deny/unknown counts against the historical witness. A node with a stale trial ID, missing observation or inconsistent cache report counts as UNKNOWN, never as a denial. Observed allow fraction is bounded by:

`lower = observed_allow / 4`, `upper = (observed_allow + unknown) / 4`.

Even if every enforcer returns a denial, the output remains `authority_truth_status=UNKNOWN` and `verification_status=INDETERMINATE` until a live authoritative comparison is possible. This is an *observed historical-policy discrepancy bound*, not calibrated exploitation probability, complete service availability or a legitimate successor to the existing v3 oracle.

The test restores the authority in `finally` and checks readiness. It retains only the witness hash, timestamp and sanitized counts as a public artifact, not raw oracle/cache states, tokens or trial IDs.

## Scope and remaining blockers

This is **not** the six-family, four-action, two-repeat v3.1 feasibility pilot. It does not yet measure action-specific service disruption and time-integrated exposure under an outage, guarantee atomic independently attested desired-policy persistence, verify authorized-user behavior for every node or produce a validated utility outcome for ranking. Those requirements remain in issue #36. No positive AI selection or critical-infrastructure field effectiveness claim is justified.

Run from the disposable lab only:

```bash
python authority_outage_witness_smoke.py --execute-lab --output reports/authority-witness.json
```

Public GitHub Actions workflow: `.github/workflows/authority-outage-witness.yml`.
