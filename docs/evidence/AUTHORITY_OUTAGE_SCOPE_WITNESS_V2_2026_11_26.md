# Authority outage witness: exact-scope and denial-evidence integrity (2026-11-26)

**Status:** [PR #180](https://github.com/katlaang/predict-shield/pull/180) merged, and [physical witness workflow #45920913347](https://github.com/katlaang/predict-shield/actions/runs/45920913347) completed successfully: unit tests, actual Docker authority outage observation, conservative bounds checks, and cleanup passed. The measured outcomes during a stopped authority remain **INDETERMINATE**, not VERIFIED. This is a disposable Docker laboratory experiment, not a production control or a U.S. critical-infrastructure pilot.

## Why this was needed

Existing `authority_outage_witness.py` correctly retained `INDETERMINATE` while the authority was offline. However, its witness commitment covered only the number of observed nodes, not their exact identities, and an HTTP 403 with a matching trial ID was treated as an observed denial even if local node metadata said the policy was not revoked. Those are provenance/evidence risks.

## Changes

1. Freeze the exact four source-observed target node identifiers, sorted, inside the pre-outage witness commitment. On the offline reading, reject missing, extra, replaced, duplicate or differently identified targets rather than scoring their HTTP responses.
2. Before scoring an offline observation, recompute the witness SHA256 over the bound trial, revision, revocation flag, observation timestamp and exact source-observed inventory. An altered in-memory witness no longer passes.
3. Treat an HTTP 403 accompanied by local policy metadata saying `revoked=false` as **UNKNOWN**, not proof of enforcement of the witnessed revoked rule. Inconsistent, missing or stale-trial metadata also remains UNKNOWN.
4. Maintain the strict prohibition on `VERIFIED` while the authoritative source is offline. The schema of new offline reports advances to `predict-shield/authority-outage-observation/2`, preserving earlier historical records unchanged.
5. Extend deterministic tests for swapped target IDs, tampered commitments, duplicate IDs, contradiction between 403 and node policy, and unchanged fail-closed behavior.

## Acceptance and remaining limitations

- **Confirmed for this implementation:** software unit tests and the real Docker authority outage witness smoke passed in [run 45920913347](https://github.com/katlaang/predict-shield/actions/runs/45920913347).
- This witness digest detects unintended modification of one in-memory record. It **does not authenticate** a malicious source or prove independently managed custody. The independent source still needs to be trusted and scoped.
- A 403 corroborated by the node's own revoked metadata is only an observed local denial, **not** an independently verified authoritative policy verdict.
- Unknown responses retain upper/lower bounds rather than optimistic success.
- The four-action stopped-authority offline utility, repeated physical campaigns, general network enforcement, operator evaluation and AI action superiority remain unresolved under [issue #36](https://github.com/katlaang/predict-shield/issues/36).
