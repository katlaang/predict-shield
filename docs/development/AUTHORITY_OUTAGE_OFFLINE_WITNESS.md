# Authority outage: pre-outage witness and conservative offline measurements

**Status:** First incremental implementation for issue #36.
It does **not** resolve issue #36, run physical authority-outage trials,
or establish policy enforcement during a disconnected authority.

This module addresses a narrow part of the blocker:
`experiment-b/mechanism-lab/python/offline_authority_witness.py`.

A separately captured policy witness must record a live authority HTTP 200
reading identifying the specific revocation and trial before the outage.
The witness contains the full policy JSON, a canonical policy SHA-256, exact
four-node inventory, timestamp and a canonical witness SHA-256.

**A hash alone is not proof of independent custody or reliable chronology.**
The current module accepts a runner-supplied timestamp and cannot attest the
actual authority identity, a durable commit log, reviewer independence or
physical shutdown. Those conditions still require tested experimental
infrastructure and independent observation.

## While the authority is unreachable

Evaluate four declared *independent direct probe records*, each reporting:
a revoked principal's actual HTTP status and a legitimate principal's actual
HTTP status. Report two bounded fractions:

- Revoked access denied: lower = observed HTTP 403 / 4;
  upper = (observed HTTP 403 + unreachable/unknown) / 4.
- Legitimate access permitted: lower = observed HTTP 200 / 4;
  upper = (observed HTTP 200 + unreachable/unknown) / 4.

Known wrong statuses count as failure, not unknown. Missing nodes or
duplicate nodes fail closed; unknown HTTP responses cannot silently disappear.
The policy source is **not contacted** during the offline bounds calculation.

Regardless of the fraction, the output has
`verification_outcome=INDETERMINATE` and
`authority_truth_current=null`. Even four known good direct probes
cannot justify `VERIFIED` without live policy reconciliation.

The bounds are a **diagnostic pre-registered candidate**, not the final
v3.1 utility function, physical outcome, or evidence of AI action superiority.

## Run targeted tests

```bash
cd experiment-b/mechanism-lab/python
python -m unittest -v test_offline_authority_witness
```

## Outstanding acceptance conditions for issue #36

1. Capture actual immutable, independently privileged pre-outage policy
   evidence and confirm policy revocation is committed before shutdown.
2. Prove a target's missed event occurred using independent physical
   observation, and disable declared mutation services during the outage.
3. Integrate real direct HTTP probes from all four enforcement nodes and
   gateway for revoked and legitimate principals under each physical action.
4. Record action transport failures and censor/unknown outcomes distinctly.
5. Restore the authority after each action in `finally`, independently
   confirm recovery and quiescence before the next trial.
6. Test all four actions and permitted/prohibited restarts; freeze
   evaluation policy before any complete new campaign.
7. Keep full oracle verification unavailable until current authority
   reconciliation resumes.

No model receives witness content through the current implementation.
Future integration must separately enforce this no-leakage boundary.

## Integrated physical direct-probe increment (2026-11-19)

`experiment-b/mechanism-lab/authority_outage_actions.py` now uses the
pre-outage witness and independently sends a revoked-principal and a
legitimate-principal HTTP GET to **each of four Docker enforcement JVMs**
after stopping the policy authority. The requests use synthetic lab
identity headers, not authentication suitable for production. The resulting
raw four-node statuses and conservative fractions are written alongside
the preexisting gateway observations and historical-witness bounds.

The integration is tested by the physical four-action CI workflow in
`.github/workflows/authority-outage-actions.yml`. The unit tests use mocked
HTTP responses. **Only a completed successful physical workflow establishes
that Docker stop/restart and the eight real direct HTTP requests executed.**
The output is not a final calibrated action-utility measure, an operational
policy guarantee, or a claim of measured AI superiority. Full live-authority
reconciliation remains mandatory after each restoration.
