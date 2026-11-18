# Physically injected external authority outage (experimental smoke)

**Status:** opt-in mechanism check for Experiment B v3.1, not a simulated optimal-action label.

The existing mechanism CI already checks persistent consumer event loss. This additional experiment stops the **actual Docker Compose authority process** after the disposable lab is ready, observes that the authority's HTTP health endpoint becomes unavailable, tries an actual resync request (which must not publish), restarts **enforcer-b** locally, and observes that the authority remains unavailable. It then starts the authority in a `finally` cleanup and waits for full lab readiness. A stop/start failure fails CI.

## Command

From `experiment-b/mechanism-lab` with disposable credentials and Compose services running:

```bash
python physical_faults.py --execute-lab --output reports/authority-outage.json
```

No production host is supported by the fixed service allowlist and hardcoded localhost target URLs. This code assumes the repository's disposable Compose configuration is used. `--execute-lab` is compulsory.

## Evidence and limitations

The report states **only** directly observable properties: baseline authority HTTP availability, resync HTTP status, JVM restart readiness time, and post-restart authority availability. It does not claim that the enforcement caches are remediated, that the authoritative service remains unavailable throughout a longer monitoring window, or that an action improves risk. No model is trained.

The workflow calls this test before the v3 40-replay pilot after restoring the original authority, so the historical v3 protocol and associated raw data schema remain unmodified.

## Next physical and scientific gates

1. Add **consumer-only pause/crash** using the actual listener container lifecycle, while preserving the enforcer HTTP process; a whole JVM pause is not a valid consumer-only fault.
2. Observe independent current authority revision, each enforcement point's live authorization response and resilience after intervention, with explicit unknown status when the authority is down.
3. Define initial state and recovery windows for every persistent fault; record counterfactual action effects under same scenario groups.
4. Update the v3.1 plan to 150 configurations × 4 actions × 2 repeats only **after** the fault-mechanism tests are verified. Freeze and tag v3.1 before scored full-campaign evidence.
5. Keep v3's exploratory pilot and the v3.1 amendment rationale visible, including losses or inconclusive results.

## Authority-unavailable oracle semantics

The physically executed authority-outage CI now queries the separate oracle **while authority remains stopped**, after a local enforcer restart. It requires `authority_truth_available=false`, `inventory_complete=false`, and `all_revoked_access_denied=null`. It retains `direct_target_observations_complete` independently so observed HTTP evidence is not lost merely because desired policy is unknowable.

This is a fail-closed distinction. A new collector must define a separately witnessed pre-outage policy, temporal bounds and conservative handling of unknown outcomes before scoring actions under an outage. See issue #36.
