# Development-only control-plane publication-gap fault

**Status:** Candidate disposable laboratory test, pending CI measurements. Not a frozen confirmatory AI study. This work intentionally does **not** refit the failed learned selector.

## Reason for this new fault

The historical 1,200 independently executed four-action physical trial records (GitHub Actions [44879497946](https://github.com/katlaang/predict-shield/actions/runs/44879497946)) contain 100 configurations and 3 repeats of 4 actions each. A retrospective complete-record count identified:

| Historical condition | Groups | Matched repetitions per action | Resync resolved | Restart resolved | Monitor-only resolved |
| --- | ---: | ---: | ---: | ---: | ---: |
| Persistent lost events | 35 | 105 | 0/105 | 105/105 | 0/105 |
| Persistently paused Kafka consumer | 35 | 105 | 0/105 | 105/105 | 0/105 |
| Short-TTL self-healing loss | 15 | 45 | 45/45 | 45/45 | 45/45 |
| Self-healing delayed event | 15 | 45 | 45/45 | 45/45 | 45/45 |

These figures **do not adjust for disruption**. Restart exceeded the declared 25-failed-request budget in 30/105 persistent-loss and 17/105 paused-consumer replays; some fixed restart actions were prohibited by authorization. A successful post-action exposure label does not automatically mean a policy-compliant success.

**Interpretation:** In those old recordings, every case where resync resolved the exposure was also resolved without any action. No historical case uniquely requires resync. We lack a fair test of choosing resync when it is a useful intervention rather than a no-op.

## New physical development mechanism

The lab authority now supports a mutation-only `POST /control/revoke-withheld`: it writes a new revoked policy revision to its actual durable state but intentionally does **not** send the update to Kafka. This models a **publication-stage** miss, distinct from a persistently paused or broken downstream Kafka consumer.

A separate authenticated `GET /operator/desired-revision` exposes **only the desired revision number**, timestamp and explicit non-oracle classification. It does not return the revocation Boolean, hidden injection type, target private state or post-action result. The distinct `LAB_OBSERVER_TOKEN` authorizes reading this and the separate Kafka Admin offset witness; it does not grant mutation or private oracle access.

The standalone Python observation path combines: desired authority revision metadata, four direct read-only enforcer applied revisions, independently measured Kafka committed backlog, consumer pause/running states and external gateway probes. It fails closed on stale, missing, mismatched or privileged evidence. **Desired revision is operator control-plane metadata, not proof of correct enforced policy.**

### Exploratory physical development test

Two action arms are executed under independently reset state:

1. **Monitor-only:** do not change anything after publication is withheld; measure all four direct-target post-action security outcomes with the separate oracle.
2. **Resynchronization:** publish the desired revision through the ordinary `/control/resync` action; measure the same independent oracle outcome.

Preconditions are observed, not assumed: all four enforcers previously converged to a healthy allowed revision, actual Kafka backlogs are zero, all four operator revisions are exactly one behind the desired revision after withholding, healthy listeners remain running, and external gateway samples demonstrate exposure. The test is invalid if these preconditions do not hold. The post-action verifier is never read before the selected action.

**Expected hypothesis, not a fact until measured:** `monitor_only` leaves the revoked principal exposed; `resync_policy` causes the four enforcers to deny it. If not, retain that negative result and investigate the mechanism.

### What this would and would not establish

If the physical result matches the hypothesis, it demonstrates **one bounded fault family in which resynchronization has a security benefit over doing nothing**. It does not establish any AI model has learned the difference. It does not compare restart and gateway restriction, measure actual legitimate service disruption, quantify accuracy, establish statistical replication or prove operator impact.

This is development data and must never be mixed into an ostensibly untouched confirmatory test after the result is examined. The earlier 1,200 measurements remain historical evidence, with preregistration provenance concerns tracked separately in [issue #188](https://github.com/katlaang/predict-shield/issues/188).

### Next gates

- Repeat the resync-versus-monitor condition across varying independent configurations and seeds, measuring legitimate service impact and timing.
- Add independently distinguishable other fault families (consumer pause, persistent application-level loss, self-healing controls) using the **same pre-action information** for expert rules and AI.
- Document whether a simple expert rule based on desired-versus-applied revisions, broker offsets and listener health already handles this case. If it does, that is a valid baseline, not a failure of the framework.
- Only after the telemetry and fault diversity are established, improve calibration using development/calibration partitions and conduct a new frozen AI-versus-expert confirmatory evaluation.

**This is research-only. No customer production deployment, autonomous authorization or field cybersecurity claim is permitted.**
