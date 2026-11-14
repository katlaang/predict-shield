# v3.1 first physical paired-action smoke: consumer-only pause

This is a **single condition**, four-action exploratory mechanism smoke, not a configuration-group feasibility gate, a trained AI run, or the preregistered 1,200-action study. It extends the real Spring Kafka multi-JVM lab with a `consumer_paused` fault mode. Unlike the legacy callback-based `loss` fault, the real Kafka listener container is paused and its paused state is checked while the enforcer HTTP handler remains available.

The runner executes `resync_policy`, `restart_enforcer`, `gateway_restrict`, and `monitor_only` through the existing measured `run_case` path. Each arm begins from a clean authority revision, physically pauses the target listener **before** broker publication, observes independent pre/post oracle snapshots, concurrent legitimate-traffic errors, time-integrated gateway exposure, and post-action scope verification. A restart or resynchronization is never scored using an acknowledgement alone.

To prevent contamination, the runner resumes the real listener in `finally`, checks actual resume status, and restarts from a clean trial baseline for the next action. A failed action or failed cleanup fails CI. It never uploads raw oracle snapshots, credentials, or hidden private states.

From a disposable local Compose lab with separate credentials:

```bash
python v31_consumer_action_pilot.py --execute-lab --output reports/v31-consumer-smoke.json
```

The real CI workflow `.github/workflows/v31-consumer-action-smoke.yml` runs the four arms and saves only a sanitized summary. The experiment has **one configuration and no repeated group**, so its observed action costs must **not** be fed to `feasibility_v31.py`. The next milestone is a separate v3.1 pilot with multiple independent predeclared configurations and two physical repeats for all four arms, including an authority-outage collector that can record genuine unknown oracle status while the authority is unavailable. Only complete audited four-stream records are eligible for the independent group-level gate.

The original `PROTOCOL_V3_AI_EVALUATION.md` and its original v3 study manifest are unchanged.
