# Experiment B: mechanism-based authorization propagation laboratory

Separate Java 25 / Spring Boot enforcement processes, an authoritative revision publisher, a real Kafka-compatible Redpanda broker, a gateway and a distinct oracle observer. A fourth enforcement process can be omitted from gateway routing while remaining in the separate oracle inventory, exposing false assurance from gateway-only probing. The older single-JVM fixture remains for compatibility; its predetermined outcome formulas must not be used as evidence of anything about the AI.

## Technical architecture

- Authority: publishes revisioned authorization decisions over the Kafka topic lab-policy.
- Enforcer A, B, C and hidden enforcer: independent JVMs, each with a local policy cache, actual TTL refresh over HTTP, and a separate Kafka consumer group.
- Consumer faults: loss, delayed delivery with jitter, duplicated delivery, and reordering with monotonic revision protection.
- Gateway: real round-robin forwarding among A/B/C, with an explicit hidden-target routing switch to test complete and incomplete scope. A restriction changes actual request handling, including legitimate traffic.
- Oracle: independently deployed process querying authoritative state, each enforcer's private administrative state and a separate active HTTP probe path.
- Pilot: produces measured HTTP status and latency during concurrent traffic, exercises four candidate actions, and triggers a silent cache regression.

## Run on a disposable local Docker host

Requirements: Docker Compose, Python 3.12, Java 25-capable Docker images.

~~~bash
export LAB_CONTROL_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export LAB_ORACLE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export LAB_INTERNAL_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
docker compose up --build -d
python pilot.py --execute-lab --rps 30 --output reports/mechanism-pilot.json
docker compose down --remove-orphans --volumes
~~~

The pilot is explicitly opt-in. The only host-exposed ports bind to 127.0.0.1.

## Limits

This is a laboratory, not a validated production security solution. The oracle uses a known inventory and administrative cache reports corroborated by active probes; it does not cryptographically attest an honest enforcement point. Fault injection is in Kafka consumers, not in a network-layer proxy. The physical topology is four enforcement JVMs, three or four of them gateway-visible depending on the scenario; a variable 2-8 node topology would need a dynamic Compose launcher.

An observed zero request failure count does not establish zero impact, because a load test may miss a transient restart. Every metric preserves denominators, observation windows and actual request rates.

GitHub Actions builds the Java code, launches the broker and separate services, exercises loss and resynchronization, runs four measured actions and checks a silent post-remediation cache regression. Every declared Java class, constructor and method has Javadoc explaining inputs, return semantics, fault model and safety bounds.

The omitted-target scenario deliberately loses a policy event in the hidden JVM, checks that gateway requests still deny access, and confirms that the independent oracle detects an unremediated in-scope target. Gateway-only clean results are not sufficient for a global VERIFIED.

## Collecting measured action outcomes

`plan.py` generates 100 configuration groups (60 train, 20 calibration, 20 held out), four named actions and three repeats per action. The plan records no oracle labels, measurements or completed actions, and does not count as collected outcomes.

~~~bash
python plan.py --output plans/mechanism --seed 20261110
python collect.py --execute-lab --manifest plans/mechanism --output results/mechanism --limit 4
~~~

Each trial resets the authority and applies a fresh consumer fault. Results are stored as four separate streams:

- `pre_action/`: model-eligible pre-action configuration and gateway observations, without the oracle
- `verification/`: post-action gateway outcomes, VERIFIED only when independent Compose-versus-gateway inventory reconciliation and all observed forwarded deny probes support it
- `operations/`: counted external HTTP failures, attempted requests, latency and observed request rate
- `oracle/`: independently observed full target inventory, per-target direct probes and private cache and authority state, with owner-only file permissions

The collector never fills missing measurements, infers oracle truth from gateway results, or overwrites an executed run ID. Larger collections run through the locked, resumable `campaign.py` in batches of at most 12 trials; `campaign.py --audit` validates record provenance, complete oracle state, request denominators, registered run IDs and the registered splits.

## The learned action model

`train.py` fits a random-forest model of each action's security exposure, path exposure and legitimate-request failures from completed, audited records only:

~~~bash
python -m pip install -r ../requirements-ml.txt
python train.py --records results/mechanism \
    --report reports/mechanism-evaluation.json \
    --export-model reports/mechanism-model.joblib
~~~

Model inputs are operationally observable signals only: cache TTL, intended load, pre-action gateway allow fraction, operator telemetry and the candidate action. Fault mode, fault target and injected delay are experimental metadata, never model features. Calibration uses the maximum observed residual per configuration group to build nominal 90% split-conformal intervals, and the report records held-out prediction error and interval coverage. This does not guarantee conditional safety under distribution shift.

A saved model is a local, trusted, pickle-based artifact; never load a model bundle from an untrusted source. `model_adapter.py` turns the model's estimates into typed `ActionPrediction` records for `engine/predict_shield/selector.py`, which applies the independent policy gate. The gate abstains without verified inventory closure and a trusted error-budget provider; automatic execution stays disabled outside the bounded, opt-in lab runner (`lab_autonomous_execution.py`).

`quality.py` is a read-only data-quality diagnostic: fault-family coverage, configurations per split, repeated-label variation and distinct observed service-health outcomes.

## Trial isolation

The enforcement JVM increments an internal epoch whenever its reset endpoint starts a new trial. Delayed and duplicate Kafka callbacks capture their originating epoch and cannot mutate the next trial's cache. Policy events carry an authority-assigned trial ID, revision and revocation state, so a delayed message from an older trial is rejected even if the broker delivers it after reset, and a reorder trial emits two distinct revisions. An oracle snapshot exposes pending scheduled callbacks and requires the queue to reach quiescence before a new fault is injected. This protects callback execution in the JVM; it does not prove external broker or network quiescence.

## Action semantics and measured outcomes

Resync republishes current policy without disabling the injected consumer fault, so a permanent lost-event consumer is not secretly fixed by resync. Restart exercises actual service downtime and a separate authority HTTP refresh. Gateway restriction can block reachable protected paths while the enforcement control remains stale. Outcomes distinguish complete direct enforcement remediation, observed gateway-path exposure, and legitimate service HTTP failure and latency.

The action window samples protected gateway HTTP responses over time and integrates allowed access into exposure-seconds, recording unknown seconds separately; network errors and unobserved intervals count toward an upper exposure bound, never as safely denied. Failed legitimate requests are measured against a declared lab allowance of 25 requests, which is not a verified operational error budget and cannot authorize execution. Configurations also vary whether a restart is permitted, simulating a change freeze.

Each Java process reports pre-action operator telemetry: cache revision, cache age, processed event count, refresh failures and pending callbacks. These are operational indicators, not fault labels or direct Kafka consumer lag, and a missing feed stays explicitly missing. Node handling time is heterogeneous (A 0 ms, B 15 ms, C 50 ms, hidden node 100 ms); distinct cold-start-time distributions are not implemented. The workload includes authorized users of the same protected operation, so a gateway-wide block causes measurable legitimate failures.

The normal verifier reads deployment inventory from Docker Compose and current gateway routing state. VERIFIED requires exact inventory reconciliation and a forwarded denial observed from every registered process; a missing route or a gateway-generated denial alone is INDETERMINATE. These rules are scoped to the experimental Compose deployment and do not establish production inventory completeness.

The operator telemetry uses the disposable control credential; dedicated least-privilege operator credentials remain a future requirement, and this lab endpoint is not suitable for production exposure.

## Tests

From the repository root:

~~~bash
PYTHONPATH=engine python -m unittest discover -s experiment-b/mechanism-lab -p "test_*.py" -v
~~~
