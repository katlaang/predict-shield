# Experiment B: mechanism-based authorization propagation laboratory

This experimental replacement uses separate Java 25 / Spring Boot enforcement processes, an authoritative revision publisher, a real Kafka-compatible Redpanda broker, a gateway, and a distinct oracle observer. A fourth enforcement process is omitted from the normal gateway but included in the oracle inventory, exposing false assurance from gateway-only probing. The older single-JVM fixture remains intact for compatibility, but its predetermined outcome formulas must not be used to claim AI effectiveness.

## Technical architecture

- Authority: publishes revisioned authorization decisions over the Kafka topic lab-policy.
- Enforcer A, B, C and hidden enforcer: independent JVMs, each with a local policy cache, actual TTL refresh over HTTP, and a separate Kafka consumer group.
- Consumer faults: loss, delayed delivery with jitter, duplicated delivery, and reordering with monotonic revision protection.
- Gateway: real round-robin forwarding among A/B/C; the hidden enforcer is deliberately omitted to test scope completeness. A restriction changes actual request handling, including legitimate traffic.
- Oracle: independently deployed process querying authoritative state, each enforcer's private administrative state and a separate active HTTP probe path.
- Pilot: produces measured HTTP status/latency during concurrent traffic, exercises four candidate actions, and triggers silent cache regression.

## Run on a disposable local Docker host

Requirements: Docker Compose, Python 3.12, Java 25-capable Docker images.

From this directory:

~~~bash
export LAB_CONTROL_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export LAB_ORACLE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export LAB_INTERNAL_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
docker compose up --build -d
python pilot.py --execute-lab --rps 30 --output reports/mechanism-pilot.json
docker compose down --remove-orphans --volumes
~~~

The pilot is explicitly opt-in. The only host-exposed ports bind to 127.0.0.1.

## What must not be claimed

This is a first mechanism-based pilot, not a trained AI system, not a 1,200-trial comparative study, and not a validated production security solution. The model is not yet wired into the decision gate or selector. The oracle uses a known inventory and administrative cache reports corroborated by active probes; it does not cryptographically attest an honest enforcement point. Fault injection is in Kafka consumers rather than in a network-layer Toxiproxy. The current physical topology is four enforcement JVMs, three gateway-visible and one intentionally omitted; a 2-8 variable topology requires a dynamic Compose launcher.

An observed zero request failure count does not establish zero impact, because a load test may miss a transient restart. Every metric must preserve denominators, observation windows and actual request rates.

## Test and Javadoc conventions

GitHub Actions builds the Java code, launches broker and separate services, exercises loss and resynchronization, runs four measured actions and checks a silent post-remediation cache regression. Every declared Java class, constructor and method has extensive Javadoc explaining inputs, return semantics, fault model, safety boundary and limitations.

Existing manifest and training code should only be adapted after the mechanism and independent observer CI checks pass. Do not run the full collection against the previous formula-based fixture.

The omitted-target scenario deliberately loses a policy event in the hidden JVM, checks that gateway requests still deny access, and confirms that the independent oracle detects an unremediated in-scope target. Gateway-only clean results are not sufficient to declare global VERIFIED.


## Reproducible mechanism-lab data collection (new milestone)

The earlier 100 x 4 x 3 manifest under `experiment-b/generated` is specific
to the **deprecated formula fixture** and must not be used to train a model
for this laboratory. A new mechanism-aware manifest accounts for the actual
four-JVM topology and supports only the implemented fault modes.

### Generate the preregistered plan

~~~bash
python plan.py --output plans/mechanism --seed 20261110
~~~

This produces **100 configuration groups** (60 train, 20 calibration,
20 held-out test), four named actions and three repeats per action, for
**1,200 planned trials**. The plan records no oracle labels, measurements
or completed actions. The initial experiment varies actual cache TTL,
Kafka consumer fault mode/target, event-delay setting and requested load.
The physical node count stays four: three gateway-visible and one deliberately
omitted from gateway routing. This is not a 2-8 node topology study.

### Collect actual HTTP measurements, without synthetic output labels

With Docker Compose already running, and the three distinct disposable
credentials set as described above:

~~~bash
python collect.py --execute-lab \
    --manifest plans/mechanism \
    --output results/mechanism \
    --limit 4
~~~

Four paired action trials will be executed against the real JVMs, with
a fresh authority reset and consumer fault configuration for each one.
Results are written separately as:

- `results/mechanism/pre_action/`: model-eligible pre-action configuration
  and gateway observations, **without** the oracle
- `results/mechanism/verification/`: post-action gateway outcomes,
  deliberately unable to claim full-scope VERIFIED without inventory proof
- `results/mechanism/operations/`: counted actual external HTTP failures,
  attempted requests, latency and observed request rate
- `results/mechanism/oracle/`: independently observed full target inventory,
  per-target direct probes and private cache/authority state, protected with
  owner-only file permissions

The collector is **not** allowed to fill missing measurements, infer the
oracle truth from gateway results or overwrite any previously executed run ID.
The full 1,200-trial campaign requires an explicit `--limit 1200` and
supervised review of outcomes, resource use and contamination from delayed
events. It has not been run merely because the manifest exists. To resume a
valid stopped campaign, select a subsequent `--offset`, after inspecting
partial records.

### Train only on completed measured records

Install the research ML dependencies declared at
`../requirements-ml.txt`, then run:

~~~bash
python -m pip install -r ../requirements-ml.txt
python train.py \
    --records results/mechanism \
    --report reports/mechanism-evaluation.json \
    --export-model reports/mechanism-model.joblib
~~~

The trainer refuses incomplete or mismatched 1,200-record collections,
cross-partition configuration groups, unknown oracle provenance and missing
actual request counts. Model inputs exclude oracle state and post-action
measurements. Results compare an initial random forest with a competitive
train-only hierarchical lookup baseline keyed by action, fault mode and
fault target. The 20 calibration groups estimate the exploratory
split-conformal prediction radius; 20 held-out configuration groups
evaluate prediction error and marginal coverage.

A saved model is a **local, trusted, pickle-based artifact**. Never load a
model bundle downloaded from an untrusted source. The trained bundle records
the fit-group fingerprint, calibration radius, feature schema and observed
training feature ranges.

The inference adapter in `model_adapter.py` converts trained estimates into
typed `ActionPrediction` records. The existing
`engine/predict_shield/selector.py` applies the independent policy gate and
ranks actions, but the lab still lacks verified two-source inventory closure
and a trusted error-budget provider. It therefore must abstain rather than
automatically executing a model-selected action. Connecting actual authorized
execution is a later separately tested milestone.

### Reproducibility and limitations

- Seeded configurations do not make asynchronous Kafka jitter, operating
  system scheduling or restart latency deterministic. Preserve measured
  timestamps, observed load and repeated runs rather than claiming identical
  execution.
- A late scheduled consumer callback from an earlier trial may contaminate a
  later replay. The current pilot uses reset/revision ordering; an explicit
  epoch barrier and quiescence audit are still required for publishable
  repeated-trial comparisons.
- Strong performance on one mechanism-lab topology is not proof of usefulness
  in a real operator network or a new fault family.
- The output labels derive from real HTTP observations of a controlled
  testbed. They do not imply real-world exploitation probability, autonomous
  authorization or production-safe policy changes.

From repository root, run all Python contract tests with:

~~~bash
PYTHONPATH=engine python -m unittest discover \
  -s experiment-b/mechanism-lab -p "test_*.py" -v
~~~

**Do not publish model performance claims before the entire measured dataset,
independent oracle reliability and fair competing baselines have been reviewed.**
