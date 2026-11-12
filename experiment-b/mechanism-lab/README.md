# Experiment B: mechanism-based authorization propagation laboratory

This experimental replacement uses separate Java 25 / Spring Boot enforcement processes, an authoritative revision publisher, a real Kafka-compatible Redpanda broker, a gateway, and a distinct oracle observer. A fourth enforcement process can be omitted from gateway routing while remaining in the separate oracle inventory, exposing false assurance from gateway-only probing. The older single-JVM fixture remains intact for compatibility, but its predetermined outcome formulas must not be used to claim AI effectiveness.

## Technical architecture

- Authority: publishes revisioned authorization decisions over the Kafka topic lab-policy.
- Enforcer A, B, C and hidden enforcer: independent JVMs, each with a local policy cache, actual TTL refresh over HTTP, and a separate Kafka consumer group.
- Consumer faults: loss, delayed delivery with jitter, duplicated delivery, and reordering with monotonic revision protection.
- Gateway: real round-robin forwarding among A/B/C, with an explicit hidden-target routing switch to test complete and incomplete scope. A restriction changes actual request handling, including legitimate traffic.
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

This is a first mechanism-based pilot, not a trained AI system, not a 1,200-trial comparative study, and not a validated production security solution. The model is not yet wired into the decision gate or selector. The oracle uses a known inventory and administrative cache reports corroborated by active probes; it does not cryptographically attest an honest enforcement point. Fault injection is in Kafka consumers rather than in a network-layer Toxiproxy. The current physical topology is four enforcement JVMs, three or four gateway-visible depending on the registered experimental scenario; a 2-8 variable topology requires a dynamic Compose launcher.

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
The physical node count stays four; full-routing and omitted-target conditions are independently assigned across fault families. This is not a 2-8 node topology study.

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
  able to return VERIFIED only when independent Compose-vs-gateway inventory reconciliation and all observed forwarded deny probes support it
- `results/mechanism/operations/`: counted actual external HTTP failures,
  attempted requests, latency and observed request rate
- `results/mechanism/oracle/`: independently observed full target inventory,
  per-target direct probes and private cache/authority state, protected with
  owner-only file permissions

The collector is **not** allowed to fill missing measurements, infer the
oracle truth from gateway results or overwrite any previously executed run ID.
The full 1,200-trial campaign requires supervised batches of at most 12 actual trials through the locked, resumable campaign runner. The plan alone does not count as collected outcomes. It has not been run merely because the manifest exists. To resume a
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


## Campaign integrity, comparison, and leakage controls

The campaign is not considered complete merely because the planner created
1,200 run IDs. Only independently measured Kafka/JVM runs with four matching
record streams count as complete. A read-only audit now validates record
provenance, complete oracle state, observed HTTP request denominators,
registered run IDs, and the exact pre-registered configuration splits.

~~~bash
python plan.py --output plans/mechanism
python campaign.py --audit \
  --plan plans/mechanism --records results/mechanism
~~~

To execute at most four additional real trials in an isolated Docker lab,
with the three distinct disposable credentials configured:

~~~bash
python campaign.py --execute-lab \
  --plan plans/mechanism --records results/mechanism \
  --max-trials 4 --resume
~~~

The batch command holds an exclusive local lock and pins a SHA-256 digest of
the registered plan. It refuses partial, invalid, mismatched or unexpected
records, and cannot execute more than 12 trials in one invocation. A failed
trial must be investigated; a resumed run never silently overwrites
incomplete evidence. This does not implement automatic cloud scheduling
or certify that a full campaign has taken place.

### Experimental leakage correction

Fault mode, fault target and deliberately injected event delay are now stored
as **experimental metadata**, not deployable model features. The learned
action-effectiveness model uses only registered, operationally observable
inputs: cache TTL, intended load, pre-action gateway allow fraction, and
candidate action. Deliberately hidden experimental conditions remain
available for post-hoc stratification and for a clearly labeled *privileged*
diagnostic lookup, not for an operational model comparison.

Calibration now uses the *maximum observed residual per operating
configuration* before constructing nominal 90% split-conformal intervals.
The 20 calibration configurations, rather than the 240 correlated action
replays, form the independent calibration units. The held-out report also
records the fraction of entire test configurations covered by the intervals.
This does not guarantee conditional safety under a distribution shift.

The training report distinguishes the comparable action-only lookup
baseline from the privileged fault/target lookup. A model that outperforms
only the action-only baseline has not established superiority over a
stronger operationally informed risk heuristic or fixed playbook.

### Paired outcome comparison

After a **fully measured and reviewed** collection:

~~~bash
python train.py --records results/mechanism \
  --report reports/mechanism-evaluation.json \
  --export-model reports/mechanism-model.joblib

python compare.py --records results/mechanism \
  --partition test --report reports/paired-test-comparison.json
~~~

The comparison reports measured exposure and failed-request differences
for each action relative to monitor-only. It resamples operating
configurations, not individual repeat runs, when constructing exploratory
confidence intervals. Action order is deterministically randomized within
each configuration/repeat to reduce fixed-order bias.

Important remaining threats to experimental validity: delayed Kafka
callbacks may contaminate adjacent runs; request timing and TTL refresh
may change the actual fault before action selection; the operator-only
feature set is limited; randomization does not eliminate all confounding;
the independent oracle still depends partly on admin self-reports and
a fixed inventory; and the system does not yet possess independently
established service error budgets.

**There is no evidence yet that the trained model outperforms deterministic
defensive selection, or that it can be deployed safely.** The existing
model-to-gate-to-selector code can abstain, but automatic action dispatch
remains intentionally disabled.


## Trial epoch isolation (implementation hardening)

The enforcement JVM now increments an internal experiment epoch whenever its
admin reset endpoint starts a new trial. Real delayed and duplicate Kafka
consumer callbacks capture their originating epoch and are prevented from
mutating the next trial's cache after a reset. This closes a previously
uncontrolled cross-trial callback race. Each newly declared Java method and
the focused JUnit suite document the exact synchronization and invalidation
semantics. The Java image build now runs JUnit tests rather than skipping
them. An oracle snapshot can expose pending scheduled callbacks and requires
the scheduled callback queue to reach quiescence before a new policy fault is
injected.

The safeguard protects callback execution in the JVM. It does **not** prove
external broker/network quiescence or eliminate the effects of an unconsumed
Kafka event that arrives after a reset. An independently replayable experiment
will also need a per-trial event envelope with an authoritative event epoch,
a consumer-acknowledgment barrier, and controlled treatment of retries.

## Quality gate before model-effectiveness claims

After all 1,200 trials have actually been collected and independently audited:

~~~bash
python quality.py --records results/mechanism \
  --report reports/mechanism-data-quality.json
~~~

This is a read-only, measured-only diagnostic. It counts fault-family
coverage, configurations per split, repeated-label variation and distinct
observed service-health outcomes. It cannot train a model, manufacture a
label, or prove a generalizable cybersecurity benefit. In particular,
duplicates of a monotonic revision may be correctly ignored by an
idempotent consumer, and one held event does not constitute a meaningful
multi-revision reordering trial. Both situations require explicit analysis
before claiming that the corresponding fault family has been evaluated.

## Persistent faults, broker-scoped trials and scientific comparison

Policy events now carry an authority-assigned trial ID, policy revision and
revocation state. Each process must bind to the current trial. A delayed
message from an older trial cannot be accepted even if it arrives from the
broker after reset. A reorder trial emits two distinct revisions.

Resync republishes current policy without disabling the injected consumer
fault. A permanent lost-event consumer is not secretly fixed by resync.
Restart exercises actual service downtime and a separate authority HTTP
refresh. Gateway restriction can block reachable protected paths without intentionally denying unrelated legitimate work, while the enforcement control remains stale. The outcomes distinguish: (1) complete direct
enforcement-control remediation; (2) observed gateway-path exposure;
and (3) legitimate service HTTP failure/latency.

The normal verifier separately reads deployment inventory from Docker Compose
and current gateway routing state. VERIFIED requires exact inventory
reconciliation and a forwarded denial observed from every registered process.
A missing route or a gateway-generated denial alone is INDETERMINATE.
These rules are scoped to the experimental Compose deployment and do not
establish production inventory completeness.

The laboratory-only 99 percent request-success objective is a declared SLO,
not a known remaining service error budget. It cannot by itself authorize
automatic defensive execution. Model-to-gate integration continues to
abstain without trusted evidence and measured remaining budgets.

Offline decision_eval reports hindsight regret on held-out paired replays
against predeclared fixed playbooks and an engineering rule. Research utility
weights are path exposure 0.50, control exposure 0.25 and service failure
0.25. Oracle outcomes score the hindsight cost, but never enter action
selection inputs. All regret results are descriptive for the laboratory,
not causal or production effectiveness findings.

The GitHub integration workflow performs a bounded 12-trial pilot across
three fault configurations and retains a sanitized per-action outcome table.
Private oracle raw records are deleted before uploading CI artifacts.
The full 1,200-run campaign is still unexecuted.

## Temporal exposure, absolute disruption, and repeated baseline pilot

The experimental action window now samples actual protected gateway HTTP
responses over time. It integrates allowed access into exposure-seconds,
preserves the observed window, and records unknown seconds separately.
Network errors and unobserved initial intervals contribute to an upper
exposure bound; no missing interval is assumed to be safely denied.

Action evaluation uses exposure fraction derived from these time-integrated
upper bounds, independent control remediation, and absolute measured
failed legitimate requests divided by a declared experimental count budget.
The absolute allowance of 25 requests is a research comparator, NOT a
verified remaining operational error budget and cannot authorize execution.

Configurations also vary whether a restart is permitted by a declared
research change policy. All four actions are replayed in the disposable
experiment to measure counterfactual outcomes, but offline decision policies
must exclude restart whenever the simulated change freeze applies. The
gateway mitigation intentionally targets only the compromised protected
route and allows legitimate requests to continue, making it a plausible
fallback where restart is prohibited or excessively disruptive.

The offline regret comparator reports fixed resync, fixed restart with
gateway fallback, fixed gateway, fixed monitor and a preregistered
engineering rule under three independent weightings:
(path, control, disruption) = (0.50, 0.25, 0.25), (0.70, 0.20, 0.10)
and (0.30, 0.20, 0.50). Absolute failure cost is not capped at one.

The revised CI pilot targets four configurations: loss, delay, reorder
and restart-prohibited loss, with two repeats of each of four actions.
It therefore plans 32 ACTUAL experimental replays (four configurations
times two repeats times four actions), plus the existing mechanism smoke
tests. CI will preserve only a sanitized regret report, not raw oracle
or sensitive data. The full 1,200-trial campaign remains unexecuted.

This pilot has only four independently configured environments, so
regret values remain preliminary descriptive statistics. Reordered messages
may be safely ignored under monotonic revision checks; the goal is to
measure the behavior, not force a security failure or invent a model win.
