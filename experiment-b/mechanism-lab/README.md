# Experiment B: mechanism-based authorization propagation laboratory

This experimental replacement uses separate Java 25 / Spring Boot enforcement processes, an authoritative revision publisher, a real Kafka-compatible Redpanda broker, a gateway, and a distinct oracle observer. The older single-JVM fixture remains intact for compatibility, but its predetermined outcome formulas must not be used to claim AI effectiveness.

## Technical architecture

- Authority: publishes revisioned authorization decisions over the Kafka topic lab-policy.
- Enforcer A, B, C: independent JVMs, each with a local policy cache, actual TTL refresh over HTTP, and a separate Kafka consumer group.
- Consumer faults: loss, delayed delivery with jitter, duplicated delivery, and reordering with monotonic revision protection.
- Gateway: real round-robin forwarding; a gateway restriction changes actual request handling, including legitimate traffic.
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

This is a first mechanism-based pilot, not a trained AI system, not a 1,200-trial comparative study, and not a validated production security solution. The model is not yet wired into the decision gate or selector. The oracle uses a known inventory and administrative cache reports corroborated by active probes; it does not cryptographically attest an honest enforcement point. Fault injection is in Kafka consumers rather than in a network-layer Toxiproxy. The physical topology is three enforcement JVMs; a 2-8 variable topology requires a separate dynamic Compose launcher.

An observed zero request failure count does not establish zero impact, because a load test may miss a transient restart. Every metric must preserve denominators, observation windows and actual request rates.

## Test and Javadoc conventions

GitHub Actions builds the Java code, launches broker and separate services, exercises loss and resynchronization, runs four measured actions and checks a silent post-remediation cache regression. Every declared Java class, constructor and method has extensive Javadoc explaining inputs, return semantics, fault model, safety boundary and limitations.

Existing manifest and training code should only be adapted after the mechanism and independent observer CI checks pass. Do not run the full collection against the previous formula-based fixture.
