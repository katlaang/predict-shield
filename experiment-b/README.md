# Experiment B: inconsistent access-control enforcement

**Status: experimental source and fixtures, not yet a validated integrated experiment.**

This self-contained localhost-only laboratory uses two instances of the same Java 25 / Spring Boot application with different initial authorization states:
- service-a at 127.0.0.1:18081 starts correct: HTTP 403 for a revoked operation.
- service-b at 127.0.0.1:18082 intentionally starts stale: HTTP 200 for that same operation.
- The independent Python probe detects mismatched enforcement. It may request a lab-only revocation after explicit opt-in, and probes both endpoints again independently of any action acknowledgment.

There is no real principal identity, event bus, propagation delay, simulated partitions, or runtime policy authority yet. This is a first-stage control-drift fixture, not a production security system. The lab is unsuitable for deployment beyond localhost.

## Prerequisites
Docker Engine with Docker Compose, with support for building Java 25 images; Python 3.10+.

## Run
From `experiment-b`:

```bash
export LAB_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
docker compose up --build -d
python run.py --output b-readonly.json
python run.py --correct-lab --output b-corrected.json
docker compose down
```

The initial read-only run should classify the stale authorization state as NOT VERIFIED. The opt-in lab correction should request revocation only from a service returning HTTP 200, then independently probe again. A failed correction is not accepted as proof.

## Unit tests
```bash
python -m unittest discover -s experiment-b -p "test_*.py" -v
```
Tests are mock-transport unit tests and do not prove the Java lab compiles or runs. Integration test evidence must be recorded separately.

## Research controls and limitations
- Define both services' expected denial behavior before running tests. See `fixtures/expected-policy.json`.
- Keep the disposable lab token private. The token gates the **lab mutation endpoint**, not an enterprise authorization control.
- All services bind to the loopback interface; do not expose this intentionally flawed testbed.
- Reports include observations, action attempts, and post-action observations. They are *not* cryptographically authenticated.
- The next checkpoint must add real fault injection, explicit policy evaluation, baseline comparisons, audit persistence, repeated test runs, and service-disruption measurements.
