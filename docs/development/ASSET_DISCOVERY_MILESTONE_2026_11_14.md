# Read-only asset discovery milestone (November 14, 2026)

This collector is a **first increment**, not a validated full discovery capability. It reports Docker runtime containers through read-only `docker ps` and `docker container inspect`, with explicit ID-matching to a **separately gathered** gateway snapshot. No Docker or production actions are executed. No proof of complete infrastructure scope, cryptographic source independence, true live traffic, vulnerability findings, or a second-source live adapter is claimed.

## Run

From repository root with Python 3.12 and permission to query the local Docker daemon:

```bash
PYTHONPATH=engine python -m predict_shield.asset_discovery --output /tmp/assets-first.json
PYTHONPATH=engine python -m unittest engine.tests.test_asset_discovery -v
```

An optional independently obtained gateway membership snapshot may be supplied:

```json
{
  "schema": "predict-shield/gateway-observation/1",
  "source": "gateway-export:mechanism-lab",
  "collected_at": "2026-11-14T13:00:00Z",
  "observed_container_ids": ["<full-container-id-from-separate-gateway-source>"]
}
```

```bash
PYTHONPATH=engine python -m predict_shield.asset_discovery --gateway-snapshot /path/to/gateway.json --output /tmp/assets-second.json
```

Use a **new output path** for every run. Never fabricate gateway IDs from Docker inspect: that would be a single source disguised as two. A matching snapshot means only `RECONCILED_SOURCES`, **not VERIFIED**. Missing gateway evidence means `INDETERMINATE`. Mismatches mean `DRIFT_DETECTED`. Docker-only inventory is not a proof that an asset does not exist outside Docker.

## Security and limitations

- Docker socket access is sensitive, even when the program only runs read-only commands. Run in an authorized isolated lab, not as a privileged public service.
- Avoid committing actual inventory exports or operational host metadata; they can be sensitive.
- Reports have a SHA-256 digest for accidental alteration detection, not source authentication or an independently anchored signature.
- Image ID is obtained from Docker runtime; **no per-image SBOM is yet generated**.
- Owner and criticality use optional container labels and missing values are explicitly reported.
- Gateway snapshot provenance and freshness are recorded but not authenticated or threshold-validated. Stale snapshots must not support a VERIFIED verdict.
- Identity reconciliation presently uses exact container IDs only. Kubernetes, ephemeral instance aliasing, image-to-SBOM correlation, service dependencies, event streaming, durable storage, and live gateway collectors remain future work.
- The JSON report is a discovery input, not yet integrated with AI prediction, case management, or the independent verifier.

## Follow-on acceptance gates

1. Read-only live gateway adapter with authenticated source identity and freshness limits, without reusing Docker enumeration as gateway evidence.
2. SBOM scan per actual image digest (e.g. Syft), with authenticated provenance, explicit scan errors and image-to-component linkage.
3. Capture event-based changes and reconcile observed routing and Kafka dependencies.
4. Persist versioned snapshots and connect case scope with fail-closed verification and AI risk assessment.
