# Physical lab gateway inventory reconciliation

This implementation queries the **existing real gateway** `GET /admin/inventory` using the disposable `LAB_CONTROL_TOKEN` and independently queries the Docker runtime for containers belonging to an explicitly specified Compose project. It compares Compose service labels to gateway upstream service names, not incompatible container IDs. A running hidden enforcer omitted by the gateway appears as `runtime_only_services`. Gateway configurations with no running enforcer are `gateway_only_services`.

From `experiment-b/mechanism-lab` with the disposable lab running, set the same `LAB_CONTROL_TOKEN` used to launch the lab, then:

```bash
PYTHONPATH=../../engine python -m predict_shield.lab_gateway_discovery \\
  --project mechanism-lab \\
  --gateway-url http://127.0.0.1:18280/admin/inventory \\
  --output reports/discovery-run-1.json
```

The Compose project name is determined by the actual Compose deployment; use its exact label, not a guessed name. Keep output files private and out of git. The token is never printed.

## Interpretation
- `DRIFT_DETECTED`: source membership differs, as expected for an omitted hidden JVM.
- `RECONCILED_SOURCES`: service names align. This **does not** mean all intended security controls are VERIFIED.
- Security state is **always INDETERMINATE** in this collector. Gateway inventory describes routing configuration, not actual successful forwarding or independently measured deny decisions.
- Reports record the two source identities, timestamps, asset IDs and hashes. Hashing does not authenticate the source or prove completeness. Runtime labels are not cryptographically authenticated.

## Next gate
Run a real localhost Java/Kafka lab discovery trial with hidden route omitted and then included, preserving the pre/post inventory reports and source hashes. Add external request evidence for routed targets, image SBOM-to-asset links and durable inventory history. Do not claim physical validation based on synthetic unit tests.
