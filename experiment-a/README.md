# Experiment A: incomplete remediation / false assurance

**Status:** standalone opt-in physical laboratory smoke test, not a trained AI model and not an independent critical-infrastructure pilot.

The test starts the disposable four-JVM Experiment B mechanism lab and injects actual Kafka event loss into the **hidden enforcement node** while removing that node from gateway routing. The gateway-visible enforcement nodes deny revoked access. A corrective restart of the **wrong, gateway-visible enforcer-a** cannot be assumed to remediate the omitted hidden node. An independent full-inventory oracle must still detect unresolved access; the external verifier must not assert `VERIFIED`.

The test exits with a failure if the residual fault spontaneously recovers, because such a result would be inconclusive rather than a demonstrated partial-remediation failure. Raw oracle and token information stays inside disposable CI.

From `experiment-b/mechanism-lab`, with Compose running and disposable tokens set:

```bash
python ../../experiment-a/partial_remediation.py \
  --execute-lab --output reports/experiment-a-partial.json
```

The result is limited to an authorization-drift laboratory mechanism and lacks a calibrated AI strategy. The next task is to compare independent verification with self-reported action success under multiple registered partial-remediation mechanisms, record exact source commits and report false-VERIFIED and indeterminate rates.
