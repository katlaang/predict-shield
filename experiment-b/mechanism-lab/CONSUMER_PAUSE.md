# Physical Kafka consumer-only pause

This proposed v3.1 mechanism differs from the original `loss` callback fault. It calls Spring Kafka's actual listener-container `pause()`, waits for `isContainerPaused()`, and confirms the enforcer's HTTP health endpoint remains available. It publishes an actual authority resync event while paused and verifies the listener's handled-event counter does not advance until resume.

The mutation endpoint is restricted to disposable lab control credentials and supports only pause and resume. The listener resumes in `finally`, and the workflow runs a measured physical smoke before the existing v3 pilot.

## Usage

In the disposable Compose lab with all three credentials configured:

```bash
python consumer_pause_smoke.py --execute-lab --output reports/consumer-pause.json
```

**Limits:** Listener pause state is reported by the node and corroborated by the absence of event handling during a real broker publication. A successful HTTP health check does not guarantee full application availability. This smoke is a mechanism assertion, not an outcome comparison, a risk model, or a full consumer-failure v3.1 configuration. The test does not assert recovery after every possible broker partition or crash. The original v3 protocol remains unchanged; the v3.1 pilot and locked plan require separate commits and review.
