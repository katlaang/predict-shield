# Prospective single lab execution with historically trained action model

**Objective:** Demonstrate a real trained-model pre-action recommendation, deterministic safety-gated lab action (if eligible), and separately observed post-action outcome on one fixed newly executed Kafka/JVM fault.

Original measured dataset: five GitHub Actions physical shards from run `43629488209`, 1,200 actual action records, 100 original configuration groups: 60 training, 20 calibration, 20 already-examined test. Source hashes are validated before training. The historical held-out results are not independent evidence for a new model comparison and must remain unchanged.

The script trains a local RandomForest action-risk and legitimate-request disruption model, exports a locally hash-checked artifact, and starts a disposable fresh Java/Kafka mechanism lab. The single scenario is predeclared: full gateway visibility, fault mode loss, target enforcer-b, TTL 5000 ms, delay 125 ms, 25 requested RPS, SIMPLE latency stratum. The hidden fault identity is not supplied to model features. The model receives real, new pre-action gateway probes and operator telemetry.

The selector uses the independent safety gate with an explicit **laboratory experimental error allowance** (not measured production headroom). The only mutating automatic actions are resync and gateway restriction. Restart requires separate approval. If the model abstains or selects monitor only, that outcome is still recorded as the result. The post-action evidence uses the existing separately deployed experimental oracle and gateway probes. One physical case cannot establish consistent model benefit or independently validated production remediation.

The workflow publishes a research artifact **only upon success** and does not include the local pickle model artifact, which remains a trusted temporary file. All negative, abstention and unavailable evidence states are to be preserved. A failed workflow is a failed pilot and must not be presented as a successful trial. No external U.S. critical-infrastructure pilot is claimed.
