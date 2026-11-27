# PREDICT-SHIELD P0: independent Kafka broker-offset evidence (v1)

**Status: VALIDATED FOR BOUNDED LAB TELEMETRY ONLY.** [PR #189](https://github.com/katlaang/predict-shield/pull/189) merged; [GitHub Actions #45929835646](https://github.com/katlaang/predict-shield/actions/runs/45929835646) passed both synthetic evidence contracts and the disposable physical four-group Kafka measurement. Source artifact: `actual-readonly-kafka-broker-offsets`. Before pause all four group backlogs were **0**. During an actual `enforcer-b` Kafka consumer pause its committed backlog reached **3** while the other three were **0**. After resume all four were **0**. The mutation control credential was denied by the observer endpoint. These are actual measured committed-backlog counts, not lag in milliseconds, proof of handler correctness or a measured AI improvement. No new model was trained.

## Scientific and engineering motivation

The earlier learned defense selected resynchronization for all three new physical cases and resolved **none**; a fixed restart resolved **three** while causing 16 to 17 legitimate request failures per case. Existing node telemetry reports listener running/paused status, applied cache revisions and refresh failures. A local listener saying it is running does not confirm that a separate Kafka broker considers a consumer up to date.

This change adds an independent, strictly **read-only Kafka Admin** observation in its own container and credential boundary. It reads the **log end offsets** for the configured `lab-policy` partitions and each of the four **committed offsets** for the exact `enforcer-a`, `enforcer-b`, `enforcer-c`, and `enforcer-hidden` consumer groups.

The measured quantity, `log_end_offset - committed_offset`, is a **committed backlog**, not the consumer's current in-memory position, a precise causal processing delay, an independent authorization oracle, a post-remediation verdict, or an attack label. Missing groups or offsets, invalid arithmetic, a broker outage, bad credentials, an out-of-date timestamp, a changed partition set or an incomplete 4-group snapshot must be **UNKNOWN** and block automatic lab authorization. Group offsets are read sequentially after topic log ends, so snapshots are **not atomic**, and individual counts cannot be taken as one consistent distributed instant.

Kafka Admin reference: https://kafka.apache.org/41/javadoc/org/apache/kafka/clients/admin/Admin.html. Spring Kafka's `@KafkaListener.groupId` controls the consumer-group identity: https://docs.spring.io/spring-kafka/reference/kafka/receiving-messages/listener-annotation.html.

## Implementation boundaries

- `BrokerOffsetObserver.java`: independent container role `broker-observer`. Its sole protected endpoint is `GET /operator/broker-offsets` with `X-Lab-Observer` rather than the fault/mutation or private oracle credentials. The Java process has no registered enforcer/authority role. Admin calls only describe the lab topic and read offsets; no payloads are fetched, groups joined, offsets committed, records produced, or actions dispatched. The observer must remain on localhost-only Compose networking and is not authenticated for a real customer environment.
- `broker_observer_v1.py`: a bounded source-specific client attaches local receipt timing and validates each partition offset and per-group total. `status: UNKNOWN` is distinct from measured zero backlog.
- `defense_review_v2.py`: the existing **veto-only** defense gate now also requires fresh, fully accounted independent broker evidence before allowing a lab action recommendation to proceed. Broker data is a pre-action feature signal, never permission to relax existing disruption or authorization limits, and never an independently verified fix. Positive backlog is reported as a signal, not assumed to be an attack or a categorical reason to restart.
- `physical_ai_execution_pilot.py`: includes the independent broker observation before the model recommendation. Missing independent observer token means no broker observation, causing human review rather than authorizing action.
- `broker_offset_physical_smoke.py`: sets up an isolated real broker and four JVM consumers, tests that the mutation token cannot read broker evidence, publishes bounded lab events, physically pauses `enforcer-b`, checks a measured positive backlog while other consumers catch up, resumes, and checks zero backlog. The test records no private oracle, no executed defense and no AI outcome.

The existing frozen `pilot.py`, historic protocol, model weights and failed AI-defense results **must remain unchanged**. Separate issue [#188](https://github.com/katlaang/predict-shield/issues/188) tracks the earlier preregistration-hash discrepancy.

## Remaining evidence limits

- **No retraining**, no calibration change and no novel AI action-selection accuracy from this integration.
- Broker committed backlog by itself does not prove that application handlers have applied the correct policy, especially when cache TTL, callbacks, errors and group rebalances are involved.
- The observer's credentials and read-only operations are enforced in the disposable lab; production authorization and scoped Kafka ACLs are **not** demonstrated.
- Lab actions must still be governed by independent policy authorization, bounded disruption, human approval for restart and direct post-action verification.
- No claim of superior AI defense, customer benefit or U.S. critical-infrastructure effectiveness is established.

## Next development work after broker evidence CI

1. **Fault discriminability:** design a *new development-only* test matrix where a one-shot missed event with a healthy consumer can be corrected by resynchronization, a physically paused consumer requires a different intervention, and a self-healing fault legitimately favors no action. Verify each with physical outcomes. Do not reuse the historical prospective test as a fresh evaluation.
2. **Calibration:** examine security-resolution and disruption coverage separately by fault family and action; improve calibration only on development/calibration partitions, preserving independent test groups.
3. **Comparative proof:** preregister a fresh matched AI-versus-best-expert-rule study with independent outcomes, non-free escalations, budget breaches, grouped uncertainty and sealed new configurations.
4. **Field validation:** separate external authorized operator and assessor required for real operational claims.

**No release qualification is implied by a passing physical telemetry test.**
