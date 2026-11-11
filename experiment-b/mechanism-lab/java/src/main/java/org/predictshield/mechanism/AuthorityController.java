package org.predictshield.mechanism;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Independent authoritative policy store and Kafka event publisher.
 *
 * <p>This service runs in a separate JVM from every enforcement process.
 * Mutating a desired revision queues an event, not a claim of successful
 * enforcement. A policy resynchronization republishes the existing revision
 * so an enforcement point can recover from missed or reordered updates.
 * This research fixture persists revisions only in memory and must never
 * serve real identity or production authorization controls.</p>
 *
 * <p>Both control and private read paths require disposable credentials.
 * This application is accessible only through an isolated Docker network.</p>
 */
@RestController
@ConditionalOnProperty(name = "lab.role", havingValue = "authority")
public final class AuthorityController {
    private final KafkaTemplate<String, String> publisher;
    private final String controlToken;
    private final String internalToken;
    private final AtomicLong sequence = new AtomicLong(0);
    private volatile PolicyRevision current = new PolicyRevision(0, false);

    /**
     * Configures the authority with a Kafka transport and scoped secrets.
     *
     * @param publisher Kafka producer configured by Spring Boot
     * @param controlToken disposable policy mutation credential
     * @param internalToken distinct oracle/cache-read credential
     */
    public AuthorityController(
            KafkaTemplate<String, String> publisher,
            @Value("${lab.control-token:}") String controlToken,
            @Value("${lab.internal-token:}") String internalToken) {
        this.publisher = publisher;
        this.controlToken = controlToken;
        this.internalToken = internalToken;
    }

    /**
     * Reports process-level readiness for isolated experiment setup.
     *
     * <p>This check says only that the authority's HTTP process is running.
     * It does not imply Kafka delivery, cache convergence, or that the
     * revocation is effective at any enforcement point. Those conditions
     * require independent observations from the experimental oracle.</p>
     *
     * @return authority process readiness, never a security verdict
     */
    @GetMapping("/healthz")
    public Map<String, Object> health() {
        return Map.of("authority", "ready");
    }

    /**
     * Revokes the test identity and asynchronously emits a policy update.
     *
     * @param token authorized control credential
     * @return revision and event-queued acknowledgment, not observed enforcement
     */
    @PostMapping("/control/revoke")
    public synchronized ResponseEntity<Map<String, Object>> revoke(
            @RequestHeader(value = "X-Lab-Control", required = false) String token) {
        if (!authorized(token, controlToken)) return denied();
        current = new PolicyRevision(sequence.incrementAndGet(), true);
        return publish(current);
    }

    /**
     * Republishes the current revision to recover from missed Kafka events.
     *
     * @param token authorized control credential
     * @return publication acknowledgment without a verification verdict
     */
    @PostMapping("/control/resync")
    public synchronized ResponseEntity<Map<String, Object>> resync(
            @RequestHeader(value = "X-Lab-Control", required = false) String token) {
        if (!authorized(token, controlToken)) return denied();
        return publish(current);
    }

    /**
     * Resets the authority to an allowed state for a fresh trial.
     *
     * <p>Callers must also reset every enforcement process separately.
     * This deliberate two-part reset prevents an old consumer state from
     * being silently interpreted as a clean starting condition.</p>
     *
     * @param token authorized control credential
     * @return new revision and publication acknowledgment
     */
    @PostMapping("/control/reset")
    public synchronized ResponseEntity<Map<String, Object>> reset(
            @RequestHeader(value = "X-Lab-Control", required = false) String token) {
        if (!authorized(token, controlToken)) return denied();
        current = new PolicyRevision(sequence.incrementAndGet(), false);
        return publish(current);
    }

    /**
     * Exposes authoritative desired state to an oracle-only observer.
     *
     * @param token laboratory private read credential
     * @return policy revision or an HTTP 403 response
     */
    @GetMapping("/oracle/policy")
    public ResponseEntity<?> oracle(
            @RequestHeader(value = "X-Lab-Oracle", required = false) String token) {
        if (!authorized(token, internalToken)) return denied();
        return ResponseEntity.ok(current);
    }

    /**
     * Provides a live policy value when an enforcement cache really expires.
     *
     * <p>This is a separate HTTP read, unlike an asynchronous event update.
     * A failed refresh must never be described as successful convergence.</p>
     *
     * @param token internal cache-refresh credential
     * @return current policy revision or HTTP 403
     */
    @GetMapping("/internal/policy")
    public ResponseEntity<?> internalPolicy(
            @RequestHeader(value = "X-Lab-Internal", required = false) String token) {
        if (!authorized(token, internalToken)) return denied();
        return ResponseEntity.ok(current);
    }

    /**
     * Queues the authority's revision on the Kafka policy topic.
     *
     * @param revision immutable desired policy revision
     * @return accepted publication request, not an observation of consumers
     */
    private ResponseEntity<Map<String, Object>> publish(PolicyRevision revision) {
        publisher.send("lab-policy", "revoked-test-principal",
                revision.revision() + "," + revision.revoked());
        return ResponseEntity.accepted().body(Map.of(
                "revision", revision.revision(),
                "desired_revoked", revision.revoked(),
                "publication_queued", true));
    }

    /**
     * Compares a provided disposable credential with its configured value.
     *
     * @param supplied provided header value
     * @param expected configured secret
     * @return true when the nonblank credentials match
     */
    private static boolean authorized(String supplied, String expected) {
        return expected != null && !expected.isBlank() && expected.equals(supplied);
    }

    /**
     * Constructs a generic forbidden response without exposing credentials.
     *
     * @return HTTP 403 laboratory control denial
     */
    private static ResponseEntity<Map<String, Object>> denied() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "laboratory credential rejected"));
    }
}
