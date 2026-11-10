package org.predictshield.lab;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Legacy two-process authorization-drift fixture for Experiment B.
 *
 * <p>This application deliberately starts two separate Spring instances with
 * different cached access decisions. Both share the same expected policy:
 * a revoked role must receive HTTP 403 for the protected operation.
 * The Python verification client probes each instance independently,
 * and a separate, explicitly authorized lab-only mutation can revoke access.
 * This fixture must be bound to localhost and must never be deployed as a
 * production access-control service.</p>
 *
 * <p>The resettable multi-target scenario fixture implemented by
 * {@link ScenarioLabController} is a separate set of endpoints. It does not
 * change the behavior or original smoke-test semantics of these endpoints.</p>
 *
 * <p>Neither endpoint represents cryptographically authenticated evidence.
 * An HTTP success response from an action is not evidence that a security
 * assertion has been independently established.</p>
 */
@SpringBootApplication
@RestController
public class AccessLabApplication {
    private final AtomicBoolean accessAllowed;
    private final String instance;
    private final String labToken;

    /**
     * Constructs the legacy fixture with its initial authorization decision.
     *
     * @param initialAllow whether the revoked operation incorrectly succeeds
     * @param instance human-readable laboratory instance identifier
     * @param labToken disposable mutation credential; blank disables revocation
     */
    public AccessLabApplication(
            @Value("${lab.initial-allow:false}") boolean initialAllow,
            @Value("${lab.instance:unknown}") String instance,
            @Value("${lab.token:}") String labToken) {
        this.accessAllowed = new AtomicBoolean(initialAllow);
        this.instance = instance;
        this.labToken = labToken;
    }

    /**
     * Starts the Spring Boot laboratory application.
     *
     * @param args standard application command-line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(AccessLabApplication.class, args);
    }

    /**
     * Reports only process readiness, not control effectiveness.
     *
     * @return instance identifier and readiness flag
     */
    @GetMapping("/healthz")
    public Map<String, Object> health() {
        return Map.of("instance", instance, "ok", true);
    }

    /**
     * Exercises the effective cached authorization state for the revoked role.
     *
     * <p>HTTP 403 is the required authorization decision; HTTP 200 indicates
     * stale authorization. Neither result proves complete target inventory.</p>
     *
     * @return HTTP response containing the actual operation decision
     */
    @GetMapping("/api/protected")
    public ResponseEntity<Map<String, Object>> protectedOperation() {
        if (accessAllowed.get()) {
            return ResponseEntity.ok(Map.of("instance", instance, "access", "ALLOWED"));
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("instance", instance, "access", "DENIED"));
    }

    /**
     * Requests one explicit laboratory-only cache revocation.
     *
     * <p>A valid token authorizes this mutation, but the returned acknowledgment
     * does not establish that the operation succeeded. A separate independent
     * HTTP probe is required before recording a VERIFIED assessment.</p>
     *
     * @param suppliedToken caller-supplied disposable laboratory credential
     * @return acknowledged mutation or HTTP 403 for an invalid credential
     */
    @PostMapping("/lab/revoke")
    public ResponseEntity<Map<String, Object>> revoke(
            @RequestHeader(value = "X-Lab-Token", required = false) String suppliedToken) {
        if (labToken.isBlank() || suppliedToken == null || !MessageDigest.isEqual(
                labToken.getBytes(StandardCharsets.UTF_8),
                suppliedToken.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("instance", instance, "error", "lab token rejected"));
        }
        accessAllowed.set(false);
        return ResponseEntity.ok(Map.of("instance", instance, "revocation_acknowledged", true));
    }
}
