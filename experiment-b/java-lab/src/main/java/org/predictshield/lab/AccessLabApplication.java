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
 * Deliberately vulnerable lab state, never use as a production authorization service.
 * Both instances share the same intended policy: revoked role MUST receive HTTP 403.
 */
@SpringBootApplication
@RestController
public class AccessLabApplication {
    private final AtomicBoolean accessAllowed;
    private final String instance;
    private final String labToken;

    public AccessLabApplication(
            @Value("${lab.initial-allow:false}") boolean initialAllow,
            @Value("${lab.instance:unknown}") String instance,
            @Value("${lab.token:}") String labToken) {
        this.accessAllowed = new AtomicBoolean(initialAllow);
        this.instance = instance;
        this.labToken = labToken;
    }

    public static void main(String[] args) {
        SpringApplication.run(AccessLabApplication.class, args);
    }

    @GetMapping("/healthz")
    public Map<String, Object> health() {
        return Map.of("instance", instance, "ok", true);
    }

    @GetMapping("/api/protected")
    public ResponseEntity<Map<String, Object>> protectedOperation() {
        if (accessAllowed.get()) {
            return ResponseEntity.ok(Map.of("instance", instance, "access", "ALLOWED"));
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("instance", instance, "access", "DENIED"));
    }

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
