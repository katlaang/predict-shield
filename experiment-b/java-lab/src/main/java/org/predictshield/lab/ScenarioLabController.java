package org.predictshield.lab;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Resettable, isolated authorization-control experiment fixture.
 *
 * <p>One Spring process hosts multiple <em>logical</em> enforcement points.
 * It is not a real distributed policy enforcement system. Each point responds
 * to a real HTTP access probe, and each controlled action changes in-memory
 * authorization or service-availability state. The evaluator must measure
 * actual HTTP outcomes rather than trust action acknowledgments.</p>
 *
 * <p>Four actions are supported: resync_policy, restart_enforcer,
 * gateway_restrict, and monitor_only. Conditions and action effects are
 * deliberately simplified. This code is strictly for a disposable localhost
 * research lab, never for production or operational technology.</p>
 *
 * <p>The oracle endpoint exposes internal logical truth only to the
 * separately credentialed evaluation collector. Since the oracle runs in
 * this same Java process, it is a laboratory fixture, not a separately
 * administered trust domain. It must never be used as a model feature.</p>
 *
 * <p>Mutating endpoints require a disposable LAB_TOKEN. The oracle
 * additionally requires a distinct LAB_ORACLE_TOKEN. The controller
 * serializes scenario operations to avoid cross-run state races.
 * Run only one controlled trial per process at a time.</p>
 */
@RestController
public final class ScenarioLabController {

    /** Complete allowlist of named laboratory actions. */
    public static final List<String> ACTIONS = List.of(
            "resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only");

    private final String labToken;
    private final String oracleToken;
    private ScenarioConfiguration configuration;
    private final List<Boolean> accessAllowed = new ArrayList<>();
    private int disruptionRequestsRemaining;
    private boolean gatewayRestricted;
    private boolean regressionArmed;
    private int successfulLegitimateRequests;

    /**
     * Loads lab-only credentials from the container environment.
     *
     * <p>Separate secrets permit separate simulator and oracle clients.
     * Empty secrets disable the associated privileged endpoint.</p>
     */
    public ScenarioLabController() {
        this.labToken = System.getenv().getOrDefault("LAB_TOKEN", "");
        this.oracleToken = System.getenv().getOrDefault("LAB_ORACLE_TOKEN", "");
    }

    /**
     * Reinitializes the experiment before a single candidate-action replay.
     *
     * <p>Uses the seeded random permutation to distribute stale authorization
     * states among logical enforcement points. The reset eliminates effects
     * from previous actions. It is acknowledged only after state is reset
     * and is never sufficient to establish security verification.</p>
     *
     * @param token disposable mutation credential
     * @param next immutable scenario and workload parameters
     * @return reset acknowledgment and logical target count
     */
    @PostMapping("/lab/scenario/reset")
    public synchronized ResponseEntity<Map<String, Object>> reset(
            @RequestHeader(value = "X-Lab-Token", required = false) String token,
            @RequestBody ScenarioConfiguration next) {
        if (!allowed(token, labToken)) {
            return forbidden();
        }
        configuration = next;
        accessAllowed.clear();
        for (int index = 0; index < next.enforcementPoints(); index++) {
            accessAllowed.add(index < next.stalePoints());
        }
        Collections.shuffle(accessAllowed, new Random(next.seed()));
        disruptionRequestsRemaining = 0;
        gatewayRestricted = false;
        regressionArmed = "silent_rebuild".equals(next.faultFamily());
        successfulLegitimateRequests = 0;
        return ResponseEntity.ok(Map.of("run_id", next.runId(),
                "reset_acknowledged", true, "logical_enforcement_points", accessAllowed.size()));
    }

    /**
     * Performs a real HTTP deny probe against a logical enforcement point.
     *
     * <p>The expected policy rejects revoked access with HTTP 403. HTTP 200
     * represents an incorrectly permitted operation. No oracle state is
     * returned to this model-independent verification endpoint.</p>
     *
     * @param point bounded zero-based logical enforcement point index
     * @return HTTP 403 if denied, 200 if stale, 404 if outside declared scope
     */
    @GetMapping("/lab/scenario/probe/{point}")
    public synchronized ResponseEntity<Map<String, Object>> probe(
            @PathVariable("point") int point) {
        if (configuration == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "scenario not configured"));
        }
        if (point < 0 || point >= accessAllowed.size()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "logical target not present"));
        }
        return accessAllowed.get(point)
                ? ResponseEntity.ok(Map.of("target", point, "decision", "ALLOWED"))
                : ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("target", point, "decision", "DENIED"));
    }

    /**
     * Executes one of four deliberately limited simulation actions.
     *
     * <p>resync_policy corrects all points except that lost_event leaves one
     * stale; restart_enforcer corrects all but introduces a bounded number
     * of legitimate-request failures; gateway_restrict closes revoked access
     * but also blocks legitimate traffic; monitor_only makes no change.
     * These are fixture mechanisms, not estimates of real deployment action
     * effectiveness. The runner must observe each effect independently.</p>
     *
     * @param action allowed action identifier
     * @param token disposable mutation credential
     * @return acknowledgement only; never a VERIFIED outcome
     */
    @PostMapping("/lab/scenario/action/{action}")
    public synchronized ResponseEntity<Map<String, Object>> applyAction(
            @PathVariable("action") String action,
            @RequestHeader(value = "X-Lab-Token", required = false) String token) {
        if (!allowed(token, labToken)) {
            return forbidden();
        }
        if (configuration == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "scenario not configured"));
        }
        if (!ACTIONS.contains(action)) {
            return ResponseEntity.badRequest().body(Map.of("error", "unknown lab action"));
        }
        switch (action) {
            case "resync_policy" -> {
                accessAllowed.replaceAll(ignored -> false);
                if ("lost_event".equals(configuration.faultFamily())) {
                    accessAllowed.set(0, true);
                }
            }
            case "restart_enforcer" -> {
                accessAllowed.replaceAll(ignored -> false);
                disruptionRequestsRemaining = Math.min(25, Math.max(1,
                        configuration.dependencyDepth() * configuration.enforcementPoints()));
            }
            case "gateway_restrict" -> {
                accessAllowed.replaceAll(ignored -> false);
                gatewayRestricted = true;
            }
            case "monitor_only" -> {
                // Baseline: intentionally does not correct authorization drift.
            }
            default -> throw new IllegalStateException("Action allowlist mismatch");
        }
        return ResponseEntity.ok(Map.of(
                "run_id", configuration.runId(), "action", action, "acknowledged", true));
    }

    /**
     * Serves legitimate traffic for measuring collateral service impact.
     *
     * <p>A simulated restart or overbroad gateway restriction can produce
     * HTTP 503. The runner measures observed status and latency externally
     * per request. No built-in cost estimate is returned as a measurement.</p>
     *
     * @return HTTP 200 for accepted legitimate traffic or 503 for disruption
     */
    @GetMapping("/lab/scenario/legitimate")
    public synchronized ResponseEntity<Map<String, Object>> legitimateRequest() {
        if (configuration == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "scenario not configured"));
        }
        if (gatewayRestricted) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("result", "gateway restricted legitimate traffic"));
        }
        if (disruptionRequestsRemaining > 0) {
            disruptionRequestsRemaining--;
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("result", "simulated restart interruption"));
        }
        successfulLegitimateRequests++;
        return ResponseEntity.ok(Map.of("result", "legitimate request accepted"));
    }

    /**
     * Triggers a silent cache-rebuild regression without a change event.
     *
     * <p>This is available only for a configured silent_rebuild scenario and
     * only once per reset. A subsequent external probe must establish the
     * regression instead of trusting the trigger acknowledgment.</p>
     *
     * @param token disposable mutation credential
     * @return trigger acknowledgment, or a conflict when not armed
     */
    @PostMapping("/lab/scenario/trigger-regression")
    public synchronized ResponseEntity<Map<String, Object>> triggerRegression(
            @RequestHeader(value = "X-Lab-Token", required = false) String token) {
        if (!allowed(token, labToken)) {
            return forbidden();
        }
        if (configuration == null || !regressionArmed) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "regression not armed"));
        }
        accessAllowed.set(0, true);
        regressionArmed = false;
        return ResponseEntity.ok(Map.of("trigger_acknowledged", true));
    }

    /**
     * Returns the fixture's internal enforcement state for oracle evaluation.
     *
     * <p>This endpoint is inaccessible without the separate oracle credential.
     * It exposes state hidden from normal probes, allowing evaluation of
     * verifier errors. It is not independently hosted or cryptographically
     * attested and is therefore insufficient as production ground truth.</p>
     *
     * @param token oracle-only credential distinct from the mutation token
     * @return internal target membership and enforcement state
     */
    @GetMapping("/lab/scenario/oracle")
    public synchronized ResponseEntity<Map<String, Object>> oracle(
            @RequestHeader(value = "X-Oracle-Token", required = false) String token) {
        if (!allowed(token, oracleToken)) {
            return forbidden();
        }
        if (configuration == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "scenario not configured"));
        }
        return ResponseEntity.ok(Map.of(
                "run_id", configuration.runId(), "scope", accessAllowed.size(),
                "authorization_allowed", List.copyOf(accessAllowed),
                "all_revoked_access_denied", accessAllowed.stream().noneMatch(Boolean::booleanValue),
                "successful_legitimate_requests", successfulLegitimateRequests));
    }

    /**
     * Checks a nonempty laboratory token with constant-time byte comparison.
     *
     * @param supplied token sent by the caller, possibly null
     * @param expected environment-configured token, possibly empty
     * @return true if and only if both nonempty values match
     */
    private static boolean allowed(String supplied, String expected) {
        return supplied != null && !supplied.isBlank()
                && expected != null && !expected.isBlank()
                && MessageDigest.isEqual(
                        supplied.getBytes(StandardCharsets.UTF_8),
                        expected.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Produces a uniform forbidden response without disclosing credentials.
     *
     * @return HTTP 403 with an intentionally generic message
     */
    private static ResponseEntity<Map<String, Object>> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "laboratory credential rejected"));
    }
}
