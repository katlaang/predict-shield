package org.predictshield.mechanism;

import java.net.URI;
import java.util.concurrent.atomic.AtomicLong;
import jakarta.annotation.PreDestroy;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.listener.MessageListenerContainer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * An independently deployed and independently cached authorization enforcement point.
 *
 * <p>Each instance runs in its own Java process and Kafka consumer group.
 * Spring Kafka delivers revision events from the authority. Fault injection
 * occurs in the real consumer callback, rather than in a training-label
 * formula: an event may be dropped, delayed on a scheduler, duplicated, or
 * held until a later event arrives. Cache TTL expiration independently issues
 * an HTTP read to the authority. This implementation therefore exposes
 * observable races between event publication, cache refresh, and request
 * processing instead of a precomputed outcome.</p>
 *
 * <p>The external protected endpoint knows only its cached policy and does
 * not publish its status as a proof of remediation. An administrator endpoint
 * exposes internal revision information only under the oracle credential.
 * Verification clients must not read this endpoint, and model feature
 * preparation must not use it.</p>
 *
 * <p>Failure injection is deliberately scoped to this isolated lab. Never
 * expose the admin endpoints or test identities on a production network.
 * Fault state is process-local and is cleared when a container restarts.</p>
 */
@RestController
@ConditionalOnProperty(name = "lab.role", havingValue = "enforcer")
public final class EnforcementController {
    private final String identity;
    private final String controlToken;
    private final String oracleToken;
    private final String authorityUrl;
    private final String internalToken;
    private final RestClient http = RestClient.create();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final Random jitter;
    private volatile PolicyRevision cached = new PolicyRevision(0, false);
    private volatile long refreshedAtMs = 0;
    /**
     * Configured per-node synthetic service time in the real HTTP handler.
     *
     * <p>Unlike a generated disruption label, the configured delay occurs
     * during actual JVM request execution and is observed by the gateway.
     * This models heterogeneous service times, not authentic production
     * hardware capacity or JVM cold-start duration.</p>
     */
    @Value("${lab.legitimate-latency-ms:0}")
    private volatile long legitimateLatencyMs;
    private volatile boolean operatorTelemetryVisible = true;

    private volatile long cacheTtlMs = 3000;
    private volatile String fault = "none";
    @Autowired(required = false)
    private KafkaListenerEndpointRegistry listenerRegistry;
    private volatile String heldEvent;
    private volatile long delayedMs = 0;
    private volatile long handledEvents = 0;
    private volatile long droppedEvents = 0;
    private volatile boolean lastRefreshFailed = false;
    private final AtomicLong experimentEpoch = new AtomicLong(0);
    private final AtomicLong scheduledCallbacks = new AtomicLong(0);
    private final AtomicLong discardedOldEpochCallbacks = new AtomicLong(0);
    private final AtomicLong rejectedTrialEvents = new AtomicLong(0);
    private final AtomicLong reorderedEventPairs = new AtomicLong(0);
    private final AtomicLong duplicatedEvents = new AtomicLong(0);

    /**
     * Injects process identity and separate authority, control and oracle credentials.
     *
     * @param identity stable name for this independently deployed enforcement point
     * @param controlToken secret authorizing fault setup and local experiment resets
     * @param oracleToken secret held only by the separate oracle observer
     * @param authorityUrl internal HTTP address of the policy authority
     * @param internalToken secret used exclusively for cache TTL refresh
     */
    public EnforcementController(
            @Value("${lab.instance:unknown}") String identity,
            @Value("${lab.control-token:}") String controlToken,
            @Value("${lab.oracle-token:}") String oracleToken,
            @Value("${lab.authority-url:http://authority:8080}") String authorityUrl,
            @Value("${lab.internal-token:}") String internalToken) {
        this.identity = identity;
        this.controlToken = controlToken;
        this.oracleToken = oracleToken;
        this.authorityUrl = authorityUrl;
        this.internalToken = internalToken;
        this.jitter = new Random(identity.hashCode() ^ System.nanoTime());
    }

    /**
     * Handles a real Kafka policy event under the configured fault mechanism.
     *
     * <p>Loss intentionally acknowledges but ignores an event. Delay schedules
     * a future cache update. Duplication applies the same revision twice.
     * Reordering holds one event and applies a later event before releasing it.
     * Monotonic revision checks prevent older events from reverting state.
     * All resulting cache changes are observed through HTTP requests.</p>
     *
     * @param value serialized revision and Boolean revocation value
     */
    @KafkaListener(id = "lab-policy-consumer", topics = "lab-policy", groupId = "${lab.instance:enforcer}")
    public synchronized void onEvent(String value) {
        // Malformed and old-trial broker messages must never enter this
        // trial's fault handler or consume a matched action's fault budget.
        String[] envelope = value.split(",", -1);
        if (envelope.length != 3 || !envelope[0].equals(cached.trialId())) {
            rejectedTrialEvents.incrementAndGet();
            return;
        }
        handledEvents++;
        String mode = fault;
        long epoch = experimentEpoch.get();
        switch (mode) {
            case "loss" -> droppedEvents++;
            case "delay" -> scheduleForEpoch(
                    value, epoch, Math.max(1, delayedMs + jitter.nextInt(81)));
            case "duplicate" -> {
                duplicatedEvents.incrementAndGet();
                applyRevision(value);
                scheduleForEpoch(value, epoch, 10 + jitter.nextInt(30));
            }
            case "reorder" -> {
                if (heldEvent == null) heldEvent = value;
                else {
                    reorderedEventPairs.incrementAndGet();
                    applyRevision(value);
                    String earlier = heldEvent;
                    heldEvent = null;
                    scheduleForEpoch(earlier, epoch, 25 + jitter.nextInt(80));
                }
            }
            default -> applyRevision(value);
        }
    }

    /**
     * Schedules an actual Kafka-consumer fault callback bound to the active trial epoch.
     *
     * <p>Replaying a message after a fresh trial reset would contaminate the
     * successor's starting conditions. The scheduled callback therefore checks
     * its captured epoch while holding the same monitor used by reset(). A
     * callback from an earlier experiment can never change the new cached
     * policy even if it carries a greater revision. A pending callback is
     * tracked so readiness can distinguish real quiescence from apparent
     * policy convergence. This does not make Kafka itself transactional.</p>
     *
     * @param raw the genuine broker-delivered revision payload
     * @param epoch active experiment generation captured during consumer handling
     * @param delayMs injected nonnegative callback delay in milliseconds
     */
    private synchronized void scheduleForEpoch(String raw, long epoch, long delayMs) {
        scheduledCallbacks.incrementAndGet();
        scheduler.schedule(() -> {
            try {
                synchronized (EnforcementController.this) {
                    if (experimentEpoch.get() == epoch) {
                        applyRevision(raw);
                    } else {
                        discardedOldEpochCallbacks.incrementAndGet();
                    }
                }
            } finally {
                scheduledCallbacks.decrementAndGet();
            }
        }, delayMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Applies a parsed Kafka revision only when it is not older than the cache.
     *
     * @param raw Kafka event containing a nonnegative revision and Boolean flag
     */
    private synchronized void applyRevision(String raw) {
        try {
            String[] tokens = raw.split(",", -1);
            if (tokens.length != 3 || !tokens[0].equals(cached.trialId())
                    || !(tokens[2].equals("true") || tokens[2].equals("false"))) {
                throw new IllegalArgumentException("Invalid lab policy event");
            }
            PolicyRevision incoming = new PolicyRevision(Long.parseLong(tokens[1]),
                    Boolean.parseBoolean(tokens[2]), tokens[0]);
            if (incoming.revision() >= cached.revision()) {
                cached = incoming;
                refreshedAtMs = System.currentTimeMillis();
                lastRefreshFailed = false;
            }
        } catch (IllegalArgumentException ignored) {
            // Malformed experimental event cannot mutate an enforcement cache.
        }
    }

    /**
     * Performs an actual HTTP refresh after TTL expiration, if enabled.
     *
     * <p>A freshly restarted process may initially have an unassigned trial;
     * its first successful authority HTTP refresh binds the current authoritative
     * trial and recovers desired policy. This gives process restart an actual
     * recovery mechanism without clearing the Kafka consumer fault. An
     * unreachable authority leaves the last known revision cached and
     * records the failure for privileged inspection. This models stale
     * enforcement under connectivity faults but does not claim to implement
     * a production fail-closed identity system.</p>
     */
    private synchronized void refreshIfExpired() {
        if (System.currentTimeMillis() - refreshedAtMs < cacheTtlMs) return;
        try {
            PolicyRevision result = http.get()
                    .uri(URI.create(authorityUrl + "/internal/policy"))
                    .header("X-Lab-Internal", internalToken)
                    .retrieve().body(PolicyRevision.class);
            if (result != null
                    && (cached.trialId().equals("unassigned")
                        || (result.trialId().equals(cached.trialId())
                            && result.revision() >= cached.revision()))) {
                cached = result;
            }
            refreshedAtMs = System.currentTimeMillis();
            lastRefreshFailed = false;
        } catch (RuntimeException ex) {
            lastRefreshFailed = true;
            refreshedAtMs = System.currentTimeMillis();
        }
    }

    /**
     * Enforces a disposable revoked principal and a separate authorized
     * laboratory principal on the same protected resource.
     *
     * <p>Authorized-protected traffic incurs a real denial when a gateway
     * restriction blocks the protected route wholesale. This is essential
     * for measuring intervention cost instead of giving gateway restriction
     * a zero-disruption advantage. The X-Lab-Principal header is a synthetic
     * test marker, NOT authenticated identity or a production security
     * boundary. It is accepted only inside the isolated testbed.</p>
     *
     * @param principal synthetic test-only principal type; "authorized" is
     *                  permitted, missing values represent the revoked test user
     * @return 403 for denied revoked access; 200 for genuinely permitted
     *         laboratory operations
     */
    @GetMapping("/protected")
    public synchronized ResponseEntity<Map<String, Object>> protectedOperation(
            @RequestHeader(value = "X-Lab-Principal", required = false) String principal) {
        // Test-only identity: the header is NOT authenticated and must not
        // be used as an authorization mechanism outside this isolated lab.
        // Its purpose is to observe how coarse gateway restriction affects
        // authorized users of the SAME protected operation.
        if ("authorized".equals(principal)) {
            return ResponseEntity.ok(Map.of(
                    "decision", "ALLOW", "instance", identity,
                    "principal_type", "authorized_test_identity"));
        }
        refreshIfExpired();
        return cached.revoked()
                ? ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("decision", "DENY", "instance", identity))
                : ResponseEntity.ok(Map.of("decision", "ALLOW", "instance", identity));
    }

    /**
     * Handles legitimate workload requests unaffected by authorization policy.
     *
     * <p>Real service restarts and network delays produce measurable failures
     * or request latency at the external gateway during concurrent traffic.
     * The endpoint does not fabricate request failures from formulas.</p>
     *
     * @return successful legitimate application response when process is ready
     */
    @GetMapping("/legitimate")
    public ResponseEntity<Map<String, Object>> legitimate() {
        long boundedMs = Math.max(0L, Math.min(150L, legitimateLatencyMs));
        if (boundedMs > 0) {
            try {
                Thread.sleep(boundedMs);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(Map.of("instance", identity, "ok", false));
            }
        }
        return ResponseEntity.ok(Map.of("instance", identity, "ok", true));
    }

    /**
     * Returns readiness without claiming control correctness.
     *
     * @return instance identifier and process health
     */
    @GetMapping("/healthz")
    public Map<String, Object> health() {
        return Map.of("instance", identity, "ready", true);
    }

    /**
     * Sets the next consumer fault mode for a single controlled experiment.
     *
     * @param token disposable lab mutation credential
     * @param mode one of none, loss, delay, duplicate or reorder
     * @param delayMs optional fixed delay component, bounded in milliseconds
     * @return accepted fault configuration without inventing outcome labels
     */
    @PostMapping("/admin/fault/{mode}/{delayMs}")
    public synchronized ResponseEntity<Map<String, Object>> setFault(
            @RequestHeader(value = "X-Lab-Control", required = false) String token,
            @PathVariable String mode,
            @PathVariable long delayMs) {
        if (!authorized(token, controlToken)) return forbidden();
        if (!java.util.Set.of("none", "loss", "delay", "duplicate", "reorder").contains(mode)
                || delayMs < 0 || delayMs > 5000) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid fault"));
        }
        fault = mode;
        delayedMs = delayMs;
        heldEvent = null;
        return ResponseEntity.ok(Map.of("instance", identity, "fault", mode));
    }

    /**
     * Controls only this JVM's actual Kafka listener container, preserving HTTP
     * service availability. Pause is asynchronous; callers must independently
     * observe isContainerPaused() before publishing fault events.
     *
     * @param token disposable lab control credential
     * @param command "pause" or "resume" only
     * @return observed container state without asserting a fault outcome
     */
    @PostMapping("/admin/consumer/{command}")
    public ResponseEntity<Map<String, Object>> controlConsumer(
            @RequestHeader(value = "X-Lab-Control", required = false) String token,
            @PathVariable String command) {
        if (!authorized(token, controlToken)) return forbidden();
        if (!java.util.Set.of("pause", "resume").contains(command)) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid command"));
        }
        MessageListenerContainer container = listenerRegistry == null ? null
                : listenerRegistry.getListenerContainer("lab-policy-consumer");
        if (container == null || !container.isRunning()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "Kafka listener not running"));
        }
        if ("pause".equals(command)) container.pause();
        else container.resume();
        return ResponseEntity.ok(Map.of("instance", identity,
                "pause_requested", container.isPauseRequested(),
                "container_paused", container.isContainerPaused()));
    }

    /**
     * Reports physical Kafka listener pause state with no injected fault label.
     *
     * @param token disposable lab control credential
     * @return actual listener lifecycle indicators
     */
    @GetMapping("/admin/consumer/status")
    public ResponseEntity<Map<String, Object>> consumerStatus(
            @RequestHeader(value = "X-Lab-Control", required = false) String token) {
        if (!authorized(token, controlToken)) return forbidden();
        MessageListenerContainer container = listenerRegistry == null ? null
                : listenerRegistry.getListenerContainer("lab-policy-consumer");
        if (container == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "Kafka listener unavailable"));
        }
        return ResponseEntity.ok(Map.of("instance", identity,
                "running", container.isRunning(),
                "pause_requested", container.isPauseRequested(),
                "container_paused", container.isContainerPaused(),
                "http_service_alive", true));
    }

    /**
     * Resets the local cache for an independent and clean action replay.
     *
     * <p>The runner must reset the authority and all enforcement processes
     * before configuring fault modes; this does not erase Kafka's committed
     * event log or external oracle observations.</p>
     *
     * @param token laboratory mutation credential
     * @param ttlMs real cache TTL in milliseconds, bounded for safety
     * @return accepted local reset or validation error
     */
    @PostMapping("/admin/reset/{ttlMs}")
    public synchronized ResponseEntity<Map<String, Object>> reset(
            @RequestHeader(value = "X-Lab-Control", required = false) String token,
            @PathVariable long ttlMs) {
        if (!authorized(token, controlToken)) return forbidden();
        if (ttlMs < 50 || ttlMs > 30000) {
            return ResponseEntity.badRequest().body(Map.of("error", "TTL out of bounds"));
        }
        // The epoch is incremented before mutating cache state under the
        // same monitor as Kafka callbacks and delayed scheduled work.
        // This explicitly invalidates callbacks from previous trials.
        experimentEpoch.incrementAndGet();
        cached = new PolicyRevision(0, false);
        refreshedAtMs = System.currentTimeMillis();
        cacheTtlMs = ttlMs;
        fault = "none";
        heldEvent = null;
        handledEvents = 0;
        droppedEvents = 0;
        lastRefreshFailed = false;
        return ResponseEntity.ok(Map.of("instance", identity, "reset", true));
    }

    /**
     * Binds a freshly reset local cache to the authority's current trial.
     *
     * <p>Only events bearing this identifier can be consumed in this trial.
     * Unlike a local callback epoch, this identifier travels over Kafka and
     * prevents broker-delayed messages from prior trials from being applied.
     * The runner must obtain the ID from the authenticated authority reset
     * response and bind every enforcement process before proceeding.</p>
     *
     * @param token disposable experiment control credential
     * @param trialId nonblank URL-safe authority-assigned trial identity
     * @return acknowledged trial identifier or a controlled error
     */
    @PostMapping("/admin/bind/{trialId}")
    public synchronized ResponseEntity<Map<String, Object>> bindTrial(
            @RequestHeader(value = "X-Lab-Control", required = false) String token,
            @PathVariable String trialId) {
        if (!authorized(token, controlToken)) return forbidden();
        if (!trialId.matches("[a-fA-F0-9-]{36}")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid trial ID"));
        }
        experimentEpoch.incrementAndGet();
        cached = new PolicyRevision(0, false, trialId);
        refreshedAtMs = System.currentTimeMillis();
        return ResponseEntity.ok(Map.of("instance", identity, "trial_id", trialId));
    }

    /**
     * Deliberately rebuilds one cache from a stale local snapshot.
     *
     * <p>This reproduces a silent regression after previously successful
     * revocation. Unlike the normal Kafka processing path, no policy change
     * event is published. An external verifier must detect the regression
     * through time-based rechecking or independent active probes. The action
     * is explicitly authorized and isolated to this disposable testbed.</p>
     *
     * @param token authorized fault-injection credential
     * @return acknowledgment of the injected stale-cache state
     */
    @PostMapping("/admin/silent-regression")
    public synchronized ResponseEntity<Map<String, Object>> injectRegression(
            @RequestHeader(value = "X-Lab-Control", required = false) String token) {
        if (!authorized(token, controlToken)) return forbidden();
        cached = new PolicyRevision(cached.revision(), false, cached.trialId());
        refreshedAtMs = System.currentTimeMillis();
        return ResponseEntity.ok(Map.of("injected", true, "instance", identity));
    }

    /**
     * Sets real HTTP handler service latency for a preregistered lab scenario.
     *
     * <p>The setting changes actual JVM service time, and therefore gateway
     * concurrency and measured latency under load. It never supplies a
     * generated action-outcome label or overwrites an oracle measurement.
     * Values are intentionally bounded to prevent runaway experiment load.</p>
     *
     * @param token disposable lab mutation credential
     * @param milliseconds requested per-request service delay, in [0, 150]
     * @return acknowledged actual handler configuration
     */
    @PostMapping("/admin/service-latency/{milliseconds}")
    public synchronized ResponseEntity<Map<String, Object>> setServiceLatency(
            @RequestHeader(value = "X-Lab-Control", required = false) String token,
            @PathVariable long milliseconds) {
        if (!authorized(token, controlToken)) return forbidden();
        if (milliseconds < 0 || milliseconds > 150) {
            return ResponseEntity.badRequest().body(Map.of("error", "delay out of bounds"));
        }
        legitimateLatencyMs = milliseconds;
        return ResponseEntity.ok(Map.of("instance", identity, "latency_ms", milliseconds));
    }

    /**
     * Enables or suppresses this process's pre-action operator telemetry.
     *
     * <p>The oracle's separate privileged admin endpoint remains available
     * even when the operator feed is missing. This models an observable
     * telemetry outage without pretending that injected faults are known to
     * the predictor. It does not affect Kafka delivery or authorization.</p>
     *
     * @param token disposable laboratory mutation credential
     * @param enabled whether this node's operator feed is available
     * @return acknowledged feed visibility state
     */
    @PostMapping("/admin/operator-visible/{enabled}")
    public synchronized ResponseEntity<Map<String, Object>> setOperatorVisibility(
            @RequestHeader(value = "X-Lab-Control", required = false) String token,
            @PathVariable boolean enabled) {
        if (!authorized(token, controlToken)) return forbidden();
        operatorTelemetryVisible = enabled;
        return ResponseEntity.ok(Map.of("instance", identity, "visible", enabled));
    }

    /**
     * Exposes bounded operational indicators to the experimental decision
     * engine without disclosing fault injection, oracle truth or private
     * verification outcome.
     *
     * <p>The existing laboratory control credential grants read-only access
     * to this pre-action snapshot. It is NOT yet a distinct least-privilege
     * operator credential. The telemetry contains observed cache age,
     * applied revision, processed-event count, failed TTL refresh and pending
     * scheduled operations. It deliberately omits the injected fault mode,
     * target identity as a fault label, desired authoritative access verdict,
     * oracle direct probes and post-action results. A local revision is not a
     * verified Kafka consumer offset. These indicators must be timestamped
     * before an action to be used as model inputs.</p>
     *
     * @param token disposable laboratory control credential, shared with lab mutations
     * @return only operator-observable monitoring fields, not oracle truth
     */
    @GetMapping("/operator/telemetry")
    public synchronized ResponseEntity<Map<String, Object>> operatorTelemetry(
            @RequestHeader(value = "X-Lab-Control", required = false) String token) {
        if (!authorized(token, controlToken)) return forbidden();
        if (!operatorTelemetryVisible) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("instance", identity, "error", "operator feed unavailable"));
        }
        long cacheAge = Math.max(0L, System.currentTimeMillis() - refreshedAtMs);
        // Actual listener health is observable before a response. This is
        // NOT a trusted broker-offset/consumer-lag measurement and it does
        // NOT disclose the experiment's injected fault label.
        MessageListenerContainer listener = listenerRegistry == null ? null
                : listenerRegistry.getListenerContainer("lab-policy-consumer");
        boolean listenerObserved = listener != null;
        return ResponseEntity.ok(Map.ofEntries(
                Map.entry("instance", identity),
                Map.entry("applied_revision", cached.revision()),
                Map.entry("cache_age_ms", cacheAge),
                Map.entry("cache_ttl_ms", cacheTtlMs),
                Map.entry("legitimate_service_latency_ms", legitimateLatencyMs),
                Map.entry("handled_events", handledEvents),
                Map.entry("refresh_failed", lastRefreshFailed),
                Map.entry("scheduled_callbacks_pending", scheduledCallbacks.get()),
                Map.entry("consumer_state_observed", listenerObserved),
                Map.entry("consumer_running", listenerObserved && listener.isRunning()),
                Map.entry("consumer_paused", listenerObserved && listener.isContainerPaused()),
                Map.entry("consumer_pause_requested",
                        listenerObserved && listener.isPauseRequested()),
                Map.entry("observed_at_epoch_ms", System.currentTimeMillis()),
                Map.entry("broker_consumer_lag_measured", false),
                Map.entry("observation_type", "operator_pre_action_v2")));
    }

    /**
     * Exposes local cached state through a separate privileged oracle path.
     *
     * <p>The oracle obtains each instance's state directly, bypassing the
     * normal request router and its potentially incomplete observations.
     * This still uses administrator-reported cache state, so independent
     * active probes should also be considered in scientific validation.</p>
     *
     * @param token credential possessed only by the oracle process
     * @return cached revision and observed consumer statistics
     */
    @GetMapping("/admin/state")
    public ResponseEntity<?> adminState(
            @RequestHeader(value = "X-Lab-Oracle", required = false) String token) {
        if (!authorized(token, oracleToken)) return forbidden();
        return ResponseEntity.ok(Map.ofEntries(
                Map.entry("instance", identity),
                Map.entry("revision", cached.revision()),
                Map.entry("revoked", cached.revoked()),
                Map.entry("fault", fault),
                Map.entry("handled_events", handledEvents),
                Map.entry("dropped_events", droppedEvents),
                Map.entry("pending_scheduled_callbacks", scheduledCallbacks.get()),
                Map.entry("old_epoch_callbacks_discarded", discardedOldEpochCallbacks.get()),
                Map.entry("experiment_epoch", experimentEpoch.get()),
                Map.entry("trial_id", cached.trialId()),
                Map.entry("rejected_trial_events", rejectedTrialEvents.get()),
                Map.entry("reordered_event_pairs", reorderedEventPairs.get()),
                Map.entry("duplicated_events", duplicatedEvents.get()),
                Map.entry("refresh_failed", lastRefreshFailed)
        ));
    }

    /**
     * Stops the laboratory scheduler when the Spring service is destroyed.
     *
     * <p>Delayed callbacks are discarded when the process terminates. The
     * lab does not persist a callback queue, so experimental
     * collectors must not treat container shutdown as delivery confirmation.</p>
     */
    @PreDestroy
    public void shutdownScheduler() {
        scheduler.shutdownNow();
    }

    /**
     * Checks a disposable header against the expected laboratory secret.
     *
     * @param supplied caller-provided token
     * @param expected configured secret
     * @return true when nonblank values exactly match
     */
    private static boolean authorized(String supplied, String expected) {
        return supplied != null && expected != null && !expected.isBlank()
                && expected.equals(supplied);
    }

    /**
     * Returns a generic rejection for unauthorized administrative requests.
     *
     * @return HTTP 403 response without token or infrastructure details
     */
    private static ResponseEntity<Map<String, Object>> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "laboratory credential rejected"));
    }
}
