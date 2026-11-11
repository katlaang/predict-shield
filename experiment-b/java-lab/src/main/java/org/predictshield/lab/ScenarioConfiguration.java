package org.predictshield.lab;

import java.util.Set;

/**
 * Immutable, validated configuration for one isolated Experiment B laboratory trial.
 *
 * <p>The configuration describes a set of logical authorization enforcement points,
 * not an operational identity provider or a physical critical-infrastructure network.
 * Values control the initial stale-policy condition and the workload used to measure
 * the effects of a simulated defensive response. They are immutable for the lifetime
 * of an individual trial, which prevents an experiment runner from changing the
 * starting conditions after observing the result.</p>
 *
 * <p>Every candidate action must be replayed from a fresh reset using the same
 * {@code seed}, {@code runId} group, and configuration. The generator assigns separate
 * training, calibration, and test configuration groups. In particular, the server
 * must not obtain a model's predicted result or a fixture oracle label through
 * this record.</p>
 *
 * <p>The named fault families are experimental labels. This initial fixture
 * implements stale authorization state, a missed resynchronization effect in one
 * lost-event condition, and a delayed cache-rebuild regression. It does not
 * emulate a Kafka cluster, network partition, or real deployment.</p>
 *
 * @param runId unique identifier of a single candidate-action run
 * @param faultFamily declared controlled fault family for this run
 * @param enforcementPoints number of distinct logical policy enforcement points
 * @param stalePoints number of enforcement points initially allowing revoked access
 * @param cacheTtlMs simulated cache time-to-live, in milliseconds
 * @param propagationDelayMs simulated policy propagation delay, in milliseconds
 * @param trafficRps intended legitimate-request workload rate
 * @param dependencyDepth planned depth of the supporting service dependency graph
 * @param redundancy planned number of redundant instances for impact analysis
 * @param seed deterministic seed shared across paired action replays
 */
public record ScenarioConfiguration(
        String runId,
        String faultFamily,
        int enforcementPoints,
        int stalePoints,
        int cacheTtlMs,
        int propagationDelayMs,
        int trafficRps,
        int dependencyDepth,
        int redundancy,
        long seed) {

    /** Fault labels accepted by the reproducible, versioned laboratory protocol. */
    public static final Set<String> FAULT_FAMILIES = Set.of(
            "stale_cache", "lost_event", "delayed_event",
            "duplicate_event", "silent_rebuild", "reordered_event");

    /**
     * Validates all parameters when a configuration is first constructed.
     *
     * <p>Rejects uncontrolled resource allocations, unknown fault labels, and
     * impossible target counts before the trial state is modified. Restricting
     * values also prevents unauthenticated test clients from using this fixture
     * as an arbitrary load generator. The host environment must still expose
     * the laboratory on localhost only.</p>
     *
     * @throws IllegalArgumentException when any required field or bound is invalid
     */
    public ScenarioConfiguration {
        if (runId == null || runId.isBlank() || runId.length() > 128) {
            throw new IllegalArgumentException("runId must contain 1..128 characters");
        }
        if (faultFamily == null || !FAULT_FAMILIES.contains(faultFamily)) {
            throw new IllegalArgumentException("Unknown controlled fault family");
        }
        if (enforcementPoints < 2 || enforcementPoints > 8) {
            throw new IllegalArgumentException("enforcementPoints must be 2..8");
        }
        if (stalePoints < 1 || stalePoints >= enforcementPoints) {
            throw new IllegalArgumentException("stalePoints must be 1..(enforcementPoints-1)");
        }
        if (cacheTtlMs < 50 || cacheTtlMs > 5000) {
            throw new IllegalArgumentException("cacheTtlMs must be 50..5000");
        }
        if (propagationDelayMs < 0 || propagationDelayMs > 5000) {
            throw new IllegalArgumentException("propagationDelayMs must be 0..5000");
        }
        if (trafficRps < 1 || trafficRps > 1000) {
            throw new IllegalArgumentException("trafficRps must be 1..1000");
        }
        if (dependencyDepth < 1 || dependencyDepth > 6) {
            throw new IllegalArgumentException("dependencyDepth must be 1..6");
        }
        if (redundancy < 1 || redundancy > enforcementPoints) {
            throw new IllegalArgumentException("redundancy must not exceed target count");
        }
    }
}
