package org.predictshield.mechanism;

/**
 * Immutable authorization revision scoped to exactly one experimental trial.
 *
 * <p>Each reset allocates a new opaque, non-secret trial identifier. Kafka
 * events and policy-cache refreshes carry that identifier. Enforcement
 * points reject policy events for any other trial, even when the late event
 * has a higher revision. Revision ordering applies only within one trial.
 * This is a research isolation mechanism, not a production authorization
 * protocol or a substitute for broker transactional guarantees.</p>
 *
 * @param revision monotonic authority revision within the current trial
 * @param revoked true when the disposable test identity must be denied
 * @param trialId nonblank opaque trial identity shared by event and policy
 */
public record PolicyRevision(long revision, boolean revoked, String trialId) {

    /**
     * Rejects corrupt or incomplete policy revisions before they become state.
     *
     * @throws IllegalArgumentException if revision is negative or trialId blank
     */
    public PolicyRevision {
        if (revision < 0 || trialId == null || trialId.isBlank()
                || trialId.length() > 128 || trialId.contains(",")) {
            throw new IllegalArgumentException("Invalid trial-scoped policy revision");
        }
    }

    /**
     * Constructs a pre-trial bootstrap marker that must never authorize
     * enforcement of an old Kafka event. Existing fixture construction
     * can use this before the authority establishes a trial identifier.
     *
     * @param revision initial nonnegative version
     * @param revoked initial synthetic authorization state
     */
    public PolicyRevision(long revision, boolean revoked) {
        this(revision, revoked, "unassigned");
    }
}
