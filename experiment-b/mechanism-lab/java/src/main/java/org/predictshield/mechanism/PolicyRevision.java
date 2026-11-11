package org.predictshield.mechanism;

/**
 * Immutable authoritative or cached authorization policy revision.
 *
 * <p>Revisions are monotonically increasing. Enforcement points must ignore
 * events older than their current revision to prevent delayed or reordered
 * policy updates from silently restoring a revoked permission. The policy
 * describes one disposable test identity, never a real user's credentials.</p>
 *
 * @param revision monotonic revision number assigned by the authority
 * @param revoked true when the test identity must be denied
 */
public record PolicyRevision(long revision, boolean revoked) {

    /**
     * Validates that the policy revision can be ordered against earlier events.
     *
     * @throws IllegalArgumentException when revision is negative
     */
    public PolicyRevision {
        if (revision < 0) {
            throw new IllegalArgumentException("revision must be nonnegative");
        }
    }
}
