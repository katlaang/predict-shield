package org.predictshield.mechanism;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/** Synthetic-only contract; the separate Docker lab proves physical behavior. */
class AuthorityWithheldPublicationTest {
    @Test
    void revisionMetadataIsNotPolicyTruthAndRequiresIndependentCredential() {
        var authority = new AuthorityController(null, "control-secret", "internal-secret");
        ReflectionTestUtils.setField(authority, "observerToken", "observer-secret");
        assertEquals(403, authority.operatorDesiredRevision("control-secret")
                .getStatusCode().value());
        assertEquals(403, authority.operatorDesiredRevision(null).getStatusCode().value());
        Map<?, ?> old = authority.operatorDesiredRevision("observer-secret").getBody();
        assertEquals(0L, old.get("desired_revision"));
        assertFalse(old.containsKey("revoked"));
        assertFalse(old.containsKey("fault"));
    }

    @Test
    void withheldPolicyCommitDoesNotCallKafkaPublisher() {
        // Null publisher proves the withholding operation cannot publish.
        var authority = new AuthorityController(null, "control-secret", "internal-secret");
        ReflectionTestUtils.setField(authority, "observerToken", "observer-secret");
        assertEquals(403, authority.revokeWithheld("observer-secret").getStatusCode().value());
        var result = authority.revokeWithheld("control-secret");
        assertEquals(202, result.getStatusCode().value());
        assertEquals(Boolean.FALSE, result.getBody().get("publication_queued"));
        var visible = authority.operatorDesiredRevision("observer-secret").getBody();
        assertEquals(1L, visible.get("desired_revision"));
        assertFalse(visible.containsKey("revoked"));
        assertEquals(Boolean.FALSE, visible.get("security_outcome_verified"));
    }
}
