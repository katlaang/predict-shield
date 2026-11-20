package org.predictshield.mechanism;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthorityPolicyStoreTest {
    @TempDir
    Path dir;

    @Test
    void coldRestartLoadsExactRevocationAndTrial() {
        Path file = dir.resolve("policy.txt");
        AuthorityPolicyStore first = new AuthorityPolicyStore(file);
        assertEquals(0, first.loadOrInitialize().revision());
        PolicyRevision committed = new PolicyRevision(
                42, true, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        first.save(committed);
        PolicyRevision recovered = new AuthorityPolicyStore(file).loadOrInitialize();
        assertEquals(committed, recovered);
        assertTrue(recovered.revoked());
        assertEquals(42L, recovered.revision());
    }

    @Test
    void corruptExistingStateNeverFallsBackToImplicitAllow() throws Exception {
        Path file = dir.resolve("policy.txt");
        AuthorityPolicyStore store = new AuthorityPolicyStore(file);
        store.loadOrInitialize();
        store.save(new PolicyRevision(
                10, true, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        String original = Files.readString(file);
        Files.writeString(file, original.replace("revoked=true", "revoked=false"));
        assertThrows(IllegalStateException.class,
                () -> new AuthorityPolicyStore(file).loadOrInitialize());
        assertEquals(original.replace("revoked=true", "revoked=false"),
                Files.readString(file));
    }

    @Test
    void truncatedExistingFileIsNotInitializedOver() throws Exception {
        Path file = dir.resolve("policy.txt");
        Files.writeString(file, "PREDICT_SHIELD_AUTHORITY_V1\\nrevision=1\\n");
        assertThrows(IllegalStateException.class,
                () -> new AuthorityPolicyStore(file).loadOrInitialize());
        assertTrue(Files.readString(file).contains("revision=1"));
    }

    @Test
    void consecutiveCommittedRevisionsRemainOrderedAfterProcessRestart() {
        Path file = dir.resolve("policy.txt");
        AuthorityPolicyStore store = new AuthorityPolicyStore(file);
        store.loadOrInitialize();
        String trial = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        store.save(new PolicyRevision(1, false, trial));
        store.save(new PolicyRevision(2, true, trial));
        AuthorityPolicyStore nextJVM = new AuthorityPolicyStore(file);
        assertEquals(new PolicyRevision(2, true, trial), nextJVM.loadOrInitialize());
        nextJVM.save(new PolicyRevision(3, true, trial));
        assertEquals(new PolicyRevision(3, true, trial),
                new AuthorityPolicyStore(file).loadOrInitialize());
    }
}
