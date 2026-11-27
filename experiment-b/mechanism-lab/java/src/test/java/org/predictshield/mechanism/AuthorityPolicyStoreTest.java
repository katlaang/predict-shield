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
    void staleRevisionAndSameTrialUnrevocationFailClosed() throws Exception {
        Path file = dir.resolve("policy.txt");
        AuthorityPolicyStore store = new AuthorityPolicyStore(file);
        store.loadOrInitialize();
        String trial = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        String nextTrial = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
        PolicyRevision revoked = new PolicyRevision(11, true, trial);
        store.save(revoked);
        String previousBytes = Files.readString(file);

        assertThrows(IllegalStateException.class,
                () -> store.save(new PolicyRevision(11, false, nextTrial)));
        assertThrows(IllegalStateException.class,
                () -> store.save(new PolicyRevision(12, false, trial)));
        assertEquals(previousBytes, Files.readString(file));
        assertEquals(revoked, new AuthorityPolicyStore(file).loadOrInitialize());

        // A higher-revision, distinct-trial reset remains allowed.
        PolicyRevision reset = new PolicyRevision(12, false, nextTrial);
        store.save(reset);
        assertEquals(reset, new AuthorityPolicyStore(file).loadOrInitialize());
    }

    @Test
    void corruptedPolicyCannotBeOverwrittenByApparentlyNewRevision() throws Exception {
        Path file = dir.resolve("policy.txt");
        AuthorityPolicyStore store = new AuthorityPolicyStore(file);
        store.loadOrInitialize();
        store.save(new PolicyRevision(
                7, true, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        Files.writeString(file, "corrupt policy state");
        assertThrows(IllegalStateException.class,
                () -> store.save(new PolicyRevision(
                        8, false, "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")));
        assertEquals("corrupt policy state", Files.readString(file));
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
