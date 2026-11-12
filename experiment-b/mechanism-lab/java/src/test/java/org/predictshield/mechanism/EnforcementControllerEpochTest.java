package org.predictshield.mechanism;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Tests isolation of asynchronously delayed policy updates between trial epochs.
 *
 * <p>The experiment requires actual delayed Kafka callbacks never to modify a
 * successor trial's cache. These focused tests call the same Kafka callback
 * method exercised by the listener, without requiring a broker or a public
 * network. Docker integration separately verifies delivery from Kafka.</p>
 *
 * <p>Every case runs with disposable credentials, an unreachable laboratory
 * authority, and a cache TTL that cannot expire during the brief test. No
 * production authorization services are involved.</p>
 */
final class EnforcementControllerEpochTest {

    private static final String TRIAL = "11111111-1111-1111-1111-111111111111";
    private static final String OTHER = "22222222-2222-2222-2222-222222222222";

    private final EnforcementController controller = new EnforcementController(
            "test-enforcer", "test-control", "test-oracle",
            "http://127.0.0.1:1", "test-internal");

    /**
     * Releases the scheduled thread after each isolated unit test.
     */
    @AfterEach
    void cleanup() {
        controller.shutdownScheduler();
    }

    /**
     * Verifies the next trial cannot inherit a delayed update from the past.
     *
     * @throws InterruptedException when test execution is interrupted
     */
    @Test
    void pendingDelayedEventCannotMutateNewEpoch() throws InterruptedException {
        controller.reset("test-control", 30000);
        controller.bindTrial("test-control", TRIAL);
        controller.setFault("test-control", "delay", 200);
        controller.onEvent(TRIAL + ",7,true");
        controller.reset("test-control", 30000);
        Thread.sleep(400);

        Map<?, ?> state = (Map<?, ?>) controller.adminState("test-oracle").getBody();
        assertEquals(0L, state.get("revision"));
        assertEquals(Boolean.FALSE, state.get("revoked"));
        assertEquals(0L, state.get("pending_scheduled_callbacks"));
        assertTrue(((Number) state.get("old_epoch_callbacks_discarded")).longValue() >= 1);
    }

    /**
     * Verifies the current trial can still process genuine delayed updates.
     *
     * @throws InterruptedException when test execution is interrupted
     */
    @Test
    void delayedEventAppliesWithinItsOwnEpoch() throws InterruptedException {
        controller.reset("test-control", 30000);
        controller.bindTrial("test-control", TRIAL);
        controller.setFault("test-control", "delay", 25);
        controller.onEvent(TRIAL + ",8,true");
        Thread.sleep(220);

        Map<?, ?> state = (Map<?, ?>) controller.adminState("test-oracle").getBody();
        assertEquals(8L, state.get("revision"));
        assertEquals(Boolean.TRUE, state.get("revoked"));
        assertEquals(0L, state.get("pending_scheduled_callbacks"));
    }

    /**
     * Verifies a late broker event with a high revision cannot cross trials.
     *
     * <p>Unlike delayed callbacks that already entered the consumer scheduler,
     * this case injects the old trial message after the successor has bound a
     * new authoritative trial ID, modelling broker-side delivery latency.</p>
     */
    @Test
    void lateBrokerMessageIsRejectedByTrialId() {
        controller.reset("test-control", 30000);
        controller.bindTrial("test-control", TRIAL);
        controller.onEvent(TRIAL + ",7,true");
        controller.reset("test-control", 30000);
        controller.bindTrial("test-control", OTHER);
        controller.onEvent(TRIAL + ",999,true");

        Map<?, ?> state = (Map<?, ?>) controller.adminState("test-oracle").getBody();
        assertEquals(0L, state.get("revision"));
        assertEquals(Boolean.FALSE, state.get("revoked"));
        assertEquals(OTHER, state.get("trial_id"));
        assertTrue(((Number) state.get("rejected_trial_events")).longValue() > 0);
    }

    /**
     * Verifies two distinct Kafka revisions actually exercise the reorder path.
     */
    @Test
    void twoRevisionsTriggerReorderAndRespectMonotonicity() {
        controller.reset("test-control", 30000);
        controller.bindTrial("test-control", TRIAL);
        controller.setFault("test-control", "reorder", 0);
        controller.onEvent(TRIAL + ",7,true");
        controller.onEvent(TRIAL + ",8,true");

        Map<?, ?> state = (Map<?, ?>) controller.adminState("test-oracle").getBody();
        assertEquals(8L, state.get("revision"));
        assertEquals(Boolean.TRUE, state.get("revoked"));
        assertEquals(1L, state.get("reordered_event_pairs"));
    }

    /**
     * Verifies obsolete callbacks cannot restore a state in the next trial.
     *
     * @throws InterruptedException when test execution is interrupted
     */
    @Test
    void duplicateCallbackFromOldTrialIsDiscarded() throws InterruptedException {
        controller.reset("test-control", 30000);
        controller.bindTrial("test-control", TRIAL);
        controller.setFault("test-control", "duplicate", 0);
        controller.onEvent(TRIAL + ",11,true");
        controller.reset("test-control", 30000);
        Thread.sleep(100);

        Map<?, ?> state = (Map<?, ?>) controller.adminState("test-oracle").getBody();
        assertEquals(0L, state.get("revision"));
        assertEquals(Boolean.FALSE, state.get("revoked"));
    }
}
