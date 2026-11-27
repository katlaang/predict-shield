package org.predictshield.mechanism;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.kafka.clients.admin.ListOffsetsResult;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.Test;

class BrokerOffsetObserverTest {
    private static final TopicPartition P0 = new TopicPartition("lab-policy", 0);

    private static Map<TopicPartition, ListOffsetsResult.ListOffsetsResultInfo> end(long n) {
        return Map.of(P0, new ListOffsetsResult.ListOffsetsResultInfo(
                n, -1L, Optional.empty()));
    }

    @Test
    void computesCommittedBacklogWithoutConsumingOrCommitting() {
        var result = BrokerOffsetObserver.offsetsForGroup(
                "enforcer-b", List.of(P0),
                Map.of(P0, new OffsetAndMetadata(4L)), end(9L));
        assertEquals("MEASURED", result.get("status"));
        assertEquals(5L, result.get("total_committed_backlog"));
        assertEquals("enforcer-b", result.get("consumer_group"));
    }

    @Test
    void cleanCommittedOffsetCanHaveZeroBacklog() {
        var result = BrokerOffsetObserver.offsetsForGroup(
                "enforcer-a", List.of(P0),
                Map.of(P0, new OffsetAndMetadata(9L)), end(9L));
        assertEquals("MEASURED", result.get("status"));
        assertEquals(0L, result.get("total_committed_backlog"));
    }

    @Test
    void missingCommitNeverBecomesZeroLag() {
        var result = BrokerOffsetObserver.offsetsForGroup(
                "enforcer-a", List.of(P0), Map.of(), end(9L));
        assertEquals("UNKNOWN", result.get("status"));
        assertEquals("MISSING_OR_INCONSISTENT_OFFSETS", result.get("reason"));
    }

    @Test
    void invalidHighCommitAndUnknownGroupFailClosed() {
        var bad = BrokerOffsetObserver.offsetsForGroup(
                "enforcer-a", List.of(P0),
                Map.of(P0, new OffsetAndMetadata(20L)), end(9L));
        assertEquals("UNKNOWN", bad.get("status"));
        assertEquals("UNKNOWN", BrokerOffsetObserver.offsetsForGroup(
                "unregistered", List.of(P0),
                Map.of(P0, new OffsetAndMetadata(4L)), end(9L)).get("status"));
    }

    @Test
    void wrongTopicAndMissingPartitionsCannotBeReadAsSuccess() {
        var wrong = new TopicPartition("other", 0);
        assertEquals("UNKNOWN", BrokerOffsetObserver.offsetsForGroup(
                "enforcer-b", List.of(wrong),
                Map.of(wrong, new OffsetAndMetadata(4L)),
                Map.of(wrong, new ListOffsetsResult.ListOffsetsResultInfo(
                        10L, -1L, Optional.empty()))).get("status"));
        assertEquals("UNKNOWN", BrokerOffsetObserver.offsetsForGroup(
                "enforcer-b", List.of(), Map.of(), Map.of()).get("status"));
    }

    @Test
    void separateTokenRequiredWithoutAnyBrokerAccess() {
        var witness = new BrokerOffsetObserver("observer-token", "broker:9092");
        var rejected = witness.getBrokerOffsets("lab-control-token");
        assertEquals(403, rejected.getStatusCode().value());
        assertEquals("REJECTED", rejected.getBody().get("status"));
        assertEquals(403, witness.getBrokerOffsets(null).getStatusCode().value());
    }

    @Test
    void emptyBrokerAddressIsUnknownNotSuccess() {
        var witness = new BrokerOffsetObserver("observer-token", "");
        var unavailable = witness.getBrokerOffsets("observer-token");
        assertEquals(503, unavailable.getStatusCode().value());
        assertEquals("UNKNOWN", unavailable.getBody().get("status"));
    }
}
