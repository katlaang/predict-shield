package org.predictshield.mechanism;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.ListOffsetsResult;
import org.apache.kafka.clients.admin.OffsetSpec;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Isolated, independent, read-only Kafka consumer-group offset witness.
 * Never joins/commits a group, produces a record or reads privileged
 * experiment fault/oracle evidence. Offsets do not prove correct processing.
 */
@RestController
@ConditionalOnProperty(name = "lab.role", havingValue = "broker-observer")
public final class BrokerOffsetObserver {
    static final String TOPIC = "lab-policy";
    static final List<String> GROUPS = List.of(
            "enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden");
    private final String token;
    private final String bootstrapServers;

    public BrokerOffsetObserver(
            @Value("${lab.observer-token:}") String token,
            @Value("${spring.kafka.bootstrap-servers:}") String bootstrapServers) {
        this.token = token;
        this.bootstrapServers = bootstrapServers;
    }

    @GetMapping("/operator/broker-offsets")
    public ResponseEntity<Map<String, Object>> getBrokerOffsets(
            @RequestHeader(value = "X-Lab-Observer", required = false) String supplied) {
        if (token == null || token.isBlank() || !token.equals(supplied)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("status", "REJECTED", "reason", "INVALID_OBSERVER_CREDENTIAL"));
        }
        if (bootstrapServers == null || bootstrapServers.isBlank()) {
            return unavailable("BROKER_NOT_CONFIGURED");
        }
        String startedAt = Instant.now().toString();
        Map<String, Object> groups = new LinkedHashMap<>();
        try (Admin admin = Admin.create(Map.of(
                "bootstrap.servers", bootstrapServers,
                "client.id", "predict-shield-readonly-broker-observer",
                "request.timeout.ms", "3500",
                "default.api.timeout.ms", "5000"))) {
            var descriptions = admin.describeTopics(List.of(TOPIC)).allTopicNames()
                    .get(5, TimeUnit.SECONDS);
            var described = descriptions.get(TOPIC);
            if (described == null || described.partitions().isEmpty()) {
                return unavailable("TOPIC_NOT_FOUND");
            }
            List<TopicPartition> partitions = described.partitions().stream()
                    .map(x -> new TopicPartition(TOPIC, x.partition()))
                    .sorted(Comparator.comparingInt(TopicPartition::partition)).toList();
            Map<TopicPartition, OffsetSpec> latestRequest = new LinkedHashMap<>();
            for (var partition : partitions) {
                latestRequest.put(partition, OffsetSpec.latest());
            }
            Map<TopicPartition, ListOffsetsResult.ListOffsetsResultInfo> latest =
                    admin.listOffsets(latestRequest).all().get(5, TimeUnit.SECONDS);
            if (!latest.keySet().containsAll(partitions)) {
                return unavailable("MISSING_BROKER_LOG_END");
            }
            for (String group : GROUPS) {
                Map<TopicPartition, OffsetAndMetadata> committed = admin
                        .listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata()
                        .get(5, TimeUnit.SECONDS);
                Map<String, Object> observation =
                        offsetsForGroup(group, partitions, committed, latest);
                if (!"MEASURED".equals(observation.get("status"))) {
                    return unavailable((String) observation.get("reason"));
                }
                groups.put(group, observation);
            }
        } catch (Exception error) {
            // Do not expose broker internals or authenticated hostnames.
            return unavailable("BROKER_READ_UNAVAILABLE");
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("schema", "predict-shield/broker-offset-witness/1");
        response.put("status", "MEASURED");
        response.put("observation_type", "kafka_admin_readonly");
        response.put("topic", TOPIC);
        response.put("started_at", startedAt);
        response.put("completed_at", Instant.now().toString());
        response.put("groups", groups);
        response.put("consumer_lag_definition", "log_end_minus_committed_offset");
        response.put("atomic_snapshot", false);
        response.put("group_membership_observed", false);
        response.put("payload_contents_read", false);
        response.put("security_outcome_verified", false);
        response.put("field_effectiveness_validated", false);
        return ResponseEntity.ok(response);
    }

    /** Strict arithmetic seam, tested without a live broker. */
    static Map<String, Object> offsetsForGroup(
            String group, List<TopicPartition> partitions,
            Map<TopicPartition, OffsetAndMetadata> committed,
            Map<TopicPartition, ListOffsetsResult.ListOffsetsResultInfo> latest) {
        if (!GROUPS.contains(group) || partitions == null || partitions.isEmpty()
                || committed == null || latest == null) {
            return unknown("UNKNOWN_GROUP_OR_PARTITIONS");
        }
        long total = 0L;
        List<Map<String, Object>> rows = new ArrayList<>();
        for (TopicPartition partition : partitions) {
            if (!TOPIC.equals(partition.topic())) {
                return unknown("UNREGISTERED_TOPIC");
            }
            var next = committed.get(partition);
            var last = latest.get(partition);
            if (next == null || last == null || next.offset() < 0
                    || last.offset() < 0 || next.offset() > last.offset()) {
                return unknown("MISSING_OR_INCONSISTENT_OFFSETS");
            }
            long behind = last.offset() - next.offset();
            try {
                total = Math.addExact(total, behind);
            } catch (ArithmeticException e) {
                return unknown("OFFSET_TOTAL_OVERFLOW");
            }
            rows.add(Map.of("partition", partition.partition(),
                    "committed_offset", next.offset(),
                    "log_end_offset", last.offset(), "committed_backlog", behind));
        }
        return Map.of("status", "MEASURED", "consumer_group", group,
                "total_committed_backlog", total, "partitions", rows);
    }

    private static Map<String, Object> unknown(String reason) {
        return Map.of("status", "UNKNOWN", "reason", reason);
    }

    private static ResponseEntity<Map<String, Object>> unavailable(String reason) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
                Map.of("schema", "predict-shield/broker-offset-witness/1",
                        "status", "UNKNOWN", "reason", reason,
                        "security_outcome_verified", false));
    }
}
