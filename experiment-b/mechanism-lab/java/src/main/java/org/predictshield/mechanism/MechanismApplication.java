package org.predictshield.mechanism;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Launches the Experiment B mechanism laboratory.
 *
 * <p>The same image serves distinct independently running processes. The
 * LAB_ROLE environment property chooses an authoritative policy publisher or
 * an enforcement point. Kafka delivers actual revision events to independently
 * cached policies; this fixture does not assign defense decisions to an AI
 * model, and it must never connect to production infrastructure.</p>
 *
 * <p>Spring Kafka is configured using SPRING_KAFKA_BOOTSTRAP_SERVERS. Each
 * enforcement point must use a unique consumer group so every replica receives
 * policy updates rather than dividing them among members of one group.</p>
 */
@SpringBootApplication
public class MechanismApplication {

    /**
     * Boots the laboratory's Spring context with environment-specific roles.
     *
     * @param args command-line Spring configuration overrides, if any
     */
    public static void main(String[] args) {
        SpringApplication.run(MechanismApplication.class, args);
    }
}
