# PREDICT-SHIELD architecture

PREDICT-SHIELD is an AI-centered, verification-grounded cybersecurity research framework with a deliberately strict boundary between predictions, permitted actions, external observations, and experimental ground truth.

The intended pipeline is:

```text
Security observations + threat/context snapshots
              |
       Risk assessment
              |
   Learned action-outcome estimator
              |
      Deterministic policy gate
              |
     Controlled action execution
              |
   Independent verification probes
              |
   Security + service-health outcomes
              |
  Versioned research data and evaluation
```

The current repository has the Python evidence evaluator, action-screening contracts, a Java 25 / Spring Boot testbed, reproducible experiment manifests, and preliminary measured-outcome training code. It does **not** yet provide end-to-end learned policy-constrained action selection or a production-grade independent evidence service.

See [the v2.2 implementation specification](../research/PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md) and [Experiment B setup](../../experiment-b/README.md).
