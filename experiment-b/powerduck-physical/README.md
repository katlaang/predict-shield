# Learned cross-stream physical-consistency detector

This is a **new implementation** of a normal-only, lagged, learned relationship between **two separately mapped measurement streams**. It is not a re-run of the unsuccessful single-message PowerDuck v3 isolation forest.

A technically valid field/stream pair must first be justified by a known topology or signal map. In a normal-only recording, the first 70% of causally aligned observations fits a linear model; the remaining 30% calibrates a 1% message residual threshold. Unknown relationships, absent observations, and insufficient normal variation **fail closed / INDETERMINATE**, not "benign". The model is frozen with a hash; a separate attack capture is then scored once.

Usage with **verified** IPAL JSONL input (raw or gzip):

    python physical_consistency.py \
      --normal /data/lab-normal.ipal.gz --attack /data/heldout-attack.ipal.gz \
      --primary-stream 'breaker>bus' --primary-field current_A \
      --reference-stream 'meter>bus' --reference-field current_A \
      --output-dir /tmp/physical-run

**The example stream names above are synthetic test fixtures, not real PowerDuck mappings.** They are not evidence that these signals exist in the original archive. Before testing the 16 historical PowerDuck captures, inspect the normal capture metadata and confirm a physically meaningful mapping with domain expertise. A test on previously scored PowerDuck captures would be exploratory, not a fresh untouched evaluation. Do not claim production grid performance from this code.

This model is one candidate for the AI-first detection program; manual policy approval and independent defensive outcome verification remain separate. No response actions are executed by this detector.
