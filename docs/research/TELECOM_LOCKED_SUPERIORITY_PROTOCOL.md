# Locked, externally adjudicated AI discovery superiority protocol

The user-requested goal is **AI chooses and discovers better than strong deterministic alternatives**, not just synthetic unit success. This protocol evaluates AI missing-link ranking against an explicit strong rule that uses LLDP neighbors, routing adjacency or independently observed bidirectional flows.

The evaluator consumes **every** candidate from a preregistered set of heldout network topology groups, records model and deterministic scores at the same 0.5 threshold, and compares **paired per-topology accuracies**. It reports a fixed-seed topology-level 95% bootstrap interval for the difference in accuracy. It refuses missing topologies, duplicated pairs, unknown labels and unlabeled positives. Minimum independent topology count for the prespecified superiority claim: **8**; confidence interval lower bound must exceed zero. Different network vendors, protocols and service-loss conditions are needed for generalization beyond any one lab.

A positive metric on synthetic data is **not evidence of superiority**. The independent ground-truth label needs an external checkable artifact, such as instrumented cabling/port connectivity, validated container-network membership, or separate hardware inventory. Labels must be collected by a process isolated from the predictor and cannot be deduced from the exact same LLDP/flow indicators passed as features. Label evidence IDs must be preserved. The `--externally-attested-truth` switch is an **operator assertion**, not a cryptographic verification; an independent audit must substantiate it before publication.

Workflow:

```bash
cd experiment-b/telecom-topology
python independent_discovery_eval.py \\
 --cases /private/heldout-paired-predictions.json \\
 --registered-groups /private/heldout-topology-ids.json \\
 --output /private/independent-discovery-evaluation.json
```

The graph learner `link_learning.py` now retains `paired_test_predictions` in its post-hoc evaluation report. If labels have no truth evidence IDs or are synthetic fixtures, do not issue a positive independent conclusion.

As of this addition **there is no externally independently verified eight-topology physical benchmark** in the repository. Existing three-agent SNMPv3 physical labs demonstrate read-only missing-device discovery only. They are not AI link-superiority evidence. A negative or inconclusive evaluation must be preserved and the model not tuned on that heldout set.
