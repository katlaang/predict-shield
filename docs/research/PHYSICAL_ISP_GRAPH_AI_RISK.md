# Physical input to graph-aware AI risk prediction

This pilot collects **actual SNMPv3-authPriv sysName responses from three disposable Linux SNMP agents**, builds a typed asset graph, and measures the response of the **actual simulated access service** over localhost HTTP. A service-to-router edge is explicitly declared as a **synthetic scenario**, not claimed as independently observed physical topology.

The graph-aware logistic model is **genuinely fitted** on toy labeled graph cases using disjoint training/test graph group IDs. It then predicts a normalized score for the live observed `forgotten-c` agent. This is a **software and dataflow integration demonstration** only. Synthetic training labels and the deliberately declared dependency cannot establish real-world incident prediction, calibrated probabilities, or superiority over exposure-only deterministic rankings.

The predicted score retains `decision_authorized=false`. It is **not** sent to any telecom operator or the controlled lab executor. A future registered experimental protocol should collect independently verified security labels and compare group-heldout graph-aware predictions against strong deterministic impact/exposure baselines across actual distinct topologies. Results are retained as a GitHub Actions artifact on passing physical CI, including a clear false flag for AI superiority.
