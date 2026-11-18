# Graph-aware cybersecurity risk model: measured-label contract

The graph feature builder combines confirmed normalized exposure with the **observed/declared** network dependency graph, reachable critical services, neighbor uncertainty and edge counts. **Inferred edges are excluded** from authoritative reachability, preventing the AI's own guesses from recursively validating its scope.

The supervised training module `experiment-b/telecom-topology/graph_risk_training.py` trains logistic regression on **pre-action** graph features and **separately observed** binary incident outcomes. It enforces topology-group isolation, evaluates the learned model on held-out topology groups, and exports model coefficients. Predictions are not calibrated probabilities and **cannot authorize a defense**; production outcomes and controlled testbed validations are still pending.

The included tests use constructed toy graph records. To evaluate meaningfully, gather independently verified network topology and outcomes with separate data provenance and reject unknown incident status instead of treating it as negative. Never use inferred edges or post-action oracle information as prediction features.
