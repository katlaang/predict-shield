# AI-assisted telecom topology inference: protocol

**Purpose:** rank candidate missing links using an actual trained `LogisticRegression` model evaluated on held-out topologies. Synthetic fixtures establish mechanics only.

The input JSON is a **list of independently labeled candidate pairs**. Each row includes `topology_id`, `source`, `target`, `split` (`train` or `test`), `verified_link` (confirmed by evidence independent of model inputs), and six **pre-verification boolean features**:

- `lldp_seen`
- `routing_adjacency_seen`
- `bidirectional_flow_seen`
- `same_site`
- `interface_type_compatible`
- `inventory_edge_declared`

**Important:** obtaining the ground-truth link label from these same input features is leakage. Labels must come from independent, authoritative physical/operational verification. Never use a link's post-inference oracle observation as a feature. All rows from the same topology are required to remain in one partition. Parameters are fitted only on the training portion, and the separately grouped test portion is used for one evaluation against the baseline `lldp_seen OR routing_adjacency_seen`.

From `experiment-b/telecom-topology` run:

```bash
python -m pip install -r ../requirements-ml.txt
python link_learning.py --training-data /private/labeled-topology-candidates.json \\
  --model-output /private/link-model.json --report-output /private/link-metrics.json
python -m unittest test_link_learning -v
```

The output JSON stores logistic coefficients, feature order, training fingerprint and confusion metrics. The model score is **not calibrated**. All inferred edges have `INFERRED`, `physically_verified=false` and `requires_independent_confirmation=true`, regardless of high score. This does not feed remediation authorization.

Tests use synthetic topology fixtures to establish software integrity only. No real ISP or telecom dataset, field label, AI improvement or production topology has yet been demonstrated. Before publishing scientific results: create an authorized collection of several independent ISP-like lab topologies; preregister train/test topology splits, thresholds and primary link detection metrics; compare deterministic and learned methods under the same evidence; independently verify positives, negatives and unknowns.
