# Predeclared v3.1 physical subset pilot (research exploratory)

This distinct v3.1 pilot fixes a **five-configuration, 40-replay subset** before execution. The five configurations use different real JVM targets, TTLs, loads, routing, complexity levels and policy constraints. Each has two physical repetitions of four actions. The seed is `20261114`, and action order is randomized within each registered configuration/repetition. It excludes the previously inspected single-condition consumer pause (enforcer-b / TTL 30,000ms / 25 RPS).

The five observable fault families are **loss, delay, duplicate, reorder and physical consumer pause**. This is *not the complete proposed six-family v3.1 protocol*: the external **authority_outage** collector is not supported by the current complete-state oracle when the authority is unavailable. The sixth family cannot be silently substituted with a synthetic label.

The runner requires distinct lab control and oracle tokens, a disposable Compose fixture, a registered plan SHA, the exact source revision and an exclusive lock. For each arm, it restarts from a clean state, ensures any paused Kafka listeners are physically resumed, executes the action with real HTTP load and Kafka events, collects separate pre-action, verification, operations and privileged oracle records, and verifies all four streams before continuing. Missing, incomplete or duplicated records are fatal.

The `export_v31_pilot.py` process independently rejects missing or mismatched source, oracle evidence and incomplete action arms. The group-level evaluator `feasibility_v31.py` computes diagnostic decision diversity, partial-visibility optima and a cluster bootstrap of *fixed-vs-hindsight* regret. **Its result is forcibly labeled `EXPLORATORY_SUBSET_INCONCLUSIVE`, even if its numerical diagnostic gates happen to pass.** This protects the full protocol from a favorable exploratory subset being misrepresented as final feasibility.

No pilot observations are committed to the repository. The GitHub Actions workflow retains only the sanitized derived feasibility report, removes privileged raw streams and tears down Compose in a cleanup step. It does **not** authorize starting the planned 150 × 4 × 2 campaign.

Execution in the disposable lab:

```bash
python run_v31_subset.py --execute-lab \
  --root /tmp/predict-shield-v31-subset \
  --output reports/v31-subset-feasibility.json
```

**Known inference limits:** two repeats do not make independent sample groups; the Java consumer jitter is a real, uncontrolled nuisance parameter and the common registered seed is not a deterministic control of all JVM scheduling. Restart-prohibited actions are physically replayed only for offline counterfactual study and are excluded from the feasible decision set. The source label `FEASIBILITY_INCONCLUSIVE` may result from diversity, partial visibility or limited precision; do not iteratively alter scenario difficulty to make the AI appear superior.

After this subset, implement a truthful authority-unavailable oracle with explicit unknown/inapplicable scope semantics; preregister a separate six-family representative feasibility sample; assess sample size; freeze all runnable v3.1 artifacts; only then consider the complete 1,200 physical trials.
