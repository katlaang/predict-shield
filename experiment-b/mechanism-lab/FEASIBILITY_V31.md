# v3.1 exploratory feasibility gate: implementation and use

This gate is **not** itself the research preregistration and does not authorize the 1,200-trial campaign. It enforces the proposed v3.1 criteria in code on an explicitly separate **pilot** dataset.

A trusted independent exporter must construct JSONL records with schema `predict-shield/v31-audited-action-costs/1` after verifying all four separated streams of real physical action replays and reproducing the locked utility calculation. Each row represents one configuration/repeat, lists all four real action costs, the eligible actions, and the source Git commit. The raw stream auditor and provenance checks must happen **before** setting `measurement_verified=true`; the boolean alone is not proof.

The evaluator rejects incomplete action sets, mixed source revisions, nonpilot partitions, missing repeats, invalid costs and unexpected configuration IDs. It never takes held-out AI outcome data. Every decision counts as mismatch only if the prespecified fixed action is not within 0.001 of the best eligible measured action. At least 30% of pilot decisions must differ from the fixed baseline, and PARTIAL_VISIBILITY must contain at least two different **uniquely** optimal actions.

It provides a deterministic, 2,000-replicate **configuration-cluster** bootstrap CI of *fixed-vs-oracle* mean regret. The 10% threshold comparison is a **diagnostic only**, not a valid model-vs-baseline power calculation. Do not assert that passing this check proves future AI superiority or adequate power; inspect paired model prediction variance separately when an independent trained model becomes available.

If the gate fails, record `FEASIBILITY_INCONCLUSIVE` and document the failure. Do not retune scenario difficulty until the AI appears to win.

Usage after independently audited pilot records exist:

```bash
python feasibility_v31.py --audited-records /secure/v31-pilot-audited.jsonl \
  --fixed-action resync_policy --output /secure/v31-feasibility.json
```

No such validated v3.1 pilot data is currently produced by this module. The v3.1 scenario adapter, secure measurement exporter, physical pilot and protocol/tag freeze are still separate required engineering work.
