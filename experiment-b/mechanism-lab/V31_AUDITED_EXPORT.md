# v3.1 physical pilot: independently audited feasibility exporter

The exporter at `export_v31_pilot.py` is a read-only bridge between **actual four-stream laboratory records** and the configuration-level feasibility evaluator. It is not a data generator, not a campaign runner, and it cannot replace the v3.1 protocol freeze.

For each registered `v31-pilot-...` configuration, both repetitions and all four actions must have already been physically executed. The pilot registration must be separate from the 150 train/calibration/test groups. The exporter uses the existing four-stream `audit.inspect_trial` checks for run ID, action, partition, source commit, measured HTTP denominator, oracle completeness, and verification. It refuses partial or unregistered files, mixed commits, inconsistent policy eligibility and mismatched fault identities.

For a physically paused Kafka consumer, the privileged oracle record must contain an **observed** listener-pause witness from before the action, with the target still serving HTTP. This evidence must not enter the pre-action model record or influence action selection. The exporter independently computes primary utility from the measured upper time-integrated exposure bound, independently observed unresolved control state, and actual failed legitimate requests under the predeclared absolute budget.

Only then does the exporter produce `predict-shield/v31-audited-action-costs/1`, which `feasibility_v31.py` can score by independent configuration group. The output is **a derived summary**, not a source of truth for whether an action was performed. The full secure raw streams and exact immutable commit remain necessary for reproduction.

Usage, **only after a complete physical pilot**:

```bash
python export_v31_pilot.py \
  --plan-dir /secure/v31-physical-pilot-plan \
  --records /secure/v31-physical-pilot-records \
  --output /secure/v31-audited-costs.jsonl

python feasibility_v31.py \
  --audited-records /secure/v31-audited-costs.jsonl \
  --fixed-action resync_policy \
  --output /secure/v31-feasibility.json
```

The exporter does **not** implement authority-outage outcome collection or choose an optimal pilot sample. No v3.1 pilot data have been collected by this code. The current single-configuration consumer-action smoke is explicitly insufficient for the gate. Failure remains `FEASIBILITY_INCONCLUSIVE`; a favorable report would be a feasibility result, not AI superiority or campaign authorization.
