# Incident feedback and learning: verified-label contract (first increment)

**Status:** Data-validation and held-out scoring contract, not a deployed learned
detector, automatic retraining system, proof of attack-detection accuracy, or
externally authenticated evidence.

## Why this exists

Existing rules detect selected endpoint patterns, and the AI rule-suggestion
experiment drafts bounded rules from training recordings. Neither output can
become a trusted learning label simply because the model or detector says so.

`engine/predict_shield/incident_feedback.py` introduces a narrow fail-closed
contract between an incident-response investigation and a *future* supervised
training pipeline. All input values are test/lab or operator-supplied;
`independent_review` must carry its own reviewer identifier and a digest of
separately collected evidence. The code checks the structure and requires
different identifiers and digests. **It does not authenticate a human reviewer
or establish that a labeled event really was an attack.** That must be proven by
an independent evaluation process and preserved original evidence.

## Evidence required for each incident

- Unique incident and asset-group IDs, a declared train/calibration/test
  partition, timestamp, source ID, and SHA-256 of original alert evidence.
- A reviewer record with ATTACK, BENIGN, or UNKNOWN outcome, reviewer ID,
  review time and a *different* SHA-256 of independent review evidence.
- Only the six explicitly enumerated *pre-action* signals are eligible model
  input features. Model prediction, post-action oracle, success acknowledgments
  and verified remediation results cannot be used as attack-prediction features.
- UNKNOWN labels remain counted but excluded from supervised labels. Review
  from the same source identity as the alert is refused. A single asset group
  cannot occur in different partitions.

`score_detection()` requires exactly one Boolean prediction for every reviewed
test incident and reports TP, FP, FN, TN, recall, precision and FPR with real
denominators. It does not manufacture performance when labels or a test set are
missing. The module intentionally never trains an AI model or authorizes a
defensive action.

## Verification

```bash
PYTHONPATH=engine python -m unittest engine.tests.test_incident_feedback -v
```

The test suite covers missed or unknown labels, duplicate predictions,
cross-partition leakage, post-action feature contamination, invalid data and
review-evidence provenance. Passing these checks **is not** evidence of
operational AI accuracy.

## Next work needed to make the AI truly learn

1. Obtain human-reviewed, independently supported ATTACK/BENIGN labels
   across *unseen sites* and *benign-only periods*, with operators' permission.
   Do not label the other 8,914 OTRF events BENIGN by subtraction.
2. Record immutable dataset/model versions; freeze the split before training;
   ensure temporal/site isolation and pre-register evaluation metrics and
   minimum acceptance criteria. Account for shared devices and repeated events.
3. Train a candidate detector using only pre-detection features and measure
   class imbalance, alert rates per host-day, precision, recall, calibrated
   uncertainty, cost and coverage on held-out infrastructure conditions.
4. Evaluate against deterministic rules and existing IDS tools for
   operational context, **without requiring AI to win** as a condition of a
   valid cybersecurity framework.
5. Keep every new detector in shadow mode until an authorized operator
   approves promotion. Model drift should trigger review/retraining proposals,
   not an automatic overwrite of the production model.
6. Connect accepted detections to authenticated intake, the existing
   risk-assessment/proposal path, an independent policy gate, authorized
   execution and independent outcome verification. Label corrections and
   incident closure must not be confused with remediation proof.
7. For electric grids, OT protective relays and essential control links stay
   outside autonomous actuation. Test actual network traffic, PLC/relay
   simulation and cyber-physical outcomes separately before proposing field use.

## Related experiments

- `experiment-b/public-sources/ai_rules/` for constrained LLM-suggested rules,
  frozen before held-out evaluation.
- `experiment-b/grid-lab/` for *decoupled* communications graph and AC feeder
  simulation with lab-only authority.
- `docs/evidence/PUBLIC_TEST_SOURCES.md` for pinned OTRF and other public
  inputs. Do not misread rule matches per event as attack-detection recall.
