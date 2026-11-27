# Measured telemetry-corrected physical defense pilot, seed 20261129

**Evidence category:** exploratory lab physical action measurements and retrospective result summary. **Not an AI superiority finding.**

## Provenance and measured setup

- Execution: [GitHub Actions run 45942687859](https://github.com/katlaang/predict-shield/actions/runs/45942687859), completed with conclusion **success** (successful execution, not demonstrated defensive superiority).
- Source PR head before outcome: `9dfca093413c48abcbed291ab313cd5be2e35d72`.
- Registered plan seed: `20261129`; selected independent configuration `mechanism-005`.
- Actual campaign: 12 physically executed actions, zero excluded, zero partial, zero invalid; 4 action arms × 3 matched repeats for **one** configuration group.
- Model fingerprint: `87208240dbea19b34c4a5ac067639ac9cdb484b2de8f1985dbbcd143d4fe3b39`.
- Measured four-stream dataset digest: `34e4bd928a6279158d03a2335328ad6c8f5b05dead8e26b1608500e9b44e0cf6`.
- Aggregate/report artifact ID: `15173626130`. Downloaded ZIP SHA-256: `b8918a68dcaf38cd7cddb6a49744785c0a4d62d68428e152214c885bf5ee9110`.
- Physical records artifact ID: `15173577256` (separate limited-retention raw streams).
- Independent post-action security oracle and measured service request failures are separated from model input. The comparison remains offline: the AI proposed counterfactual actions against separately executed physical arms; it did not control execution in this workflow.

## Live telemetry integration

The preflight step reported **4/4 observed operator feeds**, all accepted with `operator_pre_action_v2`. The runner successfully completed the physical measurement and scoring steps. The scored report records **zero learned-policy abstentions** and **zero prohibited recommendations**, unlike the earlier broken-schema cohort.

**Artifact formatting caveat:** the preflight JSON artifact has a two-character trailing literal backslash-n sequence after the closing JSON object, making the raw file invalid under strict JSON parsing. Stripping that suffix reproduces the 4/4 observed preflight records. This serialization defect is separate from the operator collection result; the next workflow revision fixes it. The original artifact remains unchanged.

## Measured outcomes

| Offline policy evaluated on measured action arms | Independently verified resolved exposures | Failed legitimate requests | Recorded disruption-budget breaches | Mean grouped composite cost |
|---|---:|---:|---:|---:|
| Learned selector | 1/3 | 14 | 0 | 0.292542 |
| Fixed monitor-only | 0/3 | 0 | 0 | 0.319283 |
| Fixed resynchronization | 0/3 | 0 | 0 | 0.250453 |
| Restart if authorized | 3/3 | 50 | 0 | 0.245744 |

Recorded learned choices: monitor-only for repeat 0; restart for repeat 1; resynchronization for repeat 2. The source reported **no abstention reasons**, because the selector did not abstain.

**Interpretation:** the telemetry contract defect was addressed sufficiently for this lab cohort to produce non-abstaining proposals. The AI resolved fewer exposures than the eligible restart baseline, despite fewer failed legitimate requests. The fixed resynchronization policy also had a lower composite cost than AI here. This does **not** establish AI decision superiority.

**Limits:** One configuration and three correlated replays are too few for generalization. Counterfactual actions were separate physical resets, not simultaneously executed production alternatives. The composite weights are inherited and should never hide direct security or disruption outcomes.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
