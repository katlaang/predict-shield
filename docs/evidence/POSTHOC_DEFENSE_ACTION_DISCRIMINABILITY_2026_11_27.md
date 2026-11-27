# PREDICT-SHIELD: retrospective action-choice discriminability and new publication-gap control

**Scope:** Laboratory research evidence, not field validation, not a new learned-policy confirmatory evaluation.

## Original physically executed 1,200-trial archive

Primary measurement: [GitHub Actions original completed scored campaign 44879497946](https://github.com/katlaang/predict-shield/actions/runs/44879497946), archived measured `results/scored/pre_action`, `oracle`, `verification` and `operations` streams.

- Archive SHA-256 obtained from the downloaded original artifact: `08a8bb16ba3b50447510c15194acbb6a4c41534062c3fcf1aead626a9a7431e3`.
- Common recorded collector source revision: `4f154d399d7a3f88087d200be7299fd05b9b9016`.
- 1,200 unique action runs, 100 distinct configuration IDs, 3 repeats of 4 candidate actions per configuration; all four joined source streams had matching run/configuration/action identities in this retrospective read.
- The post-action oracle inventory and direct target observations were complete and contained Boolean all-target revocation results for each of the 1,200 recorded runs.
- **This report was assembled after the original results were visible.** It cannot serve as a preregistered analysis. The original protocol-hash mismatch remains separately disclosed in [issue #188](https://github.com/katlaang/predict-shield/issues/188).

### Post-action security resolution, without selecting on disruption

| Fault class (configuration groups) | Replays per action | Resync resolved | Restart resolved | Monitor-only resolved |
|---|---:|---:|---:|---:|
| Persistent Kafka event loss (35) | 105 | 0 | 105 | 0 |
| Persistent Kafka listener pause (35) | 105 | 0 | 105 | 0 |
| Self-healing short-TTL loss (15) | 45 | 45 | 45 | 45 |
| Self-healing delayed event (15) | 45 | 45 | 45 | 45 |

These are counts of *independently measured direct-target post-action authorization outcomes*, **not** rates of safe, authorized interventions and not comparisons of genuine independent customer sites.

### Restart safety and authorization are not optional

The experimentally declared disruption allowance was **25 failed legitimate requests** per replay. For restart, measured verified resolution **AND** no more than 25 failed legitimate requests held in:

- Persistent loss: **75/105** replays; among episodes where restart was also explicitly authorized, only **38/105** were both authorized and within budget while resolving.
- Persistently paused consumer: **88/105** replays; both authorized and within budget while resolving in **46/105**.
- Short-TTL self-healing loss: **39/45** replays; both authorized and within budget while resolving in **18/45**.
- Self-healing delay: **28/45** replays; both authorized and within budget while resolving in **16/45**.

Some restart actions were executed experimentally as **counterfactual laboratory arms despite `restart_permitted=false`**; those results are useful as physical outcome measurements but must never be counted as authorized interventions. An observed low-disruption result cannot be substituted for a valid advance safety authorization.

**Scientific problem:** On this 1,200-trial cohort, resynchronization never resolved an exposure that monitor-only failed to resolve. The model could not demonstrate selective benefit for a meaningful resynchronization case. Persistent faults generally required restart for exposure resolution, but restart was not always authorized or within the measured request-failure budget.

## New physical development control: withheld policy publication

[PR #190](https://github.com/katlaang/predict-shield/pull/190) added and merged an *independent development-only* Kafka control-plane publication-gap condition, measured in [GitHub Actions #45930364871](https://github.com/katlaang/predict-shield/actions/runs/45930364871), artifact `untrained-withheld-publication-development`.

The authority persisted a newer desired revoked revision but withheld the Kafka event. Both separately reset action arms had the following **pre-action operator observations**, before any private oracle read:

- All four enforcers' applied revisions were exactly **one revision behind** operator-observed desired revision.
- Kafka broker committed backlog was **zero for all four consumer groups**, consistent with no queued event but not independently proving the reason it was absent.
- The gateway returned **12 HTTP 200 responses** from the revoked test identity before the action in each arm.
- All listeners were required to be running and not paused; the source metadata deliberately did not include the injected fault label or revocation Boolean.

The separate post-action oracle then measured:

| Isolated development arm | Independent all-target revocation verdict |
|---|---|
| Monitor-only | **Not resolved** |
| Resynchronize policy | **Resolved** |

Both observations passed the source workflow's prerequired completeness assertions and final physical step. No model made a decision or was trained in this experiment, no service-disruption comparison was performed, and no confirmatory repetition across independent configurations was included.

## Decision

The new result establishes **one controlled scenario where resynchronization genuinely fixes an otherwise unresolved problem**. It does **not** establish that AI can identify that scenario from operator observations, that the policy is the least disruptive eligible intervention, that a hand-written expert rule would fail, or that the effect generalizes.

**Next study requirements:** physically replicate distinct publication-stage, paused-consumer, persistent-loss and self-healing conditions across source-pinned development configurations; measure legitimate traffic disruption and approval limits; compare adaptive models and a strong transparent expert rule on the same pre-action evidence; fix uncertainty calibration on separate development/calibration groups; register and freeze an entirely new independent confirmatory test.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
