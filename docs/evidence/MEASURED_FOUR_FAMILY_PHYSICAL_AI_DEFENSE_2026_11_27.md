# Independently audited four-family physical AI defense experiment (2026-11-27)

**Evidence type:** New exploratory physical laboratory action measurements, evaluated by a frozen historical model offline. **Not confirmatory AI superiority; not U.S. critical-infrastructure field validation.**

## Measured provenance

- [GitHub Actions physical run 45943667234](https://github.com/katlaang/predict-shield/actions/runs/45943667234): completed **success**, including physical experiment, four-stream scoring, artifact retention and teardown.
- Source commit used for all physical records: `d9857b89165372d45e370e21db3f68d3868ce948`. Experiment protocol/code was committed before the new physical outcomes.
- Frozen v3.1 generated plan seed: `20261201`. Selected four different test configuration IDs: `mechanism-008` persistent loss, `mechanism-006` persistently paused consumer, `mechanism-004` self-healing delayed event, `mechanism-015` self-healing short-TTL loss. IDs are scoped by seed and are not globally new fault-family identities.
- Exactly **48 separate physical action arms** (four configurations × three repeats × four actions); **12 matched episodes across 4 configuration groups**.
- Four independent on-disk evidence streams, each with 48 records: `pre_action`, `verification`, `operations`, `oracle`. Independently rejoined by run ID and action/configuration/repeat. All four streams had the same 48 identities, and all 12 episodes had four distinct arms.
- Physical evidence artifact `15173569590`, downloaded ZIP SHA-256 `a9428b5ac49335e307428d1317a75d4e1921fc08869b5275edcd98a216730859`.
- Aggregates and plan artifact `15173897705`, downloaded ZIP SHA-256 `5aad0939ace19271a9752b6222af68188d14ba0258442d1844c5b94e6a2abc08`.
- Frozen trained model SHA-256: `87208240dbea19b34c4a5ac067639ac9cdb484b2de8f1985dbbcd143d4fe3b39`. Original historical training and calibration partitions retained. Live v2 operator telemetry preflight passed all four JVMs before the physical actions.
- Independent re-scoring of the raw oracle `after.all_revoked_access_denied` Boolean, observed `failed_requests`, and original pre-action authorized budget exactly reproduced the reported aggregate counts for all six evaluated policies.

## Actual measured outcomes

| Offline selector / baseline | Security exposures independently resolved | Failed legitimate requests | Measured budget breaches | Mean configuration cost |
|---|---:|---:|---:|---:|
| Historical learned AI selector | **9/12** | **0** | **0** | **0.113110** |
| Fixed restart if authorized, else monitor | 9/12 | 42 | 0 | 0.165874 |
| Fixed monitor-only | 6/12 | 0 | 0 | 0.182909 |
| Fixed resynchronization | 6/12 | 0 | 0 | 0.160148 |
| Fixed gateway restriction | 6/12 | 326 | 6 | 0.417275 |
| Predeclared transparent operator heuristic | 6/12 | 78 | 0 | 0.233890 |

The learned AI recorded **zero abstentions and zero prohibited recommendations**. The offline learned choices were monitor-only in five episodes, restart in three, and resynchronization in four. Exact per-episode choices are retained in the aggregate artifact. No learned policy executed interventions directly; all action arms were separately performed by the experimental campaign.

## Fault-family interpretation

| Registered configuration (3 episodes each) | Learned policy resolution | Restart-if-authorized resolution | Learned cost | Restart policy cost | Key interpretation |
|---|---:|---:|---:|---:|---|
| `mechanism-004`, self-healing delayed event | 3/3 | 3/3 | 0.0421 | 0.2239 | AI chose monitor-only and avoided 42 failed requests; fixed resync had lower measured path exposure |
| `mechanism-006`, persistent consumer pause | 3/3 | 3/3 | 0.0005 | 0.0005 | AI chose restart, matching the baseline |
| `mechanism-008`, persistent loss with restart not authorized | **0/3** | **0/3** | 0.3117 | 0.3016 | **Major unresolved security exposure.** AI chose monitor, resync, monitor; no authorized candidate resolved the threat in this lab |
| `mechanism-015`, self-healing short-TTL loss | 3/3 | 3/3 | 0.0982 | 0.1375 | AI chose resynchronization and achieved lower observed path-exposure cost; monitor-only also resolved 3/3 |

The aggregate mean cost improvement against restart-if-authorized is `0.113110 - 0.165874 = -0.052764`. At the configuration level, AI was better on two groups, tied on one, and worse on one. This is **not consistent superiority** and four groups are insufficient for reliable statistical inference. Direct security success also tied overall at 9/12.

The fixed gateway restriction exceeded the 25-request budget in six replays, illustrating why security containment must be evaluated separately from disruption. No result justifies relaxing prior authorization to permit restart when explicitly prohibited.

## Calibration and scientific limitations

Nominal 90% historical model intervals were observed to cover all outcomes for only **70%** of held-out configuration groups on residual security exposure and **60%** on gateway path exposure, versus **90%** for failed legitimate requests. The model therefore lacks a demonstrated reliable security-outcome uncertainty bound. A lower average utility cannot override this calibration deficit or the three unresolved persistent-loss episodes.

This is one **exploratory** laboratory test per fault family, with three correlated repeats. The single four-JVM/Kafka system is not four independent customer sites, and newly seeded configurations still use the already modeled fault classes. The counterfactual policy outcomes came from separate resets, not a randomized field trial; the AI chooser was not wired to the live executor in this study.

**Next evidence requirements:** independent authoritative telemetry for paused/publishing conditions; more configurations per family; withheld-publication scenarios where resync is uniquely effective; trustworthy calibrated security intervals on independent development/calibration groups; frozen strong expert baselines and predefined safety noninferiority margin; a sufficiently powered independently unseen confirmation; and external authorized critical-infrastructure assessment.

**AI decision superiority and critical-infrastructure effectiveness remain unproven.**
