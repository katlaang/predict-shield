# New prospective physical experiment: trained AI policy against strong conventional defenses

**Scope:** a single scientifically meaningful experiment, not a new cybersecurity subsystem. The original 1,200 physical Kafka/JVM fault-and-action replays produced a trained relative-benefit model in [run 43682077804](https://github.com/katlaang/predict-shield/actions/runs/43682077804). Its exact joblib artifact SHA-256, frozen **before this experiment**, is:

`35a040b26a935bfb529f6247dbd0be1a01288294f8fb7089d4de60366adf3f92`

The historical train-group exploratory CV mean monitor-minus-AI regret was about 0.00370. On historical calibration, AI regret was approximately 0.02413 versus monitor-only at 0.03534, with its paired 95% confidence interval including a possible deficit. **Neither historical result is confirmatory superiority**. This new study remedies the old-holdout reuse problem by running entirely fresh physical configurations after the model is frozen.

## Exact plan registered before executing any outcome

- **24 new operating configurations**, using seed `20261115071` to create a distinct operating manifest. IDs use `fresh-benefit-...` and do not overlap with the 1,200 historical groups.
- **Four actual Kafka policy-event fault families:** loss, delay, duplicate, reorder, exactly two configurations per fault for each of three strata: SIMPLE, INTERACTION and PARTIAL_VISIBILITY.
- **Two physical repetitions per configuration**, with four real candidate actions physically replayed from the matched initial state: resync_policy, restart_enforcer, gateway_restrict, monitor_only. Total **192 new physical actions**. A prohibited restart may be physically measured in a disposable lab but must never be selected by the policy when `restart_permitted=false`.
- The unchanged Java/Kafka four-JVM deployment injects faults, independently probes the gateway, records legitimate HTTP failures and a separate full-scope oracle. Four-stream physical audit is required on **all 192** outcomes; no incomplete or synthetic labels can be accepted. Raw privileged oracle snapshots are deleted and never published.
- The trained model and its **0.01 minimum predicted improvement threshold** remain immutable and are loaded only after checking exact precommitted model artifact SHA-256 and GitHub Actions training source.
- The *primary* conventional comparator is **fixed monitor-only**, the strongest of seven non-AI policies selected previously using the original historical calibration. All seven previously declared conventional policies are also scored. The previous training-fitted deterministic rule parameters are frozen, not optimized from these new outcomes.
- Pre-action features are operator-observable only; injected hidden fault identity/target and post-action oracle data are not model inputs. The AI selects an action **offline before its measured outcome is revealed**, without dispatching production controls.
- Primary score: predeclared exposure/operational-disruption utility. Per physical condition the selected action's actual observed cost is compared to the independent measured hindsight-optimal eligible alternative. The strong rule and AI have the same candidates and replay results.
- Statistical independence unit is the **24 configured operating conditions**, not 48 repeated decision points or 192 replays. Group-paired bootstrap `5000` fixed seed `20261115077` and Bonferroni-corrected one-sided `0.05/7` thresholds. A preliminary positive lab decision-value conclusion is allowed only if the lower paired relative improvement bound exceeds **10% against every one of seven** strong non-AI rules **and** no AI-chosen action exceeds the declared legitimate-service error allowance.
- Any negative result, abstention, unsafe action, tie, failed experimental shard or missing oracle observation stays in the original evidence. Never change the seed, frozen model, objective, group membership, action eligibility or baselines in response to the outcome.

## Important caveats

This is a **new physical software-lab test**, not a production ISP field trial. It uses the same underlying four-JVM topology, so transfer beyond that environment is unproven. All actions are experimentally replayed and the AI's choices compared **offline** to independently observed outcomes. This test cannot by itself establish real-time autonomous execution safety or a causal production benefit. The failed-service budget is a preregistered lab allowance, not a verified operator's remaining SLO.

If the new study reports insufficient or negative evidence, that is a valid scientific result. The previously examined original 20-group test cannot be reused as a second confirmation. Distinguish laboratory evidence from actual U.S. critical-infrastructure effectiveness.

**Execution:** `.github/workflows/prospective-paired-action-physical.yml` runs three disposable physical shards in parallel and scores the **frozen** model only after all three have completed. GitHub Actions retains all 192 sanitized action outcomes, exact source/protocol hashes, case-by-case AI choices, seven baselines, paired uncertainty and any budget exceedances.
