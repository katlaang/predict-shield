# PREDICT-SHIELD AI advantage research target: 99.9%

**Research aim:** show that AI-assisted discovery of unknown ISP/telecom assets, interfaces, dependencies, and misconfigurations is demonstrably better than strong conventional discovery **under incomplete, conflicting, and noisy observations**, without sacrificing critical-infrastructure service continuity.

99.9% is a **prospective target**, not an observed result. Existing physical reconfigured virtual-network experiment: 80/80 heldout AI and 80/80 strong deterministic rule, **zero measured gain**. Do not present the old dataset as a success.

## Prespecified primary discovery endpoint

- Per-candidate **accuracy >=99.9%** and its two-sided 95% Wilson lower bound >=99.9%.
- **Recall >=99.9%** on truly present assets/links, with Wilson lower bound >=99.9%, avoiding impressive accuracy from a majority-negative dataset.
- **Specificity >=99.9%** on verified absent assets/links, with Wilson lower bound >=99.9%. Precision, false-positive and false-negative counts are separately reported.
- AI **paired improvement against the strongest applicable deterministic baseline** with the lower bound of a group-bootstrap 95% interval strictly greater than zero.
- At least 10,000 adjudicated cases, at least 4,000 present and 4,000 absent cases, and at least 20 preregistered **independent network groups** for the initial research gate. These are minimum evidence thresholds, not a guarantee of generalization. If sources are repeated reconfigurations of the same devices, count them as the same deployment family for independence.
- Frozen model, frozen feature engineering, frozen baselines and fixed decision threshold before opening held-out labels. Every registered case is counted. Missing ground truth, abstentions, and partial observation cannot be silently scored correct.

Use `prospective_advantage.judge` to enforce the quantitative claim gate. It reports accuracy, recall, specificity, precision, all confusion-matrix counts, Wilson lower bounds, per-group paired deltas, and fixed-seed group-bootstrap interval.

## Experiments designed around a plausible AI advantage

1. **Conflicting identity:** sensor exports contain rotated management addresses, stale hostnames, duplicate LLDP chassis IDs, missing serials, and cross-vendor naming differences. Ground truth requires independently registered equipment serial identifiers. Compare AI identity matching with deterministic exact serial/management ID matching plus a strong normalized-rule matcher.
2. **Missing paths:** randomly omit or delay independently collected LLDP, gNMI, routing, and SNMP sources according to a **locked pre-specified mechanism**. Train on other network sites and verify hidden edges independently. Compare against strong LLDP, routing, flow, two-hop, graph closure, and site-based deterministic baselines.
3. **Unknown dependencies:** simulate shared authentication, DNS, MPLS and aggregation bottlenecks; independently record which customer/service outcomes depend on each asset. Compare graph-trained classifiers against shortest-path/criticality heuristics, not a deliberately weak comparator.
4. **Adaptive defense:** train AI to predict risk reduction and legitimate service disruption. A separate deterministic policy limits actions, independently validates true remediation, and measures service budgets. Hold out entire deployments and fault families.

## Experimental integrity

Synthetic data is allowed for initial unit tests and model debugging but **cannot** be used as independent real-world evidence. Real lab routers/virtual networks are not independent external ISP operator sites. Never alter the locked test set after seeing results or discard difficult samples. A flawless deterministic comparator on complete data is a valid result, not a failure of the study.

If the model does not attain 99.9% with defensible statistical support and a positive advantage, the official status remains **NOT ESTABLISHED**. That result informs the next training set and must be retained. A future separate confirmatory holdout is required after material model changes.

**Security safety:** A 99.9% discovery result does not authorize autonomous mitigation. Risk estimation, action selection, approval and independent post-action verification must satisfy separate operational safety constraints.
