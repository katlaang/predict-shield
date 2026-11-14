# Demonstrating AI action-decision value with physical evidence

**Status as of November 14, 2026: evaluation machinery implemented, AI superiority NOT demonstrated.**

PREDICT-SHIELD's predictive threat-ranking AI has been fitted on historical EPSS/CISA KEV data, but an independent October proxy evaluation showed worse average precision than an EPSS-only comparator. The mechanism lab already has a RandomForestRegressor action-effectiveness trainer designed for 1,200 real Kafka/JVM physical replays. **The required complete 1,200-action dataset does not exist yet** and the full six-family v3.1 campaign remains blocked pending feasible physical mechanism and preregistered utility.

The new `decision_superiority_audit.py` evaluates **actual decisions**, not only prediction MAE. Its only scientific data path is `train.py` after `load_executed_dataset` has joined and checked 1,200 executed actions across independent pre-action, verifier, operational, and privileged oracle streams. No manifest-only or incomplete records can create a training report. The model's feature vector is pre-action telemetry and candidate-action identity, **never** the hidden fault identity, post-action results or privileged oracle truth.

## Comparison designed before final testing

- **Training:** 60 independently registered configurations used to fit predictive action effects and the rule-grid baseline; every configuration has the same set of four action replays over three repeats.
- **Calibration:** 20 separate configurations choose the single strongest **eligible** non-AI comparator from operator-telemetry rules, engineering rules, training-fitted grid rule, and feasible fixed policies. The comparator and any model-calibration choices are locked before reading held-out test outcomes.
- **Held-out test:** 20 untouched configurations, group-level averaging of repeated physical action costs, followed by 2,000 configuration-cluster bootstrap resamples of paired *calibration-selected baseline regret minus AI regret*. Repeats never count as independent infrastructures.
- **Predeclared diagnostic target:** baseline regret must be positive, at least 20 independent held-out groups must exist, and the lower 95% bootstrap bound of **relative group-paired regret improvement** must exceed 10%. Additionally, the model must beat **all seven** predeclared non-AI comparator policies by at least 10% at a conservative one-sided Bonferroni-adjusted lower bootstrap bound (0.05/7 per comparison). No positive conclusion may depend on selecting a favorable or unusually weak baseline. These bootstrap bounds remain dependent on configuration exchangeability and do not establish safety under distribution shift.
- **Safety:** all choices honor the declared independent restart-freeze permission. Every physical replay is needed to compute hindsight regret, but replaying a laboratory-prohibited intervention does not authorize deployment. The module rejects authority-offline UNKNOWN outcomes as point-value labels.
- **Negative results are retained:** when the baseline has zero regret, relative advantage is undefined and the report explicitly does not support superiority. The strongest comparator is selected on calibration, never retrospectively chosen to make the test favorable.

Use **only when the complete independent physical dataset is available and frozen**:

```bash
python train.py \
  --records /secure/measured-v3-physical-records \
  --report /secure/heldout-ai-decision-report.json
```

The report includes `heldout_decision_superiority_audit`, the locked non-AI comparator and all other comparator regrets, group-paired bootstrap uncertainty, group counts and the exact measured joined-data fingerprint. It does **not** automatically dispatch a model action, turn off fail-closed policy or claim external performance.

The existing registered v3 mechanism dataset uses four fault families, not the proposed six-family v3.1 protocol. Even if its held-out results eventually show positive model value in this lab, that would establish only a limited, testbed-specific performance result. It **cannot** justify a claim of national critical-infrastructure resilience or generalize across sectors, infrastructure operators, operational dependencies or evolving adversaries.

## What would count toward externally validated U.S. infrastructure impact

A credible progression requires separately collected field/partner evidence, not GitHub stars or simulated traffic alone:

1. Obtain an operator's written permission and a bounded, safe test environment. A small broadband operator, managed critical-service platform, or another infrastructure operator could be one application; this framework is not limited to one sector.
2. Prespecify the operational impact outcomes with the operator: time to detect/contain/remediate, independently verified unauthorized-access duration, legitimate-service disruption, false remediation assurance, recovery time and operational cost.
3. Use a comparable approved deterministic operational baseline and the same scope, load, eligibility, budget, affected-service closure and observation timing for each action policy. No experiment may disrupt live critical services without operator approval.
4. Require an independent assessor, separate oracle/inventory records, reproducible source versions, failure and negative-case reporting, and at least one credible site-specific generalization analysis.
5. Report the exact sample and uncertainty. Do not extrapolate national economic or security benefits without independently grounded exposure and adoption evidence.

**Current conclusion:** This PR supplies a falsifiable AI decision-value experiment and an evidence path. It does not supply the outcome of that experiment or an external pilot. Passing synthetic unit tests validates software contracts, not AI superiority.
