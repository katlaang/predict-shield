# Precision and feasibility sample-size caution (prospective planning)

This planning aid evaluates the **binary proportion of independent configuration groups where always-resync is not hindsight optimal**. It computes 95% Wilson score intervals under a simplifying independent-binomial assumption. It does **not** estimate trained-model gain, causal action effects, multiple-testing-adjusted error, or v3.1 campaign power.

The completed five-group exploratory physical pilot found 2/5 independent group mismatches, or 40%, but its 95% Wilson interval is approximately **11.8% to 76.9%**. The point estimate exceeds the proposed 30% threshold; the lower confidence bound does not. The result is therefore insufficient to establish that at least 30% of the broader scenario population favors some different action.

The new *draft* 18-group six-family feasibility registration is not automatically adequate. For 18 independent configurations, **10** mismatches would be needed for the **lower Wilson bound** to exceed 30%. That is a precision illustration, **not** a preapproved pass/fail rule for v3.1, and it must not be used to increase the sample selectively after observing interim results. Requirements for multiple distinct uniquely optimal partial-visibility actions add further uncertainty. Shared Kafka services, dependent fault-family responses and partial observations may violate the independent-binomial assumption.

The design check reports the observational count threshold separately from this stricter statistical lower-bound threshold, for 5, 18, 30, 90 and 150 independent groups. It never reads raw trial files or model outputs.

```bash
python -m unittest test_v31_precision_planning -v
python v31_precision_planning.py --output /tmp/v31-precision-planning.json
```

Before any final v3.1 campaign, the research protocol still needs a fixed sample-size and precision/power design for **paired group-level model improvement versus strong deterministic baselines**, including uncertainty-aware authority-outage outcomes, an explicit meaningful effect size, correction for planned contrasts, and any clustered dependence. None of those can be replaced by this binomial proportion diagnostic.
