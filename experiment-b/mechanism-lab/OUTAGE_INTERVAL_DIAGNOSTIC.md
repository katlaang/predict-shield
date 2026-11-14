# Authority-outage interval cost diagnostic (exploratory)

This implementation operates on **actual four-arm timed physical observations**, independently observed direct target counts, authorized-user HTTP failures, and pre-outage policy witness commitments. It is not a new primary v3.1 utility, not learned action selection and **not** a justification for launching the 1,200-trial campaign.

## Why intervals instead of a single cost?

Once the policy authority is physically unavailable, no contemporaneous authoritative confirmation is possible. The separately witnessed historical policy revision remains useful but is not necessarily current. The existing action experiment produces lower/upper **sampled** revoked-access exposure, and actual denominators for protected authorized-user and legitimate-endpoint HTTP requests. A nonexistent probe or stale-trial observation is unknown, never evidence of safety.

The diagnostic deliberately reuses the existing v3 weighting **only as a sensitivity exercise**: 0.50 gateway path exposure, 0.25 residual policy-risk indicator, and 0.25 absolute legitimate/authorized HTTP failures divided by a declared per-window request allowance. For a stopped authority, the residual-policy indicator is 1 at its lower bound when any independently observed direct target explicitly allowed a revoked request; otherwise the lower bound is zero. The upper bound **always remains 1**, even when all observed targets deny access. The user-disruption term is computed from real HTTP failure totals and is not capped at 1.

Thus:

`cost_lower = 0.50 * gateway_exposure_lower + 0.25 * residual_indicator_lower + 0.25 * observed_user_failures / allowance`

`cost_upper = 0.50 * gateway_exposure_upper + 0.25 * 1 + 0.25 * observed_user_failures / allowance`

These ranges are **deterministic observational bounds**, not statistical confidence intervals or a guarantee of a stable or unmodified desired policy.

## Decision safeguard

All four actions must have been physically replayed, with four distinct valid pre-outage witness commitments. The offline comparison respects a separately declared `restart_permitted` change-policy flag. A candidate can strictly dominate another only when its worst-case bound is lower than the competitor's best-case bound. The program reports a unique definite best action **only if** that strict comparison holds against every eligible alternative; otherwise it returns `null`. A unique definite best action is an *experimental partial-order conclusion*, not evidence a model knows how to choose it.

It rejects missing actions, unverified/VERIFIED authority statuses, invalid observation denominators, missing HTTP status counts, nonfinite values, cross-arm witness reuse, and impossible intervals. It never reads raw oracle policy data into model features, fits an AI, or mutates services.

Execute from the isolated lab directory after running the *real* physical authority-outage action experiment:

```bash
python outage_interval_diagnostic.py \
  --physical-report reports/ci-outage-actions.json \
  --restart-permitted --error-budget-requests 25 \
  --output reports/ci-outage-interval-diagnostic.json
```

The GitHub Actions workflow generates the diagnostic report directly from physical observations and uploads only the derived non-sensitive summary. The request allowance is an explicit offline assumption here, **not** proof of the live remaining operational error budget.

## Next research requirements

The full v3.1 methodology still needs a locked contemporaneous-authority uncertainty policy, action-specific operational authority requirements, an independently registered six-family sample, multiple repeated configurations, sufficient partial-visibility decision diversity, and group-level power/precision justification. Neither this diagnostic nor the earlier five-group pilot satisfies those gates. Any future primary utility must be frozen prospectively and evaluated on new independent experiments, not retrofitted to observed action rankings.
