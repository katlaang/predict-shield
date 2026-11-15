# Real persistent-fault decision diversity experiment

**Purpose:** Determine whether the physical lab has enough genuinely different useful defensive actions to make an AI selector worth evaluating. The first real learned AI test in [PR #56](https://github.com/katlaang/predict-shield/pull/56) found no statistically supported AI advantage; the learned model chose resynchronization in all six held-out cases and tied fixed resync. That is an honest result, not a reason to manufacture a friendlier scoring method.

This new study was designed **before collecting its new physical outcomes**. It adds genuine `consumer_paused` faults where Kafka event processing remains paused while the enforcement JVM's HTTP service stays reachable, which can create persistent authorization drift requiring a different approved response. It also includes real loss, delay, duplicate and reorder faults and varying routing, cache TTL, load, topology and restart-permission constraints. These conditions are physically injected and independently measured, not assigned recovery labels by the planner.

## Frozen exploratory design

- **5 fault families × 3 complexity strata × 2 independently configured scenarios = 30 configuration groups.**
- **30 groups × 2 repeats × 4 actual actions = 240 physical Java/Kafka replay observations.**
- Prespecified 18 train / 6 calibration / 6 held-out configuration partitions, reserved for a **future** learned-selector study. This first feasibility collector neither trains a model nor inspects held-out AI performance.
- Measured scalar laboratory cost is the preexisting 0.50 upper-bound gateway exposure + 0.25 independently observed persistent authorization exposure + 0.25 actual failed legitimate requests / registered allowance. An action's success acknowledgment is never sufficient.
- `consumer_paused` trials must have a positive privileged independent witness of listener pause **with HTTP health 200**, and actual stale revoked access. The runner physically resumes every consumer before and after every action, preventing paused-listener carryover from artificially favoring restart.
- The independent unit for action-headroom analysis is one configuration group, averaging two measured repetitions. Distinct near-optimal actions use an existing 0.001 cost tolerance. The report includes all configurations and any negative results; no outcome-based exclusion or sampling changes are allowed.

This experiment **excludes authority_outage** because the external authority's live desired policy is UNKNOWN while unavailable, and existing four-stream v3 scoring cannot honestly give it a comparable VERIFIED or NOT VERIFIED scalar target. That sixth physical family requires a separate prospectively defined uncertainty-aware objective.

## Evidence and decisions

The physical GitHub Actions workflow `.github/workflows/persistent-five-fault-headroom.yml` performs all 240 action replays in disposable Docker, audits all four original streams, checks real pause witnesses, and publishes only hashed group-level sanitized costs. Results cannot be labeled `AI superiority` because no model is trained or evaluated in this particular study.

A prospective learned-model follow-up may be justified if the independent group results show **multiple distinct optimal actions** and sufficient measurable headroom against strong fixed and telemetry-based rules. We will not rerun only favorable groups or alter the utility weights after seeing the results.

Passing lab tests, genuine fault diversity and even a positive later held-out model result do not establish real U.S. critical-infrastructure field outcomes or commercial adoption.
