# Development changelog

## 2026-11-11: Mechanism-based Experiment B research hardening

- Implemented real Kafka broker, separate Java enforcement instances, a separate oracle and a measured HTTP gateway; no synthetic-formula results are claimed.
- Added source- and protocol-pinned measured-only campaign collection, independent group splits, separate oracle streams and offline model training.
- Added synchronized trial-epoch invalidation and broker-carried trial identifiers so late events from an old experiment are not applied to the next experiment.
- Corrected resync to retain persistent consumer loss, and made reordering use two distinct published revisions.
- Added independent Compose-versus-gateway scope checks, distinct path/control/service outcomes, a declared (not verified remaining) laboratory SLO budget and offline decision-regret comparisons.
- Experimental branch changes remain subject to their own tests and review; full 1,200-trial collection and scientific model superiority are not established.
## 2026-11-10: AI-centered implementation foundation and laboratory extensions

- Added typed pre-action prediction and measured-outcome contracts, with independent safety screening.
- Fixed evidence-refutation precedence so an authoritative failed probe is not obscured by a supporting self-report.
- Added controlled Experiment B scenario configuration and four candidate action handlers to the Java 25 laboratory, with extensive Javadoc.
- Added a seeded 100-configuration, four-action, three-repeat experiment manifest and separate laboratory record collectors.
- Added supervised-learning and calibration/evaluation scripts with data-leakage checks and unit tests.
- Python and Java/Docker integration CI checks passed on the corresponding development branches before merge.

## 2026-11-03 to 2026-11-05: Initial experimental fixtures

- Added localhost-only Java/Spring Boot authorization-drift fixtures, Python deny probes, and opt-in lab-only correction.
- Added independent post-action HTTP checking, mock-transport unit tests, and automated integration smoke tests.
- Reviewed a separate experimental archive; results are documented in [the archived test review](../research/v0.3.0-validation-note.md), not attributed to the integrated codebase.

A commit, passing test or simulated laboratory result does not establish production security efficacy.
