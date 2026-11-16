# Development changelog

## 2026-11-15: Real SAST fix-verification pilot; commit-signing switch

- Piloted `sast_findings.py`'s four-assertion composite against a real `semgrep` scan (pinned to a repo-local rule file, not the live registry), a real SQL-injection fixture and fix, and a real sqlite3 regression check; all four assertions reached VERIFIED. See `experiment-b/real-sast-pilot/` and its CI workflow.
- The pilot's own build surfaced and fixed two real bugs: a severity-vocabulary mismatch that made the no-new-high-severity check silently vacuous against Semgrep's real `ERROR`/`WARNING`/`INFO` scale, and a finding-fingerprint flaw caused by scanning the before/after fixture states as two separately named files rather than one shared path.
- Commits made from an ephemeral development sandbox are now created through GitHub's Git Data API rather than a local signed `git commit`, so GitHub signs them server-side and they show Verified under the `katlaang` account, without any private signing key ever being placed on that sandbox's disk.

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
