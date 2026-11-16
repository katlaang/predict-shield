# Development changelog

## 2026-11-15 (4): Wire a SAST finding into the propose-then-gate pipeline

- `plan_sast_case()` (`engine/predict_shield/pipeline.py`) is the SAST-finding counterpart to `plan_case`'s CVE/advisory flow: it independently re-confirms a finding via `sast_findings.confirm_before_fix`, maps the finding's `rule_id` to an operator-registered remediation action (deterministic registration, never a model's guess), and runs the existing `select_action` policy gate.
- Deliberately scoped to stop at the same boundary `plan_case` already stops at: it returns an eligible plan and never calls `sast_findings.evaluate_fix` itself. Post-action verification stays a separate step -- true for the CVE path as well, which this work surfaced: no capability in this repository is actually chained end to end from proposal through an applied, verified fix yet.
- 7 new unit tests pass; full engine suite (288 tests) still passes.

## 2026-11-15 (3): Second independent target through the registration mechanism

- Registered and piloted a genuinely different real CVE fix (minimist, CVE-2021-44906 / GHSA-xvch-5gv4-984h) through `remediation_target.py`, with its own `independent_probe.js` written from scratch, not reused from the lodash pilot.
- The probe uses the exact proof-of-concept Snyk's advisory (SNYK-JS-MINIMIST-2429795) publishes (`--_.constructor.constructor.prototype.foo bar`, reaching `Function.prototype`), confirmed by hand against both the vulnerable (1.2.5) and fixed (1.2.6) installed versions before writing the pilot. An initial guess at the payload (`--__proto__.y`) was tried first, found to not actually pollute on 1.2.5, and replaced once the real PoC was confirmed via search -- a negative control catching exactly the mistake it exists to catch.
- All four assertions reach VERIFIED for real: a real negative-control install (1.2.5, probed and confirmed vulnerable before any fix is credited), a real fixed install (1.2.6), a real `npm install --dry-run`, and a scan against two real OSV-confirmed advisories.
- 2 new unit tests pass; added to its own CI workflow (`real-minimist-remediation-lab.yml`).

## 2026-11-15 (2): Generalize dependency-upgrade verification registration

- `remediation_target.py` reads a declarative JSON schema (resolver command, test command, package/new-version/advisories) instead of requiring a new hand-written Python script per project, following up on `remediation_verification.py`'s two single-case pilots.
- `experiment-b/real-cve-remediation/verify_remediation_via_registration.py` re-runs the real lodash/CVE-2020-8203 case through the generic path (same real `npm install`, same real independent probe, same real advisory rescan) and reaches the identical accepted/all-four-VERIFIED result as the original hand-written `verify_remediation.py`, confirming the generalization actually holds rather than only looking reusable on paper.
- Deliberately not generalized: the `vulnerability_resolved` assertion still requires a human-supplied, separately reviewed, CVE-specific probe; this module does not invent or automate that probe for an arbitrary target.
- 10 new unit tests pass; full engine suite (281 tests) still passes.

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
