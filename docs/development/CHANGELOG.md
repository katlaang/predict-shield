# Development changelog

## 2026-11-18 (2): Close the remaining script-integrity limitations

- The fetch probe now resolves a registered hostname once, checks every address in the answer, refuses private, loopback, link-local and other non-public addresses unless the registration explicitly opts in, and connects only to that pinned address, verifying TLS against the registered hostname. A DNS answer that changes between the check and the fetch can no longer move a probe to an internal address. Tested against a rebinding resolver, a mixed public/private answer, and a real TLS server with a matching and a mismatching certificate.
- Subresource Integrity support: `sri_value` computes the browser-format pin for a trusted hash and `confirm_sri_pinned` checks that the operator's page actually carries a trusted pin with `crossorigin` set.
- The pilot's containment verification now covers four exfiltration channels (a `fetch` request, an image beacon, a form submission, a top-level navigation) against five containments, every trial with the compromise live and both independent sources required. Measured: `connect-src` contains `fetch` only; restricting every fetch directive (`default-src` plus `form-action`) contains `fetch`, image and form but not navigation, which no CSP directive in current browsers restricts; blocking the vendor script or pinning it with SRI contains all four but disables the checkout; the no-containment control is NOT VERIFIED on every channel. Browser capture and sink log agreed on all 20 trials.
- SRI's operating costs are measured rather than assumed: the pinned clean script runs only when the vendor sends CORS headers, and a benign vendor update is refused until the pin is changed.
- Detection time is now measured end to end under the existing fixed-interval re-verification scheduler on a real clock, every selected probe a real fetch: at a 2-second interval all five randomly timed tampers were detected within the interval-plus-one-second bound.
- Added `run_live_model_proposer.py` and a manually dispatched workflow (`live-model-script-proposer.yml`) that run the containment proposer against a real hosted model using a repository secret and fail on any structural safety violation. No model provider is reachable from the development sandbox, so it has not been run yet; its checks are exercised in CI with adversarial and cooperative stand-in models.
- The real-pilot workflows (lodash, minimist, SAST, script integrity) previously ran only on pull requests or manual dispatch, and changes have been pushed directly to `master`, so the GitHub Actions history held runs for the lodash pilot only. They now also run on a path-filtered push to `master`.
- CI now asserts the full 4x5 containment matrix, the verifier controls, the SRI costs and the detection bound. The pilot produced identical outcomes across three consecutive full runs.
- 12 new engine tests and 4 new pilot-contract tests; full engine suite (353 tests) passes.

## 2026-11-18: Close gaps in script-integrity containment verification

- The behavioral assertion (`confirm_no_prohibited_network_behavior`) no longer passes on an empty capture. It now takes a `BrowserBehaviorCapture` and reports no pass/fail at all, which can only assess as INDETERMINATE, unless a page-owned canary request was recorded during the same trial (the instrumentation was live) and the script under test was independently confirmed live at the vendor and attempted by the browser (the exposure was exercised). The previous version would have reported VERIFIED for instrumentation that recorded nothing.
- Added `confirm_controlled_sink_log`, a second independent source for the same assertion in a controlled simulation: the prohibited destination's own server log, independent of the browser's instrumentation.
- The pilot's containment scenario previously tightened CSP while serving the clean script, so it measured disruption but never proved containment of a compromise. Containment is now verified with the compromised script live, both sources required: blocking the vendor script (VERIFIED, checkout button disabled), restricting `connect-src` (VERIFIED, no measured disruption), and an ineffective containment (NOT VERIFIED). Two controls on the verifier itself, instrumentation not live and exposure not exercised, both report INDETERMINATE.
- The two-source rule caught a real flaw while the pilot was being built: Chromium reported the exfiltration request as failed (`net::ERR_ABORTED`) while the sink server logged it as received, so the browser capture alone scored a successful exfiltration as contained. A request now counts as blocked only when the browser refused to send it (a CSP block); any request that left the browser counts as having reached its destination.
- The script-risk proposer now returns a severity assessment from a fixed scale, correlated against the asset's registered criticality and any registered detection notes; a missing or invented severity rejects the reply. Severity is recorded as advisory only: a new acceptance test shows a model rating a finding "low" cannot move an approval-tier action into automatic eligibility. The pre-model injection screen now reaches strings nested anywhere in the context, and a test shows an instruction hidden in a detection note is flagged.
- "Detection time" is renamed probe detection latency and documented as excluding the re-verification scheduling interval.
- 11 new tests; full engine suite (341 tests) passes; the real pilot produced identical outcomes across four consecutive runs.

## 2026-11-17: Third-party script integrity as a fourth evidence domain

- `script_integrity.py` extends the four-assertion, all-or-nothing composite pattern to a third-party script an operator's own page embeds, with no access to the vendor's source: a live, independently fetched hash against a registered trusted value; a real browser's own network destinations against a registered allowlist (not only a static `<script src>` scan, so a script that loads further script or exfiltrates through a `fetch`/XHR/`sendBeacon` call is caught); whether the site's CSP header actually restricts `script-src`; and a real, post-action behavioral check -- whether a real browser load can still reach a registered-prohibited destination -- that a hash comparison cannot stand in for, since an allowlisted vendor domain can itself serve malicious code.
- A constrained AI proposer (`script_risk_proposer.py`, mirroring `action_proposer.py`) chooses a containment action only from a pre-permitted, registered set; its reply is re-validated against that exact set regardless of its content. `plan_script_integrity_case()` (`pipeline.py`) wires a confirmed finding into the propose-then-gate stage alongside `plan_sast_case`'s source-code-finding path.
- Added a required AI-security acceptance-test suite (`test_script_integrity_ai_security.py`), not only functional tests: malicious content placed in attacker-influenced evidence (a script's hash, observed domains, free-text detection notes) is proven unable to override the deterministic policy gate, introduce a containment action outside the registered set, manipulate the outcome through rationale text, trigger any execution (no capability here executes anything), or substitute a self-report for independent verification.
- Piloted in `experiment-b/real-script-integrity-pilot/` (CI workflow `real-script-integrity-lab.yml`) against two real local HTTP servers -- an operator "site" origin and a separate third-party "vendor" origin, modeling two genuinely different origins rather than one -- and a real headless-Chromium load via Playwright, through six scenarios: a clean negative control; a real malicious tamper where the browser is observed actually reaching a third, attacker-controlled origin over the network, not merely a changed hash; a benign, pre-registered vendor update that does not false-positive; an unregistered-domain injection the hash check alone would miss but the real network capture catches; a CSP enforcement toggle (missing / wildcard / correctly scoped); and a real containment action (CSP tightened to block the vendor origin) whose functional side effect -- the page's own button no longer being enabled -- is measured and reported honestly rather than assumed away.
- Scoped out of this pass, explicitly: this is a controlled adversary simulation against infrastructure the pilot itself controls, not a scan of a real vendor's production site, and not general-purpose AI-assisted red-teaming (autonomous attack-path generation across arbitrary infrastructure), which would be a materially larger, separate capability if ever pursued. SRI pinning and CSP rollout for a real site are not implemented, only checking a CSP already in place; DNS-rebinding protection beyond host-allowlisting and redirect-blocking is not implemented in the fetch probe; the AI proposer has not been exercised against a real hosted language model.
- 47 new unit and pilot-contract tests pass; full engine suite (330 tests) still passes.

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
