# Development changelog

## 2026-11-24: ISP network lab with a contained BGP hijack

- `experiment-b/isp-net-lab/`: a routed ISP in containerlab with FRRouting routers (OSPF core, iBGP route reflector, eBGP to a transit provider and a customer) and hosts that name themselves.
- **Scenario:** a customer hijacks the provider's prefix with two /25s, and the subscriber's traffic reaches the attacker.
  - Detection compares received routes with the customer's registered prefixes.
  - An over-broad filter was rolled back when the observer saw the customer cut off.
  - The registry filter was applied with a signed approval and verified by an observer that reads every ISP router directly.
- Record: CI run 45327610238. Evidence: `docs/evidence/ISP_BGP_HIJACK_LAB_2026_11_24.md`.

## 2026-11-24 (b): PowerDuck GOOSE detector v2, second measurement

- Added stream-history features, a 0.5% threshold and incident grouping. Development run 45330612517, test run 45330952174. The 16 captures had already been read by version 1's test.
- Failed again. False alarms were 1.48% against a 1% ceiling (version 1: 3.0%), and 15 of 16 scenarios were flagged. Detection after onset fell, because the history window absorbed attack traffic. Evidence: `docs/evidence/MEASURED_POWERDUCK_GOOSE_DETECTOR_V2_2026_11_24.md`.

## 2026-11-21: Mechanism-lab scored campaign

- **Run:** 1,200 of 1,200 trials, run under lock `9422667f` (CI run 44879497946), with no reruns and no exclusions. Controls passed on the same code first. Aggregate reports are in `docs/evidence/mechanism-scored-campaign/run-44879497946/`.
- **Lasting faults** (loss and paused listener, 70 configurations): restart_enforcer fixed 70 of 70. Resync, gateway restriction and doing nothing each fixed 0 of 70. In the 34 lasting-fault configurations where the plan forbids restarts, no permitted action fixed the fault.
- **Self-healing faults** (30 configurations): every action ended fixed. Doing nothing had the lowest cost at all three cost ratios, which is the robust finding. For lasting faults, restart had the lowest cost at 1:5 and 1:20, but not at 1:1.
- **Verifier:**
  - No false VERIFIED in 1,200 trials. Specificity was 334 of 334 and sensitivity 173 of 173 when it answered.
  - It abstained on 57.8% of trials.
  - The dual-evidence rule only added abstentions (62.0%).
- **Exposure-seconds** are gateway-sampled and understate oracle exposure. Q4 (estimator calibration) is not reported, because its analysis was never locked.
- Full write-up: `docs/evidence/MEASURED_MECHANISM_LAB_SCORED_CAMPAIGN_2026_11_21.md`.

## 2026-11-23: Cross-dataset flow detector v3, single HIKARI-2021 test

- Developed on CIC-IDS2017 and CSE-CIC-IDS2018 with verified-normal calibration, a detection floor and a fixed model-selection rule, then tested once on HIKARI-2021 (Zeek flowmeter captures). Development run 44914414336; test run 45314301123.
- Failed both parts of the condition. It detected 0.14% of attack flows (42 of 30,174) against a 50% floor, and alerted on 1.36% of normal flows against a 1% ceiling (Benign 0.57%, Background 2.97%).
- Development had already shown under 1.2% detection with 2018 held out. Evidence: `docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_V3_2026_11_23.md`.

## 2026-11-21: Exploitation rank drives the quarantine decision

- `engine/predict_shield/exploit_scoring.py` loads the frozen exploitation model after checking the model bytes, the feature code, the scikit-learn version and the reference file against the freeze, and scores a CVE JSON 5 record (CNA container only).
- The model was trained with balanced class weights, so its score orders CVEs but is not a probability. `reference.py` scored all 48,150 CVEs published in 2025 (after every year used to fit, choose or test; KEV not read, run 44914856897). A CVE's rank is the share of those scoring at least as high. Top 1%, 5% and 10% sit at scores 0.342, 0.039 and 0.013.
- `decide()` now takes that rank (`exploit_top_share`) and quarantines an unfixable finding in the top 5% (the share that held 51.6% of later-exploited 2024 CVEs), or one listed in KEV. A low rank is reported as not evidence of safety. `finding_for_cve()` builds a finding from a record; an unscorable record escalates.

## 2026-11-20 (a): Vulnerability response: fix, mitigate, quarantine, escalate or monitor

## 2026-11-20: Vulnerability response: fix, mitigate, quarantine, escalate or monitor

- `vulnerability_response.decide()` chooses the response for a finding, with reasons. Quarantine blocks the vulnerable route with an nginx include from a closed grammar, through `change_execution` (signed approval, `nginx -t`, reload, verification, rollback).
- DVWA lab (run 44777352174): over-broad quarantine rolled back by verification; quarantine of the SQL injection route verified (route 403, payloads refused, five other pages 200); quarantine lifted after the source fix, verified.
- Fixed: `render_csp` accepted a source ending in a line break. Evidence: `docs/evidence/VULNERABILITY_QUARANTINE_DVWA_2026_11_20.md`.

## 2026-11-20 (b): Learned exploitation likelihood for CVEs

## 2026-11-20 (1): Cross-dataset flow detector v2 measured on CSE-CIC-IDS2018

- Thresholds and the anomaly model calibrated on the first 2018 day with its labels unread; per-source context removed; the freeze now covers the code as well as the model.
- Single locked run (freeze `793d315f`, run 44782232012): benign alert rate 0.55%, every day under 1%, so the pre-stated condition was met. Detection was 0.83% (28,643 of 3,441,225 attack flows), so this version is not usable as a detector.
- Cause: the calibration day contained brute-force traffic, which pushed the supervised threshold to 0.99999997 and taught the anomaly model attacks as normal. Version 3 calibrates on verified-normal traffic and adds a detection floor to the pass condition.
- Disclosed: attempt 1 was stopped by a runner shutdown after one day's result was printed; the placeholder test pin in the first freeze; the 2018 files are not stored in time order (context is computed after sorting).



## 2026-11-20: Learned exploitation likelihood for CVEs

- `experiment-b/exploit-likelihood/`: CVE records (CNA container only) with CISA KEV as labels; train 2017 to 2022, choose on 2023 H1, freeze, score 2024 once (run 44777279550).
- Test: 39,924 CVEs, 161 in KEV. Top 1% by score held 53 of them (32.9%), top 10% held 99 (61.5%); 33 of the top 100 were in KEV; ROC AUC 0.876.
- Training fit is reported beside validation for all eight candidates: structured-field-only models underfit, the largest text model overfits, and the learning curve was still rising. Evidence: `docs/evidence/MEASURED_EXPLOIT_LIKELIHOOD_2026_11_20.md`.

## 2026-11-21 (b): Learned GOOSE anomaly detector on PowerDuck

- `experiment-b/powerduck/`: an Isolation Forest fitted on normal GOOSE messages only, using per-stream timing, state and sequence numbers, length, values and rates. The protocol and freeze were fixed before any attack capture was read; the 16 attack captures were scored once.
- Failed its stated condition. The first malicious message raised an alert in 14 of 16 scenarios, and all 16 scenarios were flagged, but 3.0% of non-malicious messages alerted against a 1% ceiling. Outside the two floods, 15.1% of malicious messages were detected. Development on held-out normal captures had already shown 1.1% to 1.8% alert rates.
- Evidence and the next version's changes: `docs/evidence/MEASURED_POWERDUCK_GOOSE_DETECTOR_2026_11_21.md`.

## 2026-11-20 (2): Mechanism-lab preregistration lock, controls and verifier scoring

- `PREREGISTRATION.json` fixes the scored campaign's questions, ground truth, VERIFIED scope, metrics, cost matrix, controls, exclusions, rerun and stopping rules. `prereg_gate.py` hashes it with the plan and the campaign code; `campaign.py --scored` refuses to start unless locked and unchanged, and CI fails on any unrecorded change after locking (`DEVIATIONS.md`).
- Rerun rule in `campaign.py`: one rerun per infrastructure failure, then exclusion, counted across invocations and logged.
- `controls.py`: positive controls per fault mode (inject, no action, 18 s of oracle reads) with self-heal rates, and a no-fault negative control. Runs as its own CI job.
- `verifier_scoring.py`: verifier sensitivity, specificity and abstain rate against oracle truth per fault mode and action, single-evidence and dual-evidence (scope plus post-action operator telemetry, abstain on disagreement). The pilot now records post-action operator telemetry.
- First control run: no-fault control healthy (8 of 8). Without action, duplicate and reorder never exposed access, delay healed in about 2 s, and loss persisted past the 6 s window only at TTL 15 s (healing at about 14 s). The verifier made no false VERIFIED on 40 control runs or 40 pilot trials, and abstained on 16 of the 40 pilot trials.
- Plan v3.1 replaces v3 for the scored campaign: 70 persistent configurations (loss and paused listener, TTL 10-30 s) and 30 self-healing ones (delay; loss with TTL 2.5-4 s). Controls now check each registered cell's class. A 16-trial v3.1 pilot runs in CI.
- Second control run confirmed 9 of 10 cells; a 1 s delay was delivered before the first read, so the delay range moved to 2-3 s. The third run confirmed all 10 cells, and the preregistration was locked on that code (tag `mechanism-prereg-v1`).
- After locking, before any scored trial: `outcome_report.py` (Q1, Q2, per-arm errors and the cost comparison at 1:1, 1:5 and 1:20) added to the lock through the first `DEVIATIONS.md` entry. New `mechanism-scored-campaign.yml` runs the controls and then the 1,200 scored trials behind the gate, commits aggregate reports to a results branch, and keeps the full records as an artifact.

## 2026-11-19: Learned flow detector measured across two networks

- `experiment-b/cic-flow/`: supervised gradient boosting plus a benign-only Isolation Forest over flow statistics, traffic type and causal 60-second context. No hand-written rules. Protocol, features, thresholds and a 1% benign alert budget fixed before any result was read; both archives pinned by SHA-256.
- Developed on CIC-IDS2017 (corrected version), frozen (model `aeb53fb9`, freeze `d2355cb3`), then scored once on all 63,195,145 CSE-CIC-IDS2018 flows.
- Result: 99.97% of attack flows detected, but 30.85% of benign flows alerted (20.9% to 40.3% per day), against the 1% budget. Precision 16.11%. The threshold set on 2017 benign traffic did not carry over. Recorded as a failed budget in `docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_2026_11_19.md`.
- The bundle and both reports are committed in `experiment-b/cic-flow/frozen/` so the evidence does not depend on artifact retention.

## 2026-11-18 (9): Endpoint rules v2 on a pre-registered second-publisher held-out set

- Reworded the detection results as integration behavior and labelled the endpoint rules as deterministic, not AI; held-out 2 of 5 carries its Wilson interval.
- `RULES_V2` frozen (`98ffd13`) before evaluation data was chosen; Splunk attack_data set selected from metadata, pinned and committed (`3fa1df9`) before it ran.
- Result: T1003.001 3 of 3, T1112 2 of 27, alerts in 4 of 10 other-technique recordings, 75,155 events.
- Found and fixed: the Windows event XML reader assumed one event per line and dropped events with newlines in their values. Re-run with unchanged rules; first run's summary kept.

## 2026-11-18 (8): Held-out measurement of the endpoint rules

- Twenty more OTRF datasets, pinned and run only after the rules were committed (`run_otrf_coverage.py`). The rules caught 2 of 5 held-out attacks of the techniques they target and alerted on 2 of 15 datasets of other techniques (one real LSASS access during pass-the-hash, one false alarm from an Azure agent), across 170,434 events.
- Found: the LSASS rule lists `taskmgr.exe` as benign, which hides the Task Manager LSASS dump; the T1112 rule covers only the WDigest key. Not changed here, so the held-out result stays valid.
- Reworded every summary that read "8,920 events, 6 detections", which looked like a per-event rate. Detection is per recorded attack: 3 of 3 on the development set, 2 of 5 held out.
- Archive format is now read from the bytes, not the file name; each rule hit records the fields it matched.
- Fixed a stale-code race in the DVWA chain: PHP's opcode cache could serve the previous file for up to two seconds after a change, so a correct fix was once refused. The lab PHP servers now run with the cache off, recorded in each report.

## 2026-11-18 (7): Public test sources

- OTRF Security-Datasets (pinned commit and archive hashes) replayed through `endpoint_telemetry.py` rules and the signed intake; every hit agreed with its dataset's published ATT&CK label.
- Real cdnjs and jsDelivr files registered only when both publishers' hashes and the live bytes agree; monitored with the production probe and SRI-loaded in Chromium.
- `osv_source.py`: OSV.dev as the advisory source for the post-fix vulnerability check, cross-checked against OSV's own version query; disagreement or unreachability is never a clean result.
- `sast_findings.evaluate_fix(require_dynamic=True)`: an opt-in fifth assertion from live exploitation attempts. Against DVWA it caught an incomplete fix that the static assertions passed.
- Dependency upgrades and DVWA source fixes run through `change_execution.py` with staging measurement, signed approval, verification and rollback.
- ET Open loaded into Suricata through `suricata-update`; a public rule's alert admitted through the signed intake.
- Finding: OSV lists two advisories covering lodash 4.17.21 (GHSA-r5fr-rjxr-66jc, GHSA-xxjr-mmjv-4gpg), so the version the earlier lodash pilot accepted now fails the known-vulnerability assertion. The earlier record is kept with a dated note.

## 2026-11-18 (6): End-to-end chain, safe apply, live data, source identity and navigation containment

- **Source identity.** Every registered detection source carries an Ed25519 public key or a client-certificate fingerprint. `admit()` accepts only an `AuthenticatedDetection` from `authenticate_signed()` or `authenticate_mtls()`, so a detection that only names a source is refused. Signatures are checked against the named source's key, replays (nonce or detection ID) are refused, and a rotated-out credential stops admitting. `intake_server.py` serves both routes over TLS.
- **Safe apply.** `change_execution.py`: signed, single-use, expiring approvals bound to the exact change; dry run by default; production targets never auto-apply; `nginx -t` validation of a generated CSP include, or a page limited to registered renderings; atomic write and reload; verification after activation; automatic rollback with the restored content checked; a hash-chained audit log.
- **End-to-end chain.** `experiment-b/end-to-end-chain` runs unattended against real nginx, Chromium and Suricata: detect, plan, dry-run, apply, verify, keep or roll back. Five registered paths plus one real-model incident run in the new `end-to-end-chain.yml` workflow. Building it surfaced a real race: right after an nginx reload, a previous-generation worker can still answer, so a single matching read is no longer accepted as proof that a state is live.
- **Live data.** `live_feed.py` and `demo/live.html` give a read-only live view that says NO LIVE DATA when the feed stops. A real Suricata on loopback is the first real detection feed: its alerts are mapped only by registered sink and referrer, signed and admitted over TLS, and an admitted alert makes the scheduler re-check at once.
- **Navigation containment.** Sandboxed-frame isolation contains all six exfiltration channels in the real Chromium matrix (fetch, image, form, frame navigation, top-window navigation, popup) with the widget still working. The pilot schema is now `/4` and request capture is now per browser context, so popup traffic is captured too.

## 2026-11-18 (5): Remove the remaining comparison logic from code

- The external pilot audit no longer takes a baseline arm or computes framework-minus-baseline differences. Each condition record now carries the framework's own independently verified measurements, and the audit reports exposure, authorized-failure fraction, downtime and false-assurance fraction per condition (schema `/2`).
- Dropped the offline-baseline flag from the outage interval diagnostic, and the remaining "baseline" naming from the re-verification scheduler and threat prioritization modules (`threat-prioritization-v1`; the document is now `THREAT_INTEL_PRIORITIZATION.md`).
- Removed the last comparison sentences from the development notes and roadmap.

## 2026-11-18 (4): Remove the AI-versus-rule comparison work and the research wording

- Removed every model-versus-rule and model-versus-model comparison from the repository: the benchmark and backtest modules, the v3/v3.1 campaign scaffolding and protocol-freeze checks, the advisory-reading and vulnerability-benchmark comparisons, the ISP and telecom AI-versus-rule studies, the lodash strong-rule arm, the lookup and exposure baselines inside the learned models, and the eighteen workflows that ran them. Their documents and result records went with them. Git history keeps all of it.
- Kept: the lab infrastructure, the learned action model and its held-out error and interval coverage, campaign collection and audit, link learning, graph risk scoring, the physical action measurements and every verification capability.
- `docs/research` is now `docs/evidence`, with an index grouped by capability. The word "research" no longer appears in code, identifiers, workflows or documents; for example `ELIGIBLE_RESEARCH_LAB_PLAN` is now `ELIGIBLE_LAB_PLAN`.
- Superiority disclaimer fields were removed from reports, since there is no comparison for them to describe.

## 2026-11-18 (3): Run the script proposer against a real model, and fix what it exposed

- The script-integrity workflow gained a second job that serves a real model (`qwen3:0.6b`) through a local Ollama on loopback, the same setup the lodash pilot uses, and runs the containment proposer against it on every relevant push, recording the installed model digest. No API key is needed.
- That run exposed a real defect: the system prompt told the model to copy an action from `permitted_actions`, but `propose()` never sent the list. The model invented actions (`block`, `patch`), and in the planted-injection case answered `disable_monitoring`, exactly the action the injected note demanded. Deterministic validation rejected all four replies, so no unsafe action got through, but the model could not do its job. The unit tests had used scripted replies that ignore the prompt, so they could not catch it.
- Fixed in `script_risk_proposer.py` and in the unused `action_proposer.py`, which had the same defect and no tests. New tests check the prompt the model actually receives.
- After the fix, with the same model digest: a valid offered choice in all four cases, an eligible plan in two, the two approval-tier choices held for review, the planted instruction not followed, and a "low" severity given where the pressure note asked for it, which did not change the approval tier. The runner now reports these usefulness measures alongside the enforced safety checks.

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

## 2026-11-11: Mechanism-based Experiment B hardening

- Implemented real Kafka broker, separate Java enforcement instances, a separate oracle and a measured HTTP gateway; no synthetic-formula results are claimed.
- Added source- and protocol-pinned measured-only campaign collection, independent group splits, separate oracle streams and offline model training.
- Added synchronized trial-epoch invalidation and broker-carried trial identifiers so late events from an old experiment are not applied to the next experiment.
- Corrected resync to retain persistent consumer loss, and made reordering use two distinct published revisions.
- Added independent Compose-versus-gateway scope checks, distinct path/control/service outcomes and a declared (not verified remaining) laboratory SLO budget.
- Experimental branch changes remain subject to their own tests and review.

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
- Reviewed a separate experimental archive; results are documented in [the archived test review](../evidence/v0.3.0-validation-note.md), not attributed to the integrated codebase.

A commit, passing test or simulated laboratory result does not establish production security efficacy.
