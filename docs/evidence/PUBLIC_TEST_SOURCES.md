# Public test sources

PREDICT-SHIELD's lab results so far came from servers, packages and fixtures the labs themselves set up. These sources add data the project does not control. Every one is published for testing or released by its owner, and none involves scanning a third-party site. Workflow: `.github/workflows/public-sources.yml`, also run weekly because OSV and the Emerging Threats ruleset change on their own.

| Source | What it is | How it enters the pipeline | Pinned by |
| --- | --- | --- | --- |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Recorded Sysmon and Windows Security events from real attack tools run in a lab, each dataset labelled with its ATT&CK technique | `endpoint_telemetry.py` rules, then signed detections through the TLS intake, then the re-verification scheduler | Repository commit and archive SHA-256 (`experiment-b/public-sources/sources.json`) |
| cdnjs and jsDelivr | Real library files with each CDN's published hash | Registered only when the live bytes match both publishers; then the production hash probe and a real-browser SRI load | Publisher hashes, fetched and compared at run time |
| [OSV.dev](https://osv.dev) | Open aggregated vulnerability database | `osv_source.py`, the post-fix "no known vulnerability" check; range evaluation must agree with OSV's own version query | Response SHA-256 recorded per run |
| [Emerging Threats Open](https://rules.emergingthreats.net/) | Public Suricata ruleset | `suricata-update` into the lab's Suricata; a public rule fires on reproducible traffic and its alert is admitted through the signed intake | Merged ruleset SHA-256 recorded per run |
| [DVWA](https://github.com/digininja/DVWA) | A deliberately vulnerable PHP application | Real target for a source-code fix through the change executor | Commit `502ac150ce37` |
| npm (lodash) | Real releases of a real package | Real target for dependency upgrades through the change executor, with OSV as the advisory source | Exact versions |

## What each run checks

**Attack telemetry.** Three OTRF datasets: an Empire WDigest downgrade (T1112), Empire Mimikatz LogonPasswords (T1003.001), and an LSASS dump via comsvcs.dll (T1003.001). Archives are refused unless their hash matches the pin, and are parsed in memory only. Every rule hit must agree with its dataset's published technique, every dataset's technique must be detected, every detection must be admitted, and every admission must make the scheduler mark that host due at once. A detection re-sent after admission must be refused. The recordings are years old, so a replayed detection carries the replay time as its observation time and keeps the original record's digest in its ID.

**CDN files.** jQuery 3.7.1, jQuery 3.7.0 and lodash 4.17.21 are each registered only after both CDNs' bytes match both publishers' hashes and each other. The production probe, with every default intact, must report VERIFIED for each and NOT VERIFIED when the 3.7.0 hash is registered for the 3.7.1 URL. In Chromium, a page loading the real cdnjs file with its published SRI value must run the library, and the same file with the other version's SRI value must not.

**OSV and dependency upgrades.** Starting from lodash 4.17.11, upgrades to 4.17.15, 4.17.21 and 4.18.1 each go through staging measurement, the policy gate, a refused unsigned attempt, a signed dry run, the applied change and the four-assertion verdict, with OSV deciding the "no known vulnerability" assertion. 4.17.15 must be rolled back. For the other two, OSV's current data decides; the run records which advisories, if any, cover each version. The run also checks that OSV places 4.17.11 inside GHSA-p6mc-m468-83gw (CVE-2020-8203).

**ET Open.** The full ruleset is downloaded for the installed Suricata, loaded alongside the lab rule, and the public rule "GPL ATTACK_RESPONSE id check returned root" (sid 2100498) must fire on lab traffic and its alert must be admitted through the signed intake.

**DVWA.** Semgrep with a pinned repo-local rule finds request data reaching the query in DVWA's SQL-injection page. Two registered fixes are measured on a staging copy, approved with a signature and applied. The first is DVWA's own "medium" pattern, escaping the input while dropping the quotes. It clears all four static assertions, including a re-scan that no longer flags the MySQL path, but live payloads still return other users' rows, so the opt-in fifth assertion fails and the change is rolled back. The second, a prepared statement, passes all five assertions and is kept.

## GitHub Actions run, 2026-11-18

Run [44451381802](https://github.com/katlaang/predict-shield/actions/runs/44451381802), commit `6bf4b5f`. All three jobs passed.

- **OTRF:** the same result as locally. Three selected OTRF attack recordings containing 8,920 telemetry events generated six matching rule alerts. Each recording produced at least one alert consistent with its published ATT&CK label. Event-level detection recall, precision and false-positive rate could not be determined from the available labels. These results demonstrate integration behavior, not generalized detection accuracy. All six alerts were signed and admitted, each host was marked due by `change_event`, and the re-sent envelope was refused.
- **CDN files:** jQuery 3.7.1, jQuery 3.7.0 and lodash 4.17.21 each matched both cdnjs's and jsDelivr's published hashes, and the two CDNs served identical bytes. The production probe reported VERIFIED for all three over the public internet, and NOT VERIFIED with the 3.7.0 hash registered for the 3.7.1 URL. Chromium ran both libraries with their published SRI values and refused jQuery 3.7.1 with 3.7.0's.
- **OSV and dependency upgrades:** 4.17.15 rolled back; OSV listed five advisories covering it, among them GHSA-p6mc-m468-83gw, and the live probe still saw prototype pollution. **4.17.21 rolled back as well:** the live probe passed, but OSV listed two advisories covering 4.17.21, GHSA-r5fr-rjxr-66jc and GHSA-xxjr-mmjv-4gpg, and its version query agreed. 4.18.1 was kept with all four assertions VERIFIED and no covering advisory. The existing lodash CVE pilot accepted 4.17.21 against the two advisories registered at the time; OSV shows that is no longer a clean version.
- **ET Open:** 53,559 enabled rules downloaded for the runner's Suricata (merged ruleset SHA-256 `1ca3bd88...0f648a`); Suricata loaded 53,560 rules including the lab rule. The public rule sid 2100498 fired on lab traffic and its alert was admitted through the signed intake in 0.51 seconds, as T1059.
- **DVWA:** the same as locally. The incomplete fix cleared all four static assertions, with Semgrep reporting the finding resolved, failed the live check (half of the payloads still returned other users' rows on staging and on the target), and was rolled back to the original file. The prepared statement passed all five and was kept.

## Endpoint rules v2 on a second publisher's recordings, 2026-11-18

**Deterministic rules, not AI.** Version 2 (`RULES_V2`) changes only what the OTRF held-out run exposed: Task Manager is no longer treated as benign, the Azure guest agent's path is excluded, LSASS dump files and dump command lines are new signals, and the registry rule watches a registered list of about ten security-relevant values instead of one. Version 1 stays the default and its results above are unchanged.

**Protocol.** Version 2 was committed (`98ffd13`) before any evaluation data was chosen. The set was then selected from Splunk `attack_data` metadata alone (a different publisher, recorded in a different lab), pinned by repository commit and file SHA-256, and committed (`3fa1df9`) before it was run: every Sysmon recording labelled T1003.001 or T1112 except two files whose first lines had been opened, plus the first Sysmon recording of ten other techniques. One file returned 404 and is recorded as skipped.

**Two runs, same rules.** The first run used a parser that assumed one event per line and dropped about ten events whose values contain newlines (477 fragment lines; summary kept in `data/splunk_heldout_run1_summary.json`). The parser was fixed to split on event boundaries (`efff42e`) and the set run again with the rules unchanged; the headline numbers did not change. The second run is the result:

| Recordings | Count | Alert agreeing with the label | 95% Wilson interval |
| --- | --- | --- | --- |
| T1003.001, LSASS credential dumping | 3 | 3 | 44% to 100% |
| T1112, registry modification | 27 | 2 | 2% to 23% |
| Covered techniques together | 30 | 5 | 7% to 34% |
| Ten other techniques | 10 | alerts in 4 | |

75,155 events, all parsed.

**What the numbers say.**
- *LSASS dumping:* all three caught, each by a different signal (a memory read, a dump command line, a dump file written by WerFault). Three recordings is a small denominator; the interval says so.
- *Registry modification:* T1112 covers any registry change used by an attacker (wallpaper policy, proxy settings, firewall rules, Safe Mode, notification centre and so on). Version 2 watches about ten values. It caught WDigest and a ransomware sample disabling UAC, and missed the other 25. The rule's T1112 label claims far more coverage than it has.
- *Other techniques:* one alert is AsyncRAT reading LSASS, real credential-access behavior under a scheduled-task label. The other three recordings, all Atomic Red Team, each contain PowerShell opening LSASS with `0x1410`. The labels cannot say whether that is the test harness or another test run on the same host; they are reported, not classified.

These measure two small rule sets. They do not test the AI: the next experiment for that is the AI correlating several telemetry sources, assessing risk, choosing a registered response and stating its uncertainty, with the policy gate unchanged.

## A stale-code race in the DVWA chain

The next CI run after the one above rolled back the prepared-statement fix: staging had measured it clean, but the live check on the target still saw injection. PHP's opcode cache was on for the built-in web server and rechecks a changed file only every `opcache.revalidate_freq` seconds (2 by default), so verification run immediately after the change exercised the previous code. The first run had passed by timing alone. The lab servers now run with the opcode cache off, and each report records the PHP flags. A production PHP adapter would make cache invalidation part of activation (an opcache reset or a PHP-FPM reload). The failure was in the safe direction: a correct fix was refused because it could not be confirmed live; an unverified fix was never kept. This is the same kind of race as the nginx reload in the end-to-end chain.

## How good are the endpoint rules? Held-out results, 2026-11-18

**These are deterministic rules, not AI.** Each is a fixed match on named event fields. Nothing here tests whether PREDICT-SHIELD's AI can recognize unfamiliar attack behavior; the replay is an end-to-end detection-integration test (telemetry, rule match, signed admission, replay refusal, scheduled re-check).

The three OTRF datasets above are the ones the rules were written from, so detecting all three says the pipeline works, not that the rules detect well. A dataset is one attack recorded with all the host's normal background activity around it; OTRF labels datasets, not individual events, so a per-event detection rate cannot be computed. Detection is therefore measured per recorded attack.

Twenty more OTRF datasets were pinned and run only after the rules were committed (`6bf4b5f`), and the rules were not changed in response (`run_otrf_coverage.py`, `coverage_datasets` in sources.json). 170,434 events in all.

| Set | Recorded attacks | Detected | Alerts elsewhere |
| --- | --- | --- | --- |
| Development (rules written from these) | 3, covering 2 techniques | 3 of 3 recordings with an alert consistent with the label | not determinable: no event-level labels |
| Held out, technique covered by a rule | 5 | **2 of 5** | n/a |
| Held out, other techniques | 15 | n/a | alerts in 2 of 15 datasets |

**Detected:** Mimikatz LSA patch (PowerShell opening LSASS with `0x1438`) and the Outflank Dumpert syscall dump (`0x1fffff`).

**Missed, and why:**
- *RDP Task Manager LSASS dump.* Task Manager opened LSASS with full access (`0x1fffff`) and wrote `lsass.DMP`. The rule lists `taskmgr.exe` as a benign source process, so it skipped exactly the process the attack used. This is a defect in the rule.
- *Empire Enable RDP* and *Empire Invoke InternalMonologue* (both T1112, registry modification). The T1112 rule only checks the WDigest key, so it does not cover registry modification in general.

**Alerts on datasets labelled with other techniques:**
- *Empire Over-Pass-The-Hash* (T1550.002): PowerShell opened LSASS with `0x1010`. Mimikatz patches LSASS for this attack, so the alert reflects real malicious activity; only the label differs.
- *Empire Invoke SMBExec* (T1021.002): the Azure guest agent's log collector (`CollectGuestLogs.exe`) opened LSASS with `0x1410`. Judged by reading the matched fields, this is an alert on benign software. The dataset has no event-level label to confirm it.

**Reading these numbers.** Three hand-written rules raised an alert consistent with the label on 2 of the 5 held-out recordings of the techniques they target (95% Wilson interval 12% to 77%), and alerted on 2 of 15 recordings of other techniques, one of them judged benign, across 170,434 events. Event-level recall, precision and false-positive rate cannot be determined from these labels. That is a measurement of these three rules, not of the pipeline's intake, scheduler or verification, which behaved as designed throughout. Improving the rules (for example, keying on LSASS access with dump-file creation rather than trusting process names, and covering more registry paths) would need a fresh held-out set to measure, since these twenty have now been seen.

## Local run, 2026-11-18

This machine can reach GitHub and npm but not the CDNs, OSV, the ET download or Docker Hub, so those parts ran only in CI.

- OTRF: Three selected OTRF attack recordings containing 8,920 telemetry events generated six matching rule alerts. Each recording produced at least one alert consistent with its published ATT&CK label. Event-level detection recall, precision and false-positive rate could not be determined from the available labels. These results demonstrate integration behavior, not generalized detection accuracy. All six alerts were admitted, each host was marked due by `change_event`, and the re-sent envelope was refused with HTTP 401.
- DVWA: the incomplete fix rolled back with static analysis reporting it resolved and the live check failing; the prepared statement kept with all five assertions VERIFIED.
- Dependency chain with the two hand-registered advisories in place of OSV: 4.17.15 rolled back; 4.17.21 and 4.18.1 kept.
- Suricata with only the public sid 2100498 rule (not the full ET download): the rule fired and the alert was admitted in about half a second.

## Limits

- Replayed telemetry is a recording, not a live endpoint. It exercises the same rules, intake and scheduler a live feed would use.
- The CDN checks fetch published library files the way any browser does; they do not monitor any site that embeds them.
- DVWA and the lodash lab are disposable local targets. Their results show the chain's behavior on real code and real releases, not on an operator's production system.
- The detection rules are three registered rules for the techniques in these datasets, not a detection library.
