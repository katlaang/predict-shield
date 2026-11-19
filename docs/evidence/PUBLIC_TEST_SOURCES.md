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

**OSV and dependency upgrades.** Starting from lodash 4.17.11, upgrades to 4.17.15, 4.17.21 and 4.18.1 each go through staging measurement, the policy gate, a refused unsigned attempt, a signed dry run, the applied change and the four-assertion verdict, with OSV deciding the "no known vulnerability" assertion. 4.17.15 must be rolled back. For the other two, OSV's current data decides; the run records which advisories, if any, cover each version.

**ET Open.** The full ruleset is downloaded for the installed Suricata, loaded alongside the lab rule, and the public rule "GPL ATTACK_RESPONSE id check returned root" (sid 2100498) must fire on lab traffic and its alert must be admitted through the signed intake.

**DVWA.** Semgrep with a pinned repo-local rule finds request data reaching the query in DVWA's SQL-injection page. Two registered fixes are measured on a staging copy, approved with a signature and applied. The first is DVWA's own "medium" pattern, escaping the input while dropping the quotes. It clears all four static assertions, including a re-scan that no longer flags the MySQL path, but live payloads still return other users' rows, so the opt-in fifth assertion fails and the change is rolled back. The second, a prepared statement, passes all five assertions and is kept.

## Local run, 2026-11-18

This machine can reach GitHub and npm but not the CDNs, OSV, the ET download or Docker Hub, so those parts ran only in CI.

- OTRF: 8,920 events across three datasets; 6 rule hits, all agreeing with their published labels; all three techniques detected; 6 detections admitted; each host marked due by `change_event`; the re-sent envelope refused with HTTP 401.
- DVWA: the incomplete fix rolled back with static analysis reporting it resolved and the live check failing; the prepared statement kept with all five assertions VERIFIED.
- Dependency chain with the two hand-registered advisories in place of OSV: 4.17.15 rolled back; 4.17.21 and 4.18.1 kept.
- Suricata with only the public sid 2100498 rule (not the full ET download): the rule fired and the alert was admitted in about half a second.

## Limits

- Replayed telemetry is a recording, not a live endpoint. It exercises the same rules, intake and scheduler a live feed would use.
- The CDN checks fetch published library files the way any browser does; they do not monitor any site that embeds them.
- DVWA and the lodash lab are disposable local targets. Their results show the chain's behavior on real code and real releases, not on an operator's production system.
- The detection rules are three registered rules for the techniques in these datasets, not a detection library.
