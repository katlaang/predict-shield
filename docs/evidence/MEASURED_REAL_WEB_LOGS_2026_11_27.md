# Benign-only detector on real production web logs (2026-11-27)

**Outcome: 1 of 2 organizations passed.** This is the first test on real users' traffic. The data is real access logs from two Indonesian public-sector organizations (Zenodo 20001206, MIT).

- **Organization X (one site): passed.** All 93 alerts in 7 days were also flagged by CRS or libinjection. None was adjudicated by hand, so this is agreement with other detectors, not confirmed attacks.
- **Organization Y (18 site identifiers in the test period): failed.** 3.2% of requests alerted, about 880 alerts a day. Most alerts came from templates (site, method and digit-normalized path) that never appeared in the two-week training window.

Neither organization's attack traffic was caught well. Most of it was a password-guessing campaign whose inputs look normal, which an input detector cannot see.

- **Protocol:** `experiment-b/real-logs-indonesia/protocol.json`, registered before any request path or query value was read.
- **Freeze:** `7a5c6510…e788`.
- **Runs:** develop 46017598376; single test 46018576222; exploratory breakdown 46030936812.
- **Training data:** unlabeled traffic before the split date, as a deployment would use: 10,298 requests (X) and 584,741 requests (Y), both with query strings.
- **Independent evidence:** OWASP CRS paranoia levels 1 and 2, and libinjection SQL and XSS checks on each input value. The publisher's labeling rules match on user agents and status codes, not inputs, so they were not used as labels.

| | Organization X | Organization Y |
|---|---|---|
| Test period | 1 to 7 Oct 2025 | 22 Apr to 1 May 2025 (includes the reported incident) |
| Requests with query strings | 6,244 | 279,389 |
| Alerts (fused, frozen threshold) | 93 (1.49%), 13 a day | 8,843 (3.17%), 884 a day |
| Alerts without independent evidence | 0 (0.00%) | 8,119 (2.91%) |
| **Pass (at most 1% without evidence)** | **yes** | **no** |
| Requests on templates unseen in training | 12.9% | 18.6% |
| Alert rate, seen / unseen templates | 0.44% / 8.6% | 1.17% / 11.9% |
| Requests with independent evidence | 422 | 86,793 |
| Of those, alerted | 22.0% | 0.8% |

## What the alerts and misses were

Aggregate structure only: digit-normalized paths, parameter names and user-agent families. No values were printed.

- **Organization X:**
  - Alerts were mostly probes for command and file parameters (`cmd`, `command`, `module`, `template`), plus config-file posts.
  - They had long inputs: median 70 characters, against 20 for all test inputs.
  - Every one was also flagged by CRS or libinjection.
  - Most CRS-flagged requests were not alerted.
- **Organization Y:**
  - **Unseen templates:** 70% of alerts (6,183) were on templates absent from training. A template is site, method and digit-normalized path; parameter names are not part of it. Examples are asset paths requested with a `ver` parameter, and new paths. A two-week window was too short for an 18-site estate whose content changes.
  - **Seen templates:** 2,660 alerts (0.95% of seen-template requests), led by an `id` parameter on one site and a `message` parameter on another. Bots and crawlers make up a large share of them.
  - **The password-guessing campaign:** CRS level 2 flagged 86,793 requests, almost all of which are repeated `wp-login.php?reauth&redirect_to` requests from Python clients, about 84,600 of them across five sites. The publisher's rules label this pattern a login attack. The detector's input-novelty component saw nothing new in those inputs, because they are identical to normal logins. The isolation forest flagged most of them; Fisher fusion with an ordinary novelty probability did not. A password-guessing campaign is about volume and repetition, which this detector does not measure.

## What the agreement metric is

"Alerts without independent evidence" counts alerts that neither CRS (levels 1 or 2) nor libinjection flagged. It is an agreement-based measure, not a verified false-positive rate, and "detection proxy" is not a verified detection rate. No alert or miss was adjudicated by a person, so true false-positive and detection rates on this traffic are not established.

## How to read this

- **Organization X:**
  - Where the site was small and stable, every alert agreed with CRS or libinjection: no alerts without such agreement in 6,244 requests.
  - The detector caught only a fifth of what the rule set flagged.
- **Organization Y:** across many changing sites, the unseen-template problem measured on Superviz26 is the main source of false alarms. It needs a design change, registered and tested as a new version. Two options:
  - learn new templates for a period before scoring them;
  - score unseen templates against a site-wide profile.
- **Out of scope:** attacks whose inputs look normal (password guessing, scraping) need rate and sequence features. This detector has neither.
- **Limits:**
  - "Without independent evidence" is not the same as false. CRS and libinjection miss some attacks, and some unconfirmed alerts come from bots and crawlers.
  - A review sample was drawn from alerts without agreement: 200 for Organization Y and none for Organization X, which had no such alerts. It is workflow artifact `real-logs-review-sample` (run 46018576222).
  - **Privacy:** the repository is public, so any signed-in GitHub user can download that artifact until it expires (2027-02-25). It holds raw request targets and user agents, which can include personal data of the sites' users. It is kept for now at the owner's decision, pending a private copy. Future review samples must be redacted or pseudonymized before upload.
