# Benign-only detector on real production web logs (2026-11-27)

**Outcome: 1 of 2 organizations passed.** This is the first test on real users' traffic. The data is real access logs from two Indonesian public-sector organizations (Zenodo 20001206, MIT).

- **Organization X (one site): passed.** All 93 alerts in 7 days had independent evidence of attack.
- **Organization Y (16 sites): failed.** 3.2% of requests alerted, about 880 alerts a day. Most alerts came from pages and parameters that never appeared in the two-week training window.

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
  - **Unseen templates:** 70% of alerts (6,183) were on page and parameter combinations absent from training. Examples are WordPress asset requests carrying `ver=` strings and new paths. A two-week window was too short for a 16-site estate whose content changes.
  - **Seen templates:** 2,660 alerts (0.95% of seen-template requests), led by an `id` parameter on one site and a `message` parameter on another. Bots and crawlers make up a large share of them.
  - **The password-guessing campaign:** CRS level 2 flagged 86,793 requests, almost all of which are repeated `wp-login.php?reauth&redirect_to` requests from Python clients, about 84,600 of them across five sites. The publisher's rules label this pattern a login attack. The detector's input-novelty component saw nothing new in those inputs, because they are identical to normal logins. The isolation forest flagged most of them; Fisher fusion with an ordinary novelty probability did not. A password-guessing campaign is about volume and repetition, which this detector does not measure.

## How to read this

- **Organization X:**
  - Where the site was small and stable, every alert had independent evidence of an attack: no unconfirmed alerts in 6,244 requests.
  - The detector caught only a fifth of what the rule set flagged.
- **Organization Y:** across many changing sites, the unseen-template problem measured on Superviz26 is the main source of false alarms. It needs a design change, registered and tested as a new version. Two options:
  - learn new templates for a period before scoring them;
  - score unseen templates against a site-wide profile.
- **Out of scope:** attacks whose inputs look normal (password guessing, scraping) need rate and sequence features. This detector has neither.
- **Limits:**
  - "Without independent evidence" is not the same as false. CRS and libinjection miss some attacks, and some unconfirmed alerts come from bots and crawlers.
  - A sample of 200 unconfirmed alerts per organization is kept as workflow artifact `real-logs-review-sample` (run 46018576222) for human review. It is not committed, because query values can hold personal data of the sites' users.
