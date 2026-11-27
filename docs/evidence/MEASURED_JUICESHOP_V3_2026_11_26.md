# DVWA v3 method on OWASP Juice Shop with scanner attacks (2026-11-26)

**Outcome: inconclusive, by the rule registered before the run.** Only 10 attack requests could be tied to a Medium or High ZAP alert, below the 30 the protocol requires for a verdict. Both measurable checks passed: 9 of 10 confirmed attacks were caught, and 6 of 2,298 benign requests alerted (0.26%).

| Stage | Run | Result |
|---|---|---|
| Smoke (harness only, no detector) | 45912051109, 45912660579 | First run: ZAP plugin ids missing, fixed via the API; second run: 18 scan rules labelled |
| Develop (3,000 benign requests) | 45913186927 | freeze `14a03b44…b2e5`, 0.40% alerts on held-out benign |
| Test (one fresh session) | 45913538168 | `experiment-b/juiceshop-v3/frozen/test-report.json` |

## Setup

OWASP Juice Shop v19.2.1 ran on loopback under strace, behind a serializing proxy that labels each request by source (`experiment-b/juiceshop-v3/protocol.json`):

- **Benign:** generated shopper journeys.
- **Attacks:** ZAP's active scan for 25 minutes, with each request carrying the id of the scan rule that sent it, then sqlmap against product search and login. No attack strings were written by us.
- **Excluded:** seeding and crawl traffic is UNKNOWN and left out of scoring.

The detector method was carried over unchanged from DVWA v3 and refitted on benign Juice Shop traffic only.

## Results (fused detector, the registered model)

| Group | Alerted |
|---|---|
| Benign requests | 6 of 2,298 (0.26%) |
| Confirmed attacks (ZAP Medium/High evidence) | 9 of 10 |
| All scanner and sqlmap requests | 4,003 of 7,179 (55.8%) |
| Families seen in DVWA (SQLi, command injection, path traversal and file inclusion) | 2,296 of 2,915 (78.8%) |
| Families never tested before | 1,707 of 4,264 (40.0%) |

Among unseen families the spread is wide:

| Detection | Families |
|---|---|
| Caught | Server Side Include 87/92, Server Side Template Injection (blind) 260/276, Shell Shock 44/46, XSLT Injection 94/104, CRLF Injection 147/161, Server Side Code Injection 167/184, Reflected XSS 60/69, WEB-INF disclosure 58/58 |
| Missed | User Agent Fuzzer 12/1,176 (it changes a header the detector does not read), Hidden File Finder 0/52, persistent XSS via spider 1/238, Directory Browsing 3/98 |

Ablations on the same session:

| Detector | Benign alerts | Requests caught | Confirmed |
|---|---|---|---|
| Fused without the forest | 6 | 5,206 | 10/10 |
| Request novelty alone | 5 | 5,612 | 10/10 |
| Isolation forest alone | 48 | 2,822 | 4/10 |

## What the result shows

- **The method transferred to a real application without retuning.** Benign alerts stayed low (0.26%), and most injection-style attacks, including several families never tested on DVWA, were flagged.
- **A design weakness appeared.** Juice Shop's benign JSON responses vary so much that the response-shift score reached its cap on ordinary traffic, and the fused threshold rose to 25.7 (against 10.0 on DVWA). A single rare signal, such as a request to a never-seen path, then cannot reach the threshold alone. That is why every hidden-file probe was missed even though each one requested an unseen path.
- **The forest again hurt.** Without it, the fusion caught 5,206 requests in place of 4,003, at the same 6 benign alerts. The same happened on DVWA (Superviz25-SQL was the exception).
- **Confirmed-attack coverage is too thin to judge.** ZAP raised 74 Medium or High alerts, but only 10 named a request that the matching rule could tie to them (same scan rule, same path, attack string present). A looser rule chosen after the fact would not be a fair fix. The next registered run should define confirmation before the test in a way that covers more alerts.

## Limits

- Benign traffic is generated, not real users.
- Scanner requests include many probes that would not succeed on any server; detection of all requests is reported as a description, not as a pass criterion.
- Duplicate parameter names collapse to one field.
