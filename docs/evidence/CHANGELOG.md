# Evidence review log

## 2026-11-03: Initial baseline (reported, not independently verified)

- Created two independent tracking schemes: 22-item NIW documentary evidence checklist and 31-indicator demonstrated-progress checklist.
- Original NIW checklist reportedly marks items N01 and N08 complete; no supporting documentation reviewed.
- Development progress indicators are unassessed.
- Initial engineering milestones are planned, not completed.
- Follow-up: review original source documents, repository implementation, tests and external evidence before changing statuses.

## 2026-11-03: Experiment B implementation started

- Committed two Spring Boot 4.1.2 / Java 25 lab instances (expected denial vs deliberately stale access), loopback-only Docker Compose, and ground-truth fixture.
- Committed Python probes, explicit opt-in lab-only revocation, post-action independent HTTP recheck, eight mock-transport unit test cases, and GitHub Actions test configuration.
- **Status:** Source committed; Java build, Docker integration, and CI execution are not independently confirmed. No empirical result or effective remediation has been claimed. Missing event propagation fault injection, OPA, baseline comparisons, repeat runs, and service health metrics.
