# Public repository CI and research data controls

PREDICT-SHIELD is public. Standard GitHub-hosted runners may execute our disposable Java/Kafka testbed, but **workflow logs, uploaded artifacts, source files, PRs, and commit history may also be publicly visible**. Public status does not make experimental credentials, participant data, external-operator data, private oracle records, or vendor information safe to publish.

## Enforced by workflows

- Ordinary development, data and experiment CI jobs request only `permissions: contents: read`.
- Docker-based physical fault experiments run for pull requests created within this repository, and approved default-branch/manual runs. They skip fork-originated PR jobs. This is an abuse/supply-chain boundary, **not** a guarantee that code on an internal PR is trusted.
- The legacy 40-replay mechanism workflow runs on PRs and `master` pushes, not every feature-branch push.
- The historical `protocol-v3` tag action is **manual-only**, requires the default branch and keeps a narrowly necessary `contents: write` token. It must not run from untrusted PR code. Tagging still requires explicit user invocation and independently checking the resulting tag object.
- Research jobs use freshly generated disposable credentials with GitHub masking. Never pass production credentials, cloud account keys, actual PII, or third-party protected datasets to these tests.
- Separate privileged oracle and raw experiment records remain transient inside the runner. Explicit artifact paths upload only reviewed, sanitized summaries and checksums. A summary is **not automatically safe** merely because it is called sanitized; review schema and output for unintentional fields.

## Reviewer checklist before any public artifact

1. Confirm no actual usernames, access tokens, session cookies, private IPs, privileged oracle cache snapshots, raw network captures, customer datasets or researcher correspondence are in the artifact.
2. Confirm `docker compose logs` and exception text cannot contain secret values or prohibited data; GitHub masking only covers values exactly registered.
3. Check experiment output paths against `.gitignore`; do not use `git add -f` for restricted records.
4. Confirm PRs do not use `pull_request_target` with untrusted checkout, and all external actions use approved pinned revisions under the organization's supply-chain policy.
5. Preserve immutable Git commit, manifest hash, registration, CI run/job identifiers, and sanitized outcome data for reproducibility. Keep original oracle observations privately accessible to authorized auditors if retention is required, without exposing them on GitHub.

## Public-history limitations

If sensitive data was ever committed while the repository was private, **changing visibility does not sanitize old Git commits or existing GitHub Actions artifacts**. Review the repository history and historical public artifacts; rotate any exposed credential and follow GitHub's sensitive-data-removal guidance if a leak is discovered. This document does not assert that a complete historical secret scan has been performed.

## Scientific gating

The five-group v3.1 pilot was inconclusive for full feasibility. Making CI publicly runnable does not change that scientific result. The complete authority-outage physical collector, credible unknown-outcome handling, preregistered six-family feasibility and protocol freeze remain required before a larger 1,200-replay campaign.
