# PREDICT-SHIELD Growth Monitoring

This is a **read-only** metrics and outreach-drafting workflow. It never generates artificial traffic, downloads, stars, or community posts. It does not claim scientific validation or adoption.

## Current launch prerequisites

- Repository must be deliberately reviewed for safe publication. Do not change visibility without confirming that no private data, credentials, unlicensed materials, or sensitive infrastructure details are included.
- Publish a documented GitHub Release with a meaningful downloadable artifact, installation instructions, checksum, limitations, and version tag before measuring release downloads.
- The GitHub repository API does not provide visitor countries. Cloud region labels for tests must not be represented as visitor geography.
- Current research/implementation statuses must be verified before the public copy claims an operational MVP.

## Workflow

`.github/workflows/growth-monitor.yml` runs daily at **13:17 UTC** and by manual dispatch. It uses the default `GITHUB_TOKEN` for metadata and releases. For repository traffic, create an optional `PREDICT_SHIELD_METRICS_TOKEN` repository secret with **read-only access to repository administration/traffic statistics** as required by GitHub's API; never use a broadly privileged token. Without the secret, traffic fields are honestly marked unavailable. Do not print or commit token values.

Outputs are uploaded as private-to-workflow artifacts under **Actions**, retained for 90 days: `snapshot.json`, `summary.md`, `outreach-drafts.md`. The workflow never writes to the evidence checklist or publishes messages. The outreach drafts require human review and must be corrected against current release documentation before posting.

Local execution:

```bash
GH_TOKEN=YOUR_READ_ONLY_TOKEN python scripts/growth_monitor.py --repo katlaang/predict-shield --out growth-report
```

The value above is a placeholder, not a token. Keep the real credential in a secret store. The CLI uses only Python's standard library.

## Measurement and provenance

- `views` and `clones` from GitHub traffic API have **rolling 14-day** windows; they are not daily counts unless stored each day and calculated carefully.
- `download_count` for a GitHub release asset is **cumulative**; store snapshots, then calculate positive differences per asset between dates. Counts are not unique people, countries, adoption, or project impact. GitHub API asset counters can reset if an asset is replaced.
- Missing API data is `unavailable`, never zero.
- Any regional download integrity check should be separately recorded as a **synthetic test** with timestamp, region, asset, SHA-256, status, and test identity, excluded from independent adoption metrics. Do not execute repetitive downloads to manipulate counters.
- Do not infer a geographic origin from an IP proxy or cloud region as if it were a human visitor.
- Keep a separate register of genuine external contributors, issues, citations, independently reproducible tests, and documented feedback. Obtain permission when documenting partner validation.

## Human-reviewed outreach workflow

1. Choose an appropriate public release.
2. Tailor one technical announcement to a community where project discussion is permitted.
3. Explain research-stage limitations accurately.
4. Invite reproducible issues, independent testing, and contributions.
5. Record publication date, destination, URL, referral information (if available), and external responses.
6. Avoid bulk unsolicited messages, fake accounts, bought engagement, or synthetic downloads presented as user growth.

**Goal:** 10 **genuine** daily artifact downloads is an aspiration, not a guaranteed outcome. The bot helps measure that goal and prepare truthful promotion, but does not manufacture evidence for it.
