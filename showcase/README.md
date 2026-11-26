# PREDICT-SHIELD showcase site

A static product site for PREDICT-SHIELD, aimed at ISPs, telecom operators and businesses with websites. It covers what PREDICT-SHIELD does, how it works and who it is for. It also shows the tested results (including the ones that fell short), offers a live CVE exploitation-rank lookup, and invites visitors to request a pilot.

Pilot requests now open a public GitHub issue form at `https://github.com/katlaang/predict-shield/issues/new?template=pilot-request.yml`. This requires GitHub sign-in; visitors are warned not to disclose private infrastructure details. Configure a private business contact channel separately before accepting confidential inquiries.

Every number on the site is read from files in `public/data/`, which are generated from committed reports and recorded runs:

| File | Made by | From |
|---|---|---|
| `evidence.json` | `scripts/build_evidence.py` | committed campaign, exploit, PowerDuck and flow-detector reports |
| `trials.json` | `scripts/export_trials.py` (workflow "Showcase data export") | the scored campaign's record artifact, run 44879497946 (kept as a compact archive of the trial records; not shown on the current page) |
| `cve-ranks-*.json` | `scripts/export_cve_ranks.py` (same workflow) | the frozen exploitation model and its 2025 reference distribution |

## Deploy on Vercel

1. In Vercel, choose **Add New → Project** and import `katlaang/predict-shield`.
2. Set **Root Directory** to `showcase`. Leave the framework preset as **Other**; `vercel.json` sets the output folder to `public` with no build step.
3. Deploy. Every push to `master` that changes `showcase/` redeploys it.

## Preview locally

```bash
cd showcase/public && python3 -m http.server 8000
```

## Scientific integrity

The evidence table includes the documented unsuccessful DVWA v1 test and PowerDuck v3 results, including the independent 242-incident retrospective correction. The corrected count is derived from previously examined captures and is **not new external validation**. Run `python showcase/scripts/build_evidence.py` after new committed experimental evidence and review the generated `public/data/evidence.json` before deploying.
