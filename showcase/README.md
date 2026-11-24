# PREDICT-SHIELD showcase site

A static site that shows the framework's recorded results: all 1,200 trials of the sealed verification campaign (selectable and replayable), the measured effect of each response, an exploitation-rank lookup for CVEs published since 2025, and the tests that missed their targets.

Every number on the site is read from files in `public/data/`, which are generated from committed reports and recorded runs:

| File | Made by | From |
|---|---|---|
| `evidence.json` | `scripts/build_evidence.py` | committed campaign, exploit, PowerDuck and flow-detector reports |
| `trials.json` | `scripts/export_trials.py` (workflow "Showcase data export") | the scored campaign's record artifact, run 44879497946 |
| `cve-ranks-*.json` | `scripts/export_cve_ranks.py` (same workflow) | the frozen exploitation model and its 2025 reference distribution |

## Deploy on Vercel

1. In Vercel, choose **Add New → Project** and import `katlaang/predict-shield`.
2. Set **Root Directory** to `showcase`. Leave the framework preset as **Other**; `vercel.json` sets the output folder to `public` with no build step.
3. Deploy. Every push to `master` that changes `showcase/` redeploys it.

## Preview locally

```bash
cd showcase/public && python3 -m http.server 8000
```
