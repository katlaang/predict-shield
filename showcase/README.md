# PREDICT-SHIELD showcase site

A static product site for PREDICT-SHIELD, aimed at ISPs, telecom operators and businesses with websites. It covers what PREDICT-SHIELD does, how it works and who it is for. It also shows the tested results (including the ones that fell short), offers a live CVE exploitation-rank lookup, and invites visitors to request a pilot.

Set `CONTACT_URL` at the top of `public/app.js` (a mailto: link or a form URL) before deploying. Until it is set, the "Request a pilot" button scrolls to the pilot section.

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
