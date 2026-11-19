# PREDICT-SHIELD lab demo

This is the first **read-only, evidence-driven lab UI** for the existing PREDICT-SHIELD Java/Kafka lab. It is not a production security console, an AI model control panel, an interactive attack simulator, or a user interface with permission to execute real remediation actions.

## Open the demo

Run the [Repeated physical authority-outage pilot and demo evidence](../.github/workflows/repeated-outage-pilots.yml) GitHub Actions workflow. The PR check also executes it on changes to this demo or the new repeated-pilot runner. A successful run produces:

- `physical-repeated-outage-evidence`: sanitized full physical-action batch summaries, two separately persisted four-arm batch records, and SHA-256 checksums
- `predict-shield-lab-demo`: `index.html` plus `data/ci-report.json`, built from the actual executed CI pilot

Download and extract the second artifact to a directory. From that directory, run:

```bash
python -m http.server 8765 --bind 127.0.0.1
```

Open **http://127.0.0.1:8765/**. The dashboard automatically loads the adjacent `data/ci-report.json`. The same UI source is in `demo/index.html`; if you open it before a report exists, it shows **NO DATA**. You can also choose any correctly structured physical pilot JSON using the file picker. A GitHub Pages deployment is **not** configured; a GitHub repository code link is not a hosted interactive demo.

## What it actually displays

- Real count of physical intervention replays and separate four-arm batches
- Each of four tested actions: total bounded time of gateway revoked-access exposure, legitimate and authorized HTTP failure numerators/denominators
- Clearly stated `INDETERMINATE` live-authority verification status and exactly one declared independent fault configuration
- Exact recorded source commit SHA and explicit limitations

The UI uses no third-party JavaScript, no external service, no API credentials, no endpoint mutations and no fabricated example measurements. It validates the report's schema and internal counts before displaying. **It does not independently authenticate the underlying GitHub CI evidence**; inspect the workflow/job logs, source SHA and recorded JSON artifact to establish provenance.

## Run more pilots

Use the same workflow's **Run workflow** control on its GitHub Actions page to execute another bounded physical exploratory pilot. Each successful invocation executes **two full batches × four physical actions = eight physical action replays**. Each action is reinitialized against the same registered loss-plus-authority-outage configuration. Repeated runs are independent executions in fresh runners but **not independently drawn fault configurations**; do not report them as eight independent infrastructure deployments.

These repetitions assess lab reproducibility only. They do not train an AI action selector or provide field evidence for U.S. infrastructure.

For local Docker execution, from `experiment-b/mechanism-lab/` with a disposable Compose lab running and three distinct masked lab credentials:

```bash
python repeated_outage_pilot.py --execute-lab --batches 2 \
  --output reports/local-repeated-outage.json
```

The output is refused if it already exists. After each complete action batch, a separate `physical-batch-0X.json` is saved immediately so later failures do not erase previous complete measurements. **Do not commit these files or any raw oracle state to GitHub.** Only the reviewed sanitized CI artifact is published.

## Live operations view

`live.html` and `live.js` are a second, read-only view served by `engine/predict_shield/live_feed.py` while the end-to-end chain runs (`experiment-b/end-to-end-chain/run_chain.py`). They poll `/api/state` every two seconds and show incidents by stage, authenticated detections and the change audit log. The page shows NO LIVE DATA when the feed cannot be reached or its timestamp stops moving. CI opens it in Chromium, checks every completed incident is rendered from the feed, then stops the feed and checks the page stops claiming to be live.

## Status of a fuller demo

This UI demonstrates recorded results. The live view above covers the running chain. Still to add: authentication for a feed exposed beyond loopback, and candidate-action predictions with uncertainty shown alongside the gate result. Those features must be wired to real services, with any mutation disabled by default; we should not pre-populate fictional model confidence or claim successful defensive automation.
