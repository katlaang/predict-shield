# PREDICT-SHIELD

**An AI-driven security assessment pipeline for network operators.**

PREDICT-SHIELD finds what is running on a network or a public-facing website, checks it against known vulnerabilities, uses a language model to read the advisories and propose fixes, screens every proposal through a deterministic policy gate, and independently verifies whether a fix actually worked. It is built for ISPs, telecom carriers, and SMEs running a public website who need continuous, evidence-backed security assessment and don't have a dedicated security team to do it by hand.

> **Status: working research prototype, not a finished product.** The pipeline below runs end-to-end today against a lab network. Running it against a real operator's live infrastructure, with a dashboard, real asset discovery, and safe automated remediation, is the next phase of work and is not something already deployed. Nothing here claims that the AI outperforms a well-built fixed rule; that is a separate, still-open research question (see [Current research](#current-research) below), and it does not block using the pipeline as an automation tool.

## How it works

1. **Discover.** Scan the network and build an inventory of running assets, services, and the dependencies between them, with every discovery record hashed so it can't be silently altered later.
2. **Evaluate.** Match the inventory against known vulnerability advisories and build a risk picture: which assets are exposed, to what, and how confidently.
3. **AI analyzes the findings.** A language model reads the advisory text and the risk picture and proposes candidate fixes. It never writes free text into the record; every proposal is checked against the real package inventory and the real advisory text, and anything it can't verify is rejected rather than guessed at. Advisory text is treated as untrusted input throughout: it is screened for known instruction-injection patterns before it ever reaches the model, independently of the grounding check.
4. **Validate in isolation, where applicable.** A text match in an advisory is not proof a weakness is actually present. For web-facing targets, a reviewed, CVE-specific, read-only probe (never one derived from the advisory text or the model's own reply) can run against a host the operator has explicitly authorized, and its result is treated as one more piece of independent evidence, not a verdict on its own.
5. **Recommend.** The model's proposal only narrows the list of things worth considering. A deterministic policy gate, not the model, makes the actual call: it checks the action against service-continuity budgets, calibrated risk/impact estimates, and policy limits before anything is approved.
6. **Apply approved defenses.** Today this step runs against an isolated lab network (Docker/Kafka/Java), not live operator infrastructure. The gate can approve an action for consideration, but nothing in this repository dispatches a change to a real production system; that boundary is intentional while the approach is still being proven out.
7. **Verify outcomes.** A separate, independent verifier, not the model and not the thing that applied the fix, re-checks the target afterward and reports one of VERIFIED, NOT VERIFIED, INDETERMINATE, or NOT APPLICABLE. An action's own "success" acknowledgment is never treated as proof it worked.

Each step produces a signed, hashed record, so a finding, a recommendation, an applied action, and a verification result can always be traced back to the evidence behind them.

## What's built vs. what's planned

| Capability | Built today | Still needed for a full operator product |
| --- | --- | --- |
| Asset & dependency discovery | Docker/container-based discovery, hashed inventory, dependency graph; a read-only Open vSwitch adapter that turns observed switch flow traffic into dependency-graph edges with real evidence IDs, for an SDN lab (e.g. Containernet, ONOS) | Now run against a real Containernet/OVS lab in CI, with explicit per-port flow evidence; discovery against real routers/CPE on a non-containerized network is still open |
| Vulnerability matching | Advisory ingestion from GitHub Advisory Database, coordinate and artifact-name matching rules | Broader source coverage (CISA KEV, vendor feeds) |
| AI-read advisories & proposals | Local/hosted language model reads advisory text, proposes only cataloged actions and checks, grounded against the real inventory; advisory text is screened for instruction-injection patterns before it reaches the model | Measured accuracy at scale, against real production data, before recommending unsupervised use; the injection screen is pattern-based and should keep growing from real examples, not a trained classifier yet |
| Confirming a finding is real | Text-grounding check (does the package and version really appear in the advisory); a bounded, read-only, catalog-registered HTTP signature check for web-facing targets | Broader confirmation checks per vulnerability class; today's web check only covers CVEs with a reviewed, registered signature |
| Policy-gated action selection | Deterministic gate: service-continuity budgets, calibrated risk predictions, policy tiers | Calibration against real operator traffic, not just lab traffic |
| Applying fixes | Executes in an isolated lab (Docker/Kafka/Java) only | A safe, reversible actuator for real operator infrastructure, with the same gate in front of it |
| Independent verification | Separate verifier distinguishes VERIFIED/NOT VERIFIED/INDETERMINATE/NOT APPLICABLE; a remediation is only accepted once four independent assertions all reach VERIFIED (vulnerability resolved, no regression against the consuming project's own test suite, the new version carries no known vulnerability of its own, dependency resolution succeeds), not just the first of those. All four are piloted against real targets in CI, not only fixtures: the regression and dependency-resolution checks against a real Maven project, and all four together against a real CVE fix (lodash, CVE-2020-8203) with a real `npm install`, a real independent behavior probe, and a scan against real published advisories | Live, authenticated probes against a real network for a web-facing target; both pilots are single, hand-registered cases, not a mechanism an operator can point at an arbitrary project themselves, and the CVE pilot's advisory list is two hand-verified entries, not a live feed |
| Dashboard | Read-only research demo displaying recorded lab trial data (`demo/index.html`); a separate prototype product UI (`dashboard/index.html`) rendering a live 3D asset graph from a real `sdn_topology_discovery` report | Wiring the dashboard to a live feed instead of a loaded JSON file; a production build instead of CDN-loaded, in-browser JSX; findings and verification status for the Java/Kafka mechanism lab shown the same way |

The one gap that matters most for an ISP/telecom pitch is the dashboard row: the pipeline is real and wired together end to end, but it has only been run against lab/test infrastructure, not a live customer network, and there's no live-data UI yet. Today everything the pipeline produces is a JSON record, not a screen an operator would look at.

## Quick start

Requirements: Python 3.12, Docker with Docker Compose, and a Docker environment able to build Java 25 images.

Run the Python evidence-engine tests:

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
```

Run the unified AI case pipeline against a local model (see [the unified pipeline doc](docs/development/UNIFIED_LOCAL_AI_VULNERABILITY_PIPELINE.md) for the full walkthrough):

```bash
ollama serve
# in a separate shell, after pulling a model revision:
PYTHONPATH=engine python -m predict_shield.run_ai_case \
  --case-id local-case-0001 \
  --discovery /private/asset-discovery-with-sbom.json \
  --advisories /private/sourced-advisories.json \
  --catalog /private/registered-actions.json \
  --model qwen3:8b \
  --model-fingerprint sha256:recorded-model-digest \
  --output /private/unified-ai-case-0001.json
```

Measure a language model's advisory-reading accuracy against real public advisories and against fixed-rule baselines:

```bash
PYTHONPATH=engine python -m predict_shield.advisory_eval \
  --corpus experiment-a/advisory-reading/corpus.json \
  --model ollama:qwen3:0.6b \
  --output results.json
```

Bring up the isolated, localhost-only mechanism lab to see fixes actually applied and verified:

```bash
cd experiment-b
export LAB_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export LAB_ORACLE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
docker compose up --build -d
python integration_smoke.py
docker compose down
```

Read [the Experiment B guide](experiment-b/README.md) for full setup and limitations.

## Current research

The framework's design scopes its one core AI-versus-deterministic research question narrowly: whether a learned drift model for the continuous-assurance re-verification scheduler detects regressions sooner than the transparent priority function it is compared against, under an equal probe budget. The transparent scheduler is built and tested; the learned variant and that comparison have not been run yet.

See [the research index](docs/research/README.md) for the full set of studies, and [the roadmap](docs/development/ROADMAP.md) for a capability-by-capability account of what's verified versus still outstanding.

## Documentation

- [Architecture notes](docs/architecture/README.md)
- [Asset dashboard prototype](dashboard/README.md)
- [Unified AI vulnerability-to-defense pipeline](docs/development/UNIFIED_LOCAL_AI_VULNERABILITY_PIPELINE.md)
- [Research index](docs/research/README.md)
- [Engineering roadmap](docs/development/ROADMAP.md)
- [Development history](docs/development/CHANGELOG.md)

## Safety and reproducibility

The mechanism lab intentionally reproduces incorrect authorization decisions for research purposes. **Do not deploy it to the internet, production infrastructure, or operational systems.** Keep credentials and raw oracle observations out of source control. Record commit SHA, configuration seed, measured outcomes, and known limitations with every result. A passing unit test or a simulated observation does not establish effectiveness outside the tested conditions, and nothing in this repository authorizes unattended action against a real network.

## Project maturity

This repository is under active development. Interfaces, experiments, and evaluation methods may change following reproducible testing. Licensed under Apache License 2.0; see [LICENSE](LICENSE).
