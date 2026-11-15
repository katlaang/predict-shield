# PREDICT-SHIELD

**AI-centered, verification-grounded cybersecurity research framework**

PREDICT-SHIELD is experimental research software for investigating whether learned cyber-defense decisions can improve security outcomes without unnecessarily disrupting dependent services. The framework combines predictive threat intelligence, contextual risk assessment, policy-constrained defensive actions, and independently assessed outcomes.

> **Research status:** Pre-alpha prototype (November 2026). The repository contains executable laboratory components and an AI training/evaluation prototype, **not** a validated production cybersecurity platform. No claim of superior AI performance or real-world effectiveness is made.

## Research approach

1. **Assess:** Collect security observations and determine which controls are at risk.
2. **Predict:** Estimate candidate-action effectiveness and disruption using a learned model, retaining explicit uncertainty and deterministic baselines.
3. **Constrain:** Apply an independent policy and service-continuity gate before any authorized action.
4. **Act:** Execute controlled laboratory changes; do not interpret action acknowledgments as evidence of success.
5. **Verify:** Probe the resulting security state separately from the action runner, record coverage and ambiguity, and retain observed service-health effects.
6. **Evaluate:** Compare model predictions with measured outcomes and an experimental oracle, without leaking the oracle into model inputs.

The verifier distinguishes **VERIFIED**, **NOT VERIFIED**, **INDETERMINATE**, and **NOT APPLICABLE**. The experimental oracle, verifier conclusion, pre-action prediction, and operational measurements are separate records.

## Implemented components

| Location | Current scope |
| --- | --- |
| `engine/predict_shield/` | Python evidence assessment, typed AI prediction records, and fail-closed action screening |
| `engine/tests/` | Evidence-assessment and policy-gate unit tests |
| `experiment-b/java-lab/` | Java 25 / Spring Boot localhost-only authorization-drift laboratory |
| `experiment-b/run.py` | Initial two-instance deny probe, opt-in lab correction, and independent HTTP re-check |
| `experiment-b/generate_manifest.py` | Reproducible plan for 100 configurations × 4 candidate actions × 3 repeats |
| `experiment-b/collect_training_data.py` | Explicitly authorized action replays and separate experimental record collection |
| `experiment-b/train_action_model.py` | Supervised model-training and held-out evaluation code, with calibration and lookup baseline |
| `.github/workflows/` | Python unit tests and Java/Docker integration checks |

**What remains:** full execution and evaluation of the 1,200-run plan; learned-model integration into the decision path; independently reconciled target inventory; a separately administered oracle; realistic policy propagation faults; operational impact calibration; broader threat intelligence and external validation.

The training manifest contains **planned runs only**. It does not constitute training data until each trial is executed and its outcomes measured.

## Quick start

Requirements: Python 3.12, Docker with Docker Compose, and a Docker environment able to build Java 25 images.

From the repository root, run the Python evidence-engine tests:

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
```

From the `experiment-b` directory, initialize a disposable, **localhost-only** laboratory with separate action and oracle tokens:

```bash
export LAB_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export LAB_ORACLE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"

docker compose up --build -d
python integration_smoke.py
python generate_manifest.py --out generated --seed 20261110
python collect_training_data.py --execute-lab --manifest generated --out results --limit 4
docker compose down
```

The first data-collection invocation runs **four candidate actions**, not the whole experimental campaign. The optional ML training dependencies are in `experiment-b/requirements-ml.txt`. Training requires a complete, consistent measured dataset and refuses incomplete records.

Read [the Experiment B guide](experiment-b/README.md) for precise setup, restrictions, data provenance, and study limitations.

## Unified local AI vulnerability assessment

The new [unified AI case pipeline](docs/development/UNIFIED_LOCAL_AI_VULNERABILITY_PIPELINE.md) reuses existing Docker/SBOM discovery and the current policy-constrained action selector. A loopback-only Ollama-compatible language model reads **untrusted advisory text** and proposes only cataloged actions and verification check IDs. The evidence-dependency graph preserves gateway/source uncertainty and explicitly declared service relationships.

This path currently supports **read-only AI-assisted investigation and offline independently checked action planning**. A separate authenticated scope snapshot, independently verified CVE applicability, and calibrated learned action-impact predictions are required before a candidate can pass the existing selector. The CLI does not dispatch actions or claim verified remediation; the pre-existing Java/Kafka mechanism lab remains the only lab actuator.

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
# See docs/development/UNIFIED_LOCAL_AI_VULNERABILITY_PIPELINE.md for a local model run.
```

The model has not yet demonstrated superiority over strong conventional baselines. Unit-test fixtures cannot establish model quality or real infrastructure protection.

## Research demo and repeated physical pilot evidence

A first [read-only research dashboard](demo/README.md) is now available in `demo/index.html`. It displays **actual recorded Java/Kafka/Docker physical trial measurements**, not simulated AI recommendation results, and allows viewing exposure-duration intervals, authorized-user disruption and source provenance.

The [November 14 repeated authority-outage research record](docs/research/PHYSICAL_OUTAGE_REPEATED_PILOT_2026_11_14.md) records **eight physically executed action replays in two repeat batches** of one configuration, with GitHub Actions run ID, separately hashed evidence, per-arm outcomes and explicit scientific limitations. The corresponding [GitHub Actions workflow](.github/workflows/repeated-outage-pilots.yml) is manually rerunnable for further bounded exploratory batches and publishes a standalone dashboard artifact alongside the measured report.

The dashboard demonstrates experimental measurements **only**. It has no production remediation controls. No AI decision-value superiority or independently validated U.S. critical-infrastructure impact has yet been established.

## Documentation

- [Architecture notes](docs/architecture/README.md)
- [v2.2 implementation specification](docs/research/PREDICT_SHIELD_v2_2_IMPLEMENTATION_SPEC.md)
- [Engineering roadmap](docs/development/ROADMAP.md)
- [Development history](docs/development/CHANGELOG.md)
- [Initial v0.3.0 test review](docs/research/v0.3.0-validation-note.md)

## Safety and reproducibility

The lab intentionally reproduces incorrect authorization decisions. **Do not deploy it to the internet, production infrastructure, or operational systems.** Keep credentials and raw oracle observations out of source control. Record commit SHA, configuration seed, measured outcomes, and experiment limitations. A passing unit test or a simulated observation does not establish effectiveness outside the tested conditions.

## Project maturity

This repository is research software under development. Interfaces, experiments, assumptions, and evaluation methods may change following reproducible testing. No distribution license is currently declared in this repository.
