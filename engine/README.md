# Evidence-assurance engine (pre-alpha)

First executable component of PREDICT-SHIELD. Standard library Python; no network or production actions.

## Run the tests

From repository root:

```bash
PYTHONPATH=engine python -m unittest discover -s engine/tests -v
```

The engine makes conservative, scoped assessments from timestamped observations. A current independent check can establish VERIFIED; a failing independent check gives NOT VERIFIED; missing, stale, unsupported or conflicting evidence returns INDETERMINATE; NOT APPLICABLE requires an explicit applicability decision. Conflicting evidence is recorded as a flag, not another outcome.

## Important limitations

This is not yet the integrated MVP. Coverage is defined by caller-supplied assertions and number of independent checks, rather than an independently established full asset inventory. Source identity is not cryptographically authenticated, and independent-check status is caller-reported. A real deployment must strengthen provenance, completeness, trust policy, fault precedence, and evidence-store integrity. No AI model, EPSS/KEV connector, action orchestrator, Java 25 service, service continuity model, or production validation is implemented in this version.

See the accompanying research plan for full specifications. No benchmarks or security efficacy are claimed.
