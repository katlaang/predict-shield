# Electric-grid cyber-physical resilience: first isolated laboratory milestone

**Status: implementation proposed; CI results must be checked on the actual
commit before any passing-experiment claim. Not a grid-operator deployment.**

## Purpose

Extend PREDICT-SHIELD's sector-independent framework with a reusable
electric-distribution test scenario. The first lab demonstrates that a
constrained AI interface can propose a **registered cybersecurity action**,
a separate gate can require explicit laboratory approval, and a separate
evaluator can compare cyber-communications outcomes with an AC power-flow
observation. It does not claim physical-grid control or critical-infrastructure
risk reduction.

## Components

- `registration.json`: a declared, invented OT communications network:
  untrusted VPN, remote-management gateway, engineering workstation, control
  center, two substations and relays, and telemetry. Explicitly records all
  network links, required control paths, protected links, and permitted actions.
  **It is not a real utility asset map or field telemetry.**
- `engine/predict_shield/grid_cyber_physical_lab.py`: validates evidence and
  scenario schema; constrains model recommendations to registered actions;
  screens known instruction-injection patterns; requires laboratory approval
  and preservation of critical communication paths; performs **copy-on-write
  virtual graph updates**, never real network configuration.
- `pandapower.networks.case33bw`: a published IEEE 33-bus-style radial
  distribution case solved using the Newton-Raphson AC power-flow algorithm.
  Reports minimum and maximum per-unit voltages, maximum line loading and
  convergence. The power model is separate from the communications graph.
- `run_grid_lab.py`: preserves the input digest, chosen action, safety-gate
  decision, simulated link removal, before/after power-flow observations and
  separate verification decision.
- `test_grid_cyber_physical_lab.py`: negative controls including an unsafe
  relay-disconnection proposal, malformed graph, prompt injection, missing
  evidence, attempted unapproved mutation, inactive cyber containment, altered
  outcome graph, missing power observations and intentionally too-strict
  electrical limits.

## What is actually proven by a passing run?

Only that, **for this declared topology**, the simulated removal of the
untrusted management link cuts its registered adversary path while preserving
all registered essential communication paths, and separately executed
pandapower AC load-flow results are within the registered limits before and
after. The physical model receives the same loads on both sides because this
first phase makes *no electrical switching changes*. Stable power-flow
results therefore measure consistency, **not** cyber-physical causal
resilience. There is no IEC 61850, DNP3 or Modbus simulation; no relay logic,
protection timing, real SDN controller, hardware-in-the-loop, authenticated
utility data, physical disturbance or end-to-end grid restoration.

The default proposal source is a **labeled deterministic test double**, so a
passing default GitHub Actions run must **never** be reported as evidence that
a real AI model made a correct power-grid defense decision.

## Run

```bash
python -m pip install 'pandapower==3.2.1'
PYTHONPATH=engine python -m unittest discover -s engine/tests -p 'test_grid_cyber_physical_lab.py' -v
python experiment-b/grid-lab/run_grid_lab.py --output /tmp/ps-grid-lab.json
```

Optional live AI integration is available using the repository's existing
Ollama adapter:

```bash
ollama serve
python experiment-b/grid-lab/run_grid_lab.py --model ollama:qwen3:0.6b --output /tmp/ps-grid-real-model.json
```

The real model can abstain, select monitor-only or submit a malformed answer,
in which case the pilot will not report a positive verified outcome.
No cloud account, external utility connection or grid actuator is used.
A real-model experiment must record the **actual model identity/digest and
output** before making research claims. The optional invocation does not
constitute a successful AI test until run and checked.

## Next milestones

1. Emulate the declared OT communications links with Containernet/OVS and
   collect observed flow and latency measurements via the existing read-only
   OVS adapter. Keep it isolated and use explicit network-namespace boundaries.
2. Couple communications and electrical state via HELICS and a grid-specific
   control/protection simulator, including communication loss, delays and
   protection responses. Do not infer physical consequences from graph reachability.
3. Replace the deterministic model double with an actually executed pinned
   model; evaluate multiple authorized incidents, unseen scenarios, uncertainty,
   wrong recommendations, service disruption, and explicit safe abstention.
4. Integrate PREDICT-SHIELD's existing signed approval and authenticated
   independent-evidence contracts; no read-only simulation should be described
   as production actuation.
5. Reproduce with independent observers, utility engineers and an operator's
   written approval before designing any field-facing integration.

## Relevant authoritative references

- pandapower documentation: https://pandapower.readthedocs.io/
- IEEE 33-bus style pandapower case: https://pandapower.readthedocs.io/en/latest/networks/power_system_test_cases.html
- NIST SP 800-82 Rev. 3, Guide to OT Security:
  https://csrc.nist.gov/pubs/sp/800/82/r3/final
- HELICS co-simulation: https://docs.helics.org/en/main/
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/

Do not assert NERC CIP conformance without asset-specific applicability and
independent compliance review.
