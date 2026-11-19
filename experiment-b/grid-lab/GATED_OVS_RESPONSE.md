# Grid OVS control integration: lab-only policy gate

This increment connects the registered **grid cybersecurity action** to the
existing real Open vSwitch ICMP test. It closes the previous gap in which
`ovs_packet_pilot.sh` applied a fixed DROP rule based only on runner opt-in.

The plan and packet response remain **synthetic laboratory work**.
The provided proposal originates from a named deterministic test double;
**no real AI model chose the action**. The scenario's relay is only a Linux
network namespace. The simulation does not run protection relay logic,
SCADA, IEC 61850, DNP3, or coupled electrical dynamics.

## Fail-closed action sequence

1. `gated_ovs_response.py propose` loads the versioned
   `registration.json` and produces a *non-authorizing* proposal for
   `block_untrusted_remote_management`.
2. The OVS script requires a distinct disposable-runner opt-in and lab
   approval. A missing proposal or approval exits **before** creating
   network namespaces or mutating an OVS bridge.
3. The gate recomputes `grid_cyber_physical_lab.screen()` from the
   registration, checking required communication paths, protected links
   and action reversibility.
4. The adapter recognizes **one** exact mapping: the simulated removal
   of `untrusted-vpn -> remote-access-gateway` becomes an isolated
   OpenFlow DROP match from private `10.89.34.10` to `10.89.34.30`.
   This is a documented *abstraction*, not a physical network topology
   equivalent. It preserves other OVS packet paths.
5. The shell independently compares the emitted rule against known
   allowlisted strings. Arbitrary source model output, altered plans,
   prohibited actions, unapproved changes and new mappings cannot
   become OpenFlow commands.
6. Only then are actual OVS ICMP packet probes performed, followed by
   removal of the DROP rule and a restoration probe.
7. The CI report retains the plan, authorization decision, flow table
   fingerprints and independent packet-test results.

```bash
PYTHONPATH=engine:experiment-b/grid-lab \
  python -m unittest -v test_gated_ovs_response

PYTHONPATH=engine python experiment-b/grid-lab/gated_ovs_response.py propose \
  --registration experiment-b/grid-lab/registration.json \
  --plan /tmp/unused.json --output /tmp/ps-grid-ovs-plan.json \
  --trusted-lab-fixture

sudo env PREDICT_SHIELD_ISOLATED_LAB=1 PREDICT_SHIELD_LAB_APPROVAL=1 \
  bash experiment-b/grid-lab/ovs_packet_pilot.sh \
  /tmp/ps-grid-ovs-pilot.json /tmp/ps-grid-ovs-plan.json
```

Run only inside a disposable authorized Linux laboratory. The
`PREDICT_SHIELD_LAB_APPROVAL` switch is an explicit **test runner** flag,
not identity verification, a real utility operator approval, or an
authorization mechanism suitable for deployment.

**Not established:** AI-chosen defense correctness, signed production
authorization, attacker intent from real telemetry, power-system stability
during actual control-link loss, resilience of electric-grid equipment or
NERC CIP conformance.

**Next:** run an actual model in a separately measured trial, replace test
flags with authenticated approvals, and connect network fault behavior to a
power-system co-simulation with independent electrical measurements.
