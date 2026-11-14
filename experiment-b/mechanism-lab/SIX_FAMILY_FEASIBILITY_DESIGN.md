# Proposed independent six-family v3.1 feasibility registration

**Status: DRAFT, not authorized, not run.** This design was written after inspecting the original five-group exploratory subset and the one-condition authority-outage observations. It therefore is **not preregistered relative to those earlier results**, and cannot rehabilitate them as independent validation.

The generator `six_family_feasibility_design.py` produces 18 independent configurations with three instances of each physical fault family (loss, delay, duplicate, reorder, consumer-paused, and stopped policy authority) and six instances of each complexity stratum. Each proposed configuration has two repetitions, each replaying four physical actions from a fresh initial state. The total is **18 × 2 × 4 = 144 proposed, nonexecuted action trials**. This is a preliminary engineering and feasibility-size proposal, not the separate 150-group main campaign.

The fixed seed is 20261114; identifier, action arm order, target, workload, TTL, policy eligibility and complete manifest can be regenerated. The schema is intentionally incompatible with the frozen v3 campaign runner and the 150-group v3.1 proposal. `execution_status=NOT_AUTHORIZED_NOT_EXECUTED` prevents any manifest row from being mistaken for collected research data.

## Pre-execution scientific blockers

1. **Outcome comparability:** A stopped authority has `UNKNOWN` live authoritative policy truth. The new bounded observational diagnostic does not supply a point target comparable with the other five families. Establish a prospectively frozen interval-based primary estimand and decision policy for UNKNOWN before scoring a six-family action-selection experiment.
2. **Fault mechanism:** Physically establish and attest the correct lost revocation before stopping authority. Revalidate independent direct probes, signed/committed historical witness, time-integrated gateway exposure and legitimate-service disruption on every repeated outage arm.
3. **Eligibility:** Execute only under declared lab policy approvals. Restart-prohibited arms may be replayed for laboratory counterfactual analysis only, not interpreted as a deployable choice.
4. **Design independence:** Lock the independent feasibility configuration manifest before collecting outcomes, retain original Git commit and hash, and compare only configuration-group units. The seed and design must not be changed in response to pilot regrets.
5. **Power and validity:** Eighteen groups are not demonstrably enough for the 30% diversity gate, multiple distinct partial-visibility optima, or a model-improvement confidence interval. Obtain and document a prospective sample-size/precision analysis and uncertainty-aware decision-value measurement design before selecting a final pilot size.
6. **Research provenance:** Maintain separate private four-stream raw records, sanitized public artifacts, exact source/runtime and configuration checksums; independently verify physical interventions and that no oracle truth enters model features.
7. **Campaign authorization:** Do not execute the 150 × 4 × 2 proposed final campaign or call any data confirmatory until the scientific protocol is frozen and the feasibility criteria are satisfied.

## Reproduce the proposed design

```bash
python six_family_feasibility_design.py --output /tmp/v31-six-family-design
python -m unittest test_six_family_feasibility_design -v
```

Neither command runs Kafka, trains an AI, changes the master experiment, or generates scored research results. Exact trial counts reflect planning, not completed testing.
