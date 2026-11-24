# ISP network lab: BGP hijack by a customer

A routed ISP built from real FRRouting routers in containerlab, used to test detection, gated response and independent verification on a network attack. CI deploys it, runs the scenario and destroys it (`.github/workflows/isp-net-lab.yml`).

## Topology

| Node | Role | Address space |
|---|---|---|
| `upstream` | transit provider, AS65000 | originates 203.0.113.0/24; `content` host 203.0.113.10 |
| `pe1` | ISP edge to upstream, AS65100 | OSPF + iBGP client |
| `core1` | ISP core, BGP route reflector | originates 100.64.0.0/24; `subscriber` host 100.64.0.10 |
| `pe2` | ISP edge to the customer | OSPF + iBGP client; inbound filter target |
| `cust` | customer, AS65200 | registered for 198.51.100.0/24 (`custhost`); `attacker` host 203.0.113.10/25 |

Each host serves a one-word page naming itself (`content`, `customer`, `attacker`), so a fetch from the subscriber shows which machine actually answered.

## Scenario (`run_lab.py`)

1. **Baseline.** The lab waits for BGP to converge. The subscriber reaches `content` and `customer`.
2. **Hijack.** The customer announces 203.0.113.0/25 and 203.0.113.128/25. These are more specific than the provider's /24, so every ISP router prefers them, and the subscriber's requests reach `attacker`.
3. **Detect (`route_monitor.py`).** Routes received from the customer before policy are compared with the customer's registered prefixes. Routes echoed back with the ISP's own AS are ignored, because BGP drops them as loops.
4. **Over-broad response.** A deny-everything filter is refused without approval. With a signed approval it is applied, then the observer sees the customer's own network cut off, so it is rolled back.
5. **Correct response.** The filter derived from the registry permits only 198.51.100.0/24. It is refused without approval, then applied with approval and verified.

The filter is applied through `engine/predict_shield/change_execution.py`: signed approval, validation against a closed grammar (`bgp_filter.py`), activation by a soft inbound reset, verification, and rollback to the exact previous state on failure. Every step is written to a hash-chained audit log.

## Verification (`observer.py`)

The observer never asks the response code whether its change worked. It reads the forwarding table and best-path origin AS on every ISP router directly, and fetches both pages from the subscriber. A result counts only after six identical reads, taken after a settle period.

## Limits

- Five routers and four hosts in one CI runner. There is no real traffic load, no RPKI or IRR service, and the registry is a fixed entry for one customer.
- The SDN access segment (an OpenFlow controller with Open vSwitch) is the next milestone of this lab and is not built yet.
