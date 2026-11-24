# ISP network lab: customer BGP hijack contained and verified (2026-11-24)

The run of record is CI run 45327610238. Its report is `experiment-b/isp-net-lab/reports/isp-bgp-hijack.json`.

The lab is a routed ISP built from FRRouting 8.4.1 routers in containerlab. A customer announces two /25s inside the transit provider's 203.0.113.0/24 (see `experiment-b/isp-net-lab/README.md`).

| Step | Observed | How it was observed |
|---|---|---|
| Baseline | All three ISP routers route 203.0.113.10 via the /24 from AS65000. The subscriber's fetch is answered by `content`. | Each router's forwarding table and best-path origin AS, plus a fetch from the subscriber host |
| Hijack | All three ISP routers switch to 203.0.113.0/25 from AS65200. The subscriber's fetch is answered by `attacker`. | Same |
| Detection | Of the five routes received from the customer, exactly 203.0.113.0/25 and 203.0.113.128/25 were flagged. The customer's own 198.51.100.0/24 passed. Two routes echoed back with the ISP's AS were ignored. | Received routes on pe2 before policy, compared with the customer's registry entry |
| Over-broad filter (deny all from the customer) | Refused without approval. With approval it was applied, then **rolled back**: "the customer's own network is not reachable". | Independent observer |
| Registry filter (permit only 198.51.100.0/24) | Refused without approval. With approval it was **applied and verified**: the subscriber reaches `content` again and still reaches `customer`. No ISP router routes the content prefix to AS65200. | Independent observer |

The audit log hash chain was intact.

## What the first runs caught

- **False positives in detection.** The first CI run also flagged the ISP's own routes, echoed back by the customer. BGP discards these as loops. The monitor now ignores routes whose path contains the ISP's AS, and CI requires exactly the two hijack prefixes.
- **Baseline taken too early.** The second run took its baseline before BGP had converged, and the observer accepted a stable "unreachable". The lab now waits for every ISP router to hold the content route from BGP. The observer also waits 5 s after a change and needs six identical reads.

## Limits

- A five-router lab with no traffic load and a fixed one-customer registry.
- This is a demonstration of the response and verification path on a real routing stack. It is not a measured detection rate.
- The SDN access segment is the next milestone.
