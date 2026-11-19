# End-to-end chain: detect, plan, apply, verify, keep or roll back

**Where it runs:** `experiment-b/end-to-end-chain/run_chain.py`, in CI by `.github/workflows/end-to-end-chain.yml`. Everything is real and on loopback: nginx serving the operator's page, a vendor server, a sink standing in for an attacker destination, headless Chromium, Suricata, the TLS detection intake, the live feed, and a local model served by Ollama.

## What one incident does, with no human step

1. **Monitor.** The re-verification scheduler probes the registered vendor script by fetching it for real and hashing it. At a random moment the vendor starts serving a script that sends page data to the sink over one channel.
2. **Detect.** The next due probe records NOT VERIFIED (hash mismatch). In the IDS incident the scheduler interval is 300 seconds, so detection does not come from routine probing. A real Suricata alert on the exfiltration traffic is signed by the forwarder with the IDS source's own key and admitted by the intake over TLS. The admitted detection marks the page changed, and the scheduler probes it at once.
3. **Plan.** `pipeline.plan_script_integrity_case` runs the AI containment proposer over the registered action set, then the deterministic policy gate. Per-action outcome estimates come from the measured containment matrix.
4. **Apply.** `change_execution.apply_change` checks authority. An automatic-tier plan needs a target registered for automatic apply. An approval-tier action needs a signed approval. It records a dry run first. Then it snapshots, validates (`nginx -t`, or membership in the registered page renderings), writes atomically and reloads.
5. **Verify.** This step is independent of the executor. An HTTP client waits until six consecutive fetches show the change live, because after a reload nginx workers from the previous generation can answer briefly. Then a fresh Chromium loads the page while the compromised script is still being served. The browser's own capture and the sink's own log must both show nothing reached the sink. Widget function is measured separately.
6. **Keep or roll back.** Only VERIFIED keeps the change. Anything else restores the snapshot, reloads, and confirms the served state is back at the snapshot through the same six-read check.

Every step is written to a hash-chained audit log. The live view (`demo/live.html` on `live_feed.py`) shows each incident's stage as it happens.

## Incidents exercised every run

| Incident | Channel | Proposed action | Expected and checked outcome |
| --- | --- | --- | --- |
| A | fetch | tighten CSP to self for every fetch directive | kept: verified, served, widget working |
| B | frame navigation | the same CSP change | rolled back: CSP does not stop navigation, and the served state is confirmed back at the snapshot |
| C | frame navigation | isolate the widget in a sandboxed frame | kept: verified, widget working |
| D | popup | block the vendor script (approval tier) | refused without a signature, applied with a signed approval; the widget is disabled, as blocking implies |
| E | fetch | chosen by a real model, `qwen3:0.6b` with its digest recorded | any outcome the policy allows; never applied and unverified, never left half changed |
| F | fetch, IDS-triggered | isolation | kept; the probe ran because of the admitted Suricata alert (`change_event`), well inside the 300-second interval |

Incidents A to D and F use `FixedChoiceModel`, which always returns one named action, so that each path runs on purpose. The report records which proposer each incident used.

## Local run, 2026-11-18

nginx 1.24.0, Suricata 7.0.3, Chromium through Playwright. Results: A kept, B rolled back and confirmed at baseline, C kept with the widget working, D refused then applied with a signature, F kept after a Suricata-triggered probe 1.7 seconds after the tamper, with two alerts seen, signed, admitted and none rejected. The audit chain was intact and the live view showed all five incidents, advanced, and reported NO LIVE DATA once the feed was stopped. Incident E needs the local model and runs in CI.

## Limits

- The site, vendor and sink are lab servers on loopback that the chain itself controls. No operator's site has been registered.
- Suricata is an open-source IDS. A commercial EDR or SIEM feed would use the same signed or mTLS intake but has not been connected.
- Isolation keeps the widget working only through its typed message contract. A widget that must read or write the operator's page directly cannot be isolated this way.
- The containment estimates the gate uses are the lab's own measured matrix, not a model trained on operator incidents.
