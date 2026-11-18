# PREDICT-SHIELD asset dashboard (prototype)

This is a first prototype of the live operator dashboard called out as a gap in the main [README](../README.md)'s built-vs-planned table. It is a different thing from [`demo/`](../demo/README.md): that directory is a zero-dependency, evidence-grade lab console for the Java/Kafka mechanism lab's measured pilot results. This directory is a customer-facing product UI prototype, and it is built differently on purpose: React and Three.js, loaded from CDN, rendering an interactive 3D graph of a network's assets and the data flowing between them.

## What it shows

`index.html` renders the exact JSON schema `engine/predict_shield/sdn_topology_discovery.build_topology_report()` produces:

- Every port the switch reports, as a 3D node.
- Declared service dependencies (an operator-named port talking to another operator-named port), drawn as a solid line with the real `ovs-flow:` evidence ID behind it.
- Ports carrying real traffic that nobody declared (`active_unnamed_ports`), drawn as a distinct node with a dashed line to whatever it is actually talking to. This is the risk-flagging behavior added in PR #107.
- Animated particles along each line, paced by the real packet counts in the report's `flow_entries`.

It opens pre-loaded with a real example: the output of `build_topology_report()` replayed from the actual `ovs-vsctl`/`ovs-ofctl` data captured in the passing Containernet/OVS CI run (PR #108). Use **Load a report (.json)** to point it at any other report with the same schema; the file never leaves the browser.

## What it is not yet

- Not wired to a live feed. It reads a JSON file you give it, once; it does not poll a running network. Hooking it up to a real feed needs a backend, which does not exist yet.
- Not bundled. React, Babel (for in-browser JSX), and Three.js load from CDN at runtime, including the JSX transform itself. That is fine for a prototype; before this is in front of a customer repeatedly, pre-build it (a real React toolchain, or even just precompiling the JSX) so it does not depend on three CDNs staying up and does not pay the Babel-in-the-browser cost on every load.
- Not integrated with the Java/Kafka mechanism lab's data, or with the SNMP/telecom-topology discovery track. It only understands the OVS/SDN topology schema today.

## Running it

It is one static file with no build step and no server-side code.

```bash
cd dashboard
python -m http.server 8766 --bind 127.0.0.1
```

Open <http://127.0.0.1:8766/>. To publish it to a real URL, see the main README or ask for GitHub Pages to be enabled on this repository (**Settings → Pages → Deploy from branch → master → /dashboard**); that one toggle has to be done by a repository admin through GitHub's own UI, not from a script.
