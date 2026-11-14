# ISP/telecom asset discovery and evidence graph: first increment

PREDICT-SHIELD now represents **physical devices** (routers, switches, firewalls, access and radio equipment, servers), **virtual resources** (VMs, containers), **software components**, **services**, and **interfaces** through a common, explicit asset schema. Edges support connected-to, neighbor-of, routes-to, hosts, runs, depends-on, serves and affected-by.

This is an **offline, read-only importer for authorized exports**, not a network scanning tool or an active SNMP/gNMI client. Operators should collect the source data using their existing approved NMS/OSS or telemetry export workflow. The resulting schema is `predict-shield/telecom-source-export/1`, with `source_kind` from `inventory`, `lldp`, `routing`, `telemetry`, `cloud`, or `runtime`, an immutable source identifier for that snapshot, an offset-aware `collected_at`, explicit asset IDs/types and links with evidence IDs. Never put device passwords or community strings in exports.

Example (illustrative *synthetic* source documents):

**oss.json**
```json
{"schema":"predict-shield/telecom-source-export/1","source_kind":"inventory","source_id":"oss-inventory-v1","collected_at":"2026-11-14T22:00:00Z","assets":[{"asset_id":"router-a","type":"router","attributes":{"name":"router-a"}},{"asset_id":"switch-a","type":"switch","attributes":{"name":"switch-a"}}],"links":[{"source":"router-a","target":"switch-a","relation":"CONNECTED_TO","evidence_id":"oss-link-1"}]}
```

**lldp.json**
```json
{"schema":"predict-shield/telecom-source-export/1","source_kind":"lldp","source_id":"lldp-collection-v1","collected_at":"2026-11-14T22:00:00Z","assets":[{"asset_id":"router-a","type":"router","attributes":{}},{"asset_id":"switch-a","type":"switch","attributes":{}},{"asset_id":"router-z","type":"router","attributes":{}}],"links":[{"source":"switch-a","target":"router-z","relation":"NEIGHBOR_OF","evidence_id":"lldp-link-2"}]}
```

From repository root:

```bash
PYTHONPATH=engine python -m predict_shield.telecom_graph --sources oss.json lldp.json --output telecom-graph.json
PYTHONPATH=engine python -m unittest engine.tests.test_telecom_graph -v
```

Expected synthetic observation: `router-z` is reported as `observed_not_registered`; the LLDP relationship is `OBSERVED`, and the OSS-only relationship is `DECLARED`. A remote LLDP neighbor not represented by any source asset becomes an **unresolved link**, not an invented verified device.

## Evidence and trust rules

- An `OBSERVED` relationship indicates matching imported telemetry evidence, **not cryptographically authenticated or physically verified topology**.
- A `DECLARED` relationship is an OSS assertion, not a live observation.
- The collector records disagreements in raw attributes rather than selecting a winner silently.
- Asset IDs require deterministic mapping by the operator. Hostnames/IPs are not universally unique, and this first increment does **not** perform probabilistic entity resolution or learned topology inference.
- Absence from a particular source cannot establish actual nonexistence.
- SHA-256 detects accidental report modification, not tampering by a source administrator.
- Do not claim this is deployed in a real ISP or validates AI superiority. All included tests use synthetic fixtures.

## Next milestones

1. Connect authorized SNMPv3 / gNMI / NETCONF read-only adapters and passive LLDP export to real virtual network nodes (e.g. supported Containerlab router images).
2. Add graph-aware reconciliation across multiple time-separated snapshots and explicit source freshness and confidence evidence.
3. Create a preregistered hidden-asset and hidden-link benchmark with deterministic baselines, an optional separately trained ML ranking model and **held-out network topologies**.
4. Link observed network/telecom dependencies to the AI risk predictor and independent policy gate, while retaining strict verification and service disruption limits.
