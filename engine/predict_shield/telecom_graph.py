"""Read-only ISP/telecom asset graph from independent inventory and observations.

This stage imports explicitly provided normalized collector exports. It NEVER
actively scans a device, guesses a physically confirmed cable, or treats
an inferred relationship as independently observed.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_NODE_TYPES = {"router", "switch", "firewall", "olt", "onu", "radio_unit",
               "distributed_unit", "central_unit", "server", "virtual_machine",
               "container", "software_component", "service", "interface"}
_EDGE_TYPES = {"CONNECTED_TO", "NEIGHBOR_OF", "ROUTES_TO", "HOSTS", "RUNS",
               "DEPENDS_ON", "SERVES", "AFFECTED_BY"}
_EVIDENCE_TYPES = {"inventory", "lldp", "routing", "telemetry", "cloud", "runtime"}
_ALLOWED_STATUS = {"OBSERVED", "DECLARED", "INFERRED"}

def _timestamp(stamp: str) -> str:
    if not isinstance(stamp, str):
        raise ValueError("Missing source collection time")
    dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Source timestamps must include timezone")
    return dt.astimezone(timezone.utc).isoformat()

def _validate_id(value: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(c.isspace() for c in value)):
        raise ValueError("Asset ID must be a stable, nonempty identifier")
    return value

def load_export(export: dict) -> dict:
    """Validate a collector-provided offline JSON export, no trusted status implied."""
    if (not isinstance(export, dict)
            or export.get("schema") != "predict-shield/telecom-source-export/1"
            or export.get("source_kind") not in _EVIDENCE_TYPES
            or not isinstance(export.get("source_id"), str)
            or not export["source_id"]):
        raise ValueError("Unsupported telecom source export")
    _timestamp(export.get("collected_at"))
    if not isinstance(export.get("assets"), list) or not isinstance(export.get("links"), list):
        raise ValueError("Source export assets and links must be lists")
    assets = {}
    for item in export["assets"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid asset")
        asset_id = _validate_id(item.get("asset_id"))
        kind = item.get("type")
        if kind not in _NODE_TYPES or asset_id in assets:
            raise ValueError("Unknown asset type or duplicate asset ID")
        attrs = item.get("attributes", {})
        if not isinstance(attrs, dict):
            raise ValueError("Asset attributes must be a mapping")
        if "management_ip" in attrs and attrs["management_ip"] is not None:
            ipaddress.ip_address(attrs["management_ip"])
        assets[asset_id] = {"asset_id": asset_id, "type": kind, "attributes": attrs}
    links = []
    seen = set()
    for item in export["links"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid link")
        src, dst = _validate_id(item.get("source")), _validate_id(item.get("target"))
        relation = item.get("relation")
        if src == dst or relation not in _EDGE_TYPES:
            raise ValueError("Self-link or unknown edge type")
        if not isinstance(item.get("evidence_id"), str) or not item["evidence_id"]:
            raise ValueError("Missing independent link evidence reference")
        key = (src, dst, relation, item["evidence_id"])
        if key in seen:
            raise ValueError("Duplicated link evidence")
        seen.add(key)
        links.append({"source": src, "target": dst, "relation": relation,
                      "evidence_id": item["evidence_id"]})
    return {"source_kind": export["source_kind"], "source_id": export["source_id"],
            "collected_at": _timestamp(export["collected_at"]),
            "assets": list(assets.values()), "links": links}

def build_graph(exports: list[dict]) -> dict:
    """Merge declared and observed evidence; missing references remain unresolved."""
    parsed = [load_export(record) for record in exports]
    provenance = {}
    nodes = {}
    claims = defaultdict(list)
    for record in parsed:
        identity = (record["source_kind"], record["source_id"])
        if identity in provenance:
            raise ValueError("Duplicate source identity; snapshots must be versioned")
        provenance[identity] = record["collected_at"]
        for asset in record["assets"]:
            key = asset["asset_id"]
            if key in nodes and nodes[key]["type"] != asset["type"]:
                raise ValueError("Conflicting asset types for stable ID")
            if key not in nodes:
                nodes[key] = {"asset_id": key, "type": asset["type"],
                              "attributes_by_source": {}, "evidence_sources": []}
            nodes[key]["evidence_sources"].append({"source_kind": record["source_kind"],
                                                   "source_id": record["source_id"]})
            nodes[key]["attributes_by_source"][record["source_id"]] = asset["attributes"]
        for link in record["links"]:
            key = (link["source"], link["target"], link["relation"])
            claims[key].append({"source_kind": record["source_kind"],
                                "source_id": record["source_id"],
                                "evidence_id": link["evidence_id"],
                                "collected_at": record["collected_at"]})
    edges = []
    unresolved = []
    for (src, dst, relation), support in sorted(claims.items()):
        entry = {"source": src, "target": dst, "relation": relation,
                 "evidence": support, "confidence_calibrated": False,
                 "physically_verified": False}
        if src not in nodes or dst not in nodes:
            unresolved.append({**entry, "reason": "MISSING_ENDPOINT_ASSET"})
            continue
        # A declared inventory link and a passive observation are not
        # interchangeable. A single independent telemetry observation supports
        # OBSERVED, but does not cryptographically prove the physical link.
        observed = any(e["source_kind"] in {"lldp", "routing", "telemetry", "runtime"}
                       for e in support)
        entry["status"] = "OBSERVED" if observed else "DECLARED"
        edges.append(entry)
    for node in nodes.values():
        node["evidence_sources"].sort(key=lambda e: (e["source_kind"],e["source_id"]))
    graph = {
        "schema": "predict-shield/asset-evidence-graph/1",
        "source_count": len(parsed),
        "nodes": sorted(nodes.values(), key=lambda e:e["asset_id"]),
        "edges": edges,
        "unresolved_links": unresolved,
        "complete_inventory_verified": False,
        "inferred_edges_automatically_verified": False,
        "source_independence_authenticated": False,
    }
    graph["sha256"] = hashlib.sha256(
        json.dumps(graph,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return graph

def compare_inventory_observations(graph: dict) -> dict:
    """Find inventory omissions and unknown endpoints without inventing labels."""
    assets = {n["asset_id"]: n for n in graph["nodes"]}
    observed = {key for key, n in assets.items() if any(
        x["source_kind"] not in ("inventory",) for x in n["evidence_sources"])}
    registered = {key for key, n in assets.items() if any(
        x["source_kind"] == "inventory" for x in n["evidence_sources"])}
    return {"schema": "predict-shield/asset-drift/1",
            "observed_not_registered": sorted(observed - registered),
            "registered_not_observed": sorted(registered - observed),
            "unresolved_link_count": len(graph["unresolved_links"]),
            "observed_links": sum(x["status"]=="OBSERVED" for x in graph["edges"]),
            "declared_only_links": sum(x["status"]=="DECLARED" for x in graph["edges"]),
            "no_observation_is_not_proof_of_absence": True,
            "complete_inventory_verified": False}

def main() -> None:
    parser = argparse.ArgumentParser(description="Offline read-only telecom asset evidence graph")
    parser.add_argument("--sources",nargs="+",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite existing evidence")
    graph=build_graph([json.loads(path.read_text(encoding="utf-8")) for path in args.sources])
    graph["drift"]=compare_inventory_observations(graph)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(graph,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("Nodes",len(graph["nodes"]),"edges",len(graph["edges"]),
          "unregistered observed",len(graph["drift"]["observed_not_registered"]))

if __name__ == "__main__":
    main()
