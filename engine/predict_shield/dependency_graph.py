"""Evidence-first runtime, software and declared-service dependency graph.

No inferred edges, asset identity guesses, or unverified gateway membership.
The graph supports advisory-to-asset risk context, not a topology oracle.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict


def build_dependency_graph(discovery: dict, *,
                           service_dependencies: list[dict] | None = None) -> dict:
    if not isinstance(discovery, dict) or discovery.get("schema") != "predict-shield/asset-discovery-report/1":
        raise ValueError("Expected existing Docker and gateway discovery report")
    assets = discovery.get("assets")
    if not isinstance(assets, list):
        raise ValueError("Discovery assets missing")
    reconciled = discovery.get("reconciliation", {})
    matched = set(reconciled.get("matched", []))
    nodes, edges, unresolved = {}, [], []
    seen_assets = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("Invalid asset")
        asset_id, image_id = asset.get("asset_id"), asset.get("image_id")
        container_id, service = asset.get("container_id"), asset.get("service")
        if not isinstance(asset_id, str) or not asset_id or asset_id in seen_assets:
            raise ValueError("Missing or duplicate asset identity")
        seen_assets.add(asset_id)
        if not isinstance(image_id, str) or not image_id:
            unresolved.append({"asset_id": asset_id, "reason": "MISSING_IMAGE_ID"})
            continue
        nodes[asset_id] = {"node_id":asset_id,"type":"container",
                           "service":service,"owner":asset.get("owner"),
                           "criticality":asset.get("criticality"),
                           "gateway_observed":container_id in matched}
        image_node="image:"+image_id
        nodes.setdefault(image_node,{"node_id":image_node,"type":"software_image",
                                     "image_id":image_id})
        edges.append({"source":asset_id,"target":image_node,"relation":"RUNS",
                      "evidence":"docker-container-inspect","status":"OBSERVED"})
        if not service:
            unresolved.append({"asset_id":asset_id,"reason":"MISSING_SERVICE_IDENTITY"})
        else:
            service_node="service:"+service
            nodes.setdefault(service_node,{"node_id":service_node,"type":"service",
                                           "name":service})
            edges.append({"source":service_node,"target":asset_id,"relation":"HOSTS",
                          "evidence":"docker-compose-service-label","status":"DECLARED"})
        if container_id not in matched:
            unresolved.append({"asset_id":asset_id,"reason":"UNRECONCILED_GATEWAY_IDENTITY"})
        if not asset.get("criticality"):
            unresolved.append({"asset_id":asset_id,"reason":"MISSING_CRITICALITY"})
    dependencies=service_dependencies or []
    if not isinstance(dependencies,list):
        raise ValueError("Service dependencies must be an explicit list")
    seen_pairs=set()
    for entry in dependencies:
        if not isinstance(entry,dict):
            raise ValueError("Invalid service dependency")
        source,target,source_id=(entry.get("service"),entry.get("depends_on"),
                                 entry.get("evidence_id"))
        if not all(isinstance(x,str) and x for x in (source,target,source_id)) or source==target:
            raise ValueError("Missing explicit dependency evidence")
        pair=(source,target)
        if pair in seen_pairs:
            raise ValueError("Duplicate service dependency")
        seen_pairs.add(pair)
        a,b="service:"+source,"service:"+target
        if a not in nodes or b not in nodes:
            unresolved.append({"service":source,"depends_on":target,
                               "reason":"UNRESOLVED_SERVICE_DEPENDENCY"})
            continue
        edges.append({"source":a,"target":b,"relation":"DEPENDS_ON",
                      "evidence":source_id,"status":"DECLARED"})
    graph={
        "schema":"predict-shield/evidence-dependency-graph/1",
        "discovery_sha256":discovery.get("sha256"),
        "source_independence_authenticated":False,
        "complete_scope_verified":False,
        "reconciliation_status":reconciled.get("scope_status","INDETERMINATE"),
        "nodes":sorted(nodes.values(),key=lambda item:item["node_id"]),
        "edges":sorted(edges,key=lambda item:(item["source"],item["target"],item["relation"])),
        "unresolved":unresolved,
    }
    graph["sha256"]=hashlib.sha256(json.dumps(graph,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return graph


def reachable_service_dependents(graph: dict, service: str) -> dict:
    """Conservative declared dependency closure, not inferred customer impact."""
    if graph.get("schema")!="predict-shield/evidence-dependency-graph/1":
        raise ValueError("Invalid graph")
    key="service:"+service
    available={node["node_id"] for node in graph["nodes"]}
    if key not in available:
        raise ValueError("Unknown service")
    backward=defaultdict(set)
    for edge in graph["edges"]:
        if edge["relation"]=="DEPENDS_ON" and edge["status"] in ("DECLARED","OBSERVED"):
            backward[edge["target"]].add(edge["source"])
    seen={key}
    frontier=[key]
    while frontier:
        curr=frontier.pop()
        for depender in backward[curr]-seen:
            seen.add(depender)
            frontier.append(depender)
    return {"service":service,
            "declared_service_dependents":sorted(x.removeprefix("service:") for x in seen if x!=key),
            "impact_scope_complete":False,
            "unresolved_dependency_count":sum(r.get("reason")=="UNRESOLVED_SERVICE_DEPENDENCY" for r in graph["unresolved"])}
