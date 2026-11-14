"""Graph-dependent pre-action features for model-based telecom risk analysis.

Only observed/declared graph edges are input. Unverified inferred edges do
not silently become operational dependencies. Model scores do not authorize action.
"""
from __future__ import annotations
import math
from collections import deque

FEATURES=("observed_degree","declared_degree","critical_service_reachability",
          "dependency_count","unknown_neighbor_count","known_exposure")

def features_for_asset(graph:dict, asset_id:str, *, critical_services:tuple[str,...],
                       confirmed_exposure:float | None) -> dict:
    if graph.get("schema")!="predict-shield/asset-evidence-graph/1":
        raise ValueError("Unsupported provenance-bearing graph")
    nodes={n["asset_id"]:n for n in graph["nodes"]}
    if asset_id not in nodes:
        raise ValueError("Unknown asset")
    if any(s not in nodes or nodes[s]["type"]!="service" for s in critical_services):
        raise ValueError("Critical service identities must be explicit graph nodes")
    if confirmed_exposure is None or not math.isfinite(confirmed_exposure) or not 0<=confirmed_exposure<=1:
        raise ValueError("Independent normalized exposure evidence is required")
    neighbors={n:set() for n in nodes}
    observed=declared=dependencies=0
    for edge in graph.get("edges",[]):
        if edge.get("status") not in ("OBSERVED","DECLARED"):
            continue
        src,dst=edge["source"],edge["target"]
        if src not in nodes or dst not in nodes:
            raise ValueError("Malformed graph edge")
        neighbors[src].add(dst)
        neighbors[dst].add(src)
        if asset_id in (src,dst):
            if edge["status"]=="OBSERVED": observed+=1
            else: declared+=1
            if edge["relation"] in ("DEPENDS_ON","SERVES","HOSTS"): dependencies+=1
    reached={asset_id}
    queue=deque([asset_id])
    # Limit traversals to validated reported node set, not invented third-party edges.
    while queue:
        current=queue.popleft()
        for nxt in neighbors[current]-reached:
            reached.add(nxt)
            queue.append(nxt)
    critical=sum(s in reached for s in critical_services)
    unknown=sum(asset_id in (e.get("source"),e.get("target"))
                for e in graph.get("unresolved_links",[]))
    return {"observed_degree":float(observed),"declared_degree":float(declared),
            "critical_service_reachability":float(critical),
            "dependency_count":float(dependencies),
            "unknown_neighbor_count":float(unknown),
            "known_exposure":float(confirmed_exposure)}

def predict_graph_risk(bundle:dict, graph:dict, asset_id:str, *,
                       critical_services:tuple[str,...], confirmed_exposure:float) -> dict:
    if bundle.get("schema")!="predict-shield/telecom-graph-risk-logistic/1" or bundle.get("features")!=list(FEATURES):
        raise ValueError("Unrecognized risk model")
    weights=bundle.get("coefficients")
    intercept=bundle.get("intercept")
    if not isinstance(weights,list) or len(weights)!=len(FEATURES) or not all(math.isfinite(float(x)) for x in weights) or not math.isfinite(float(intercept)):
        raise ValueError("Non-finite model parameters")
    values=features_for_asset(graph,asset_id,critical_services=critical_services,
                              confirmed_exposure=confirmed_exposure)
    linear=float(intercept)+sum(float(weight)*values[key] for key,weight in zip(FEATURES,weights))
    score=1/(1+math.exp(-max(-700,min(700,linear))))
    return {"asset_id":asset_id,"model_score":score,"probability_calibrated":False,
            "features":values,"training_fingerprint":bundle.get("training_fingerprint"),
            "graph_digest":graph.get("sha256"),"decision_authorized":False,
            "requires_independent_validation":True}
