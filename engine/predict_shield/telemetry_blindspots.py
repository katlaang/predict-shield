"""Pre-verification graph evidence features for missing-link AI research.

Reads only declared and directly observed evidence. Never imports oracle
labels or inferred edges. The deterministic baseline uses corroborated direct
signals and observed graph connectivity.
"""
from __future__ import annotations

from collections import deque
from math import isfinite

FEATURES=(
    "observed_direct_evidence_count",
    "declared_direct_evidence_count",
    "observed_shared_neighbor_count",
    "connected_by_observed_path",
    "shortest_observed_path_inverse",
    "independent_source_count",
    "source_disagreement",
    "endpoint_observation_missing",
)


def preverification_pair(graph:dict, source:str, target:str) -> dict:
    if graph.get("schema")!="predict-shield/asset-evidence-graph/1":
        raise ValueError("Unsupported evidence graph")
    nodes={n["asset_id"]:n for n in graph["nodes"]}
    if source not in nodes or target not in nodes or source==target:
        raise ValueError("Known distinct endpoints required")
    observed={key:set() for key in nodes}
    direct_obs=direct_declared=0
    evidences=set()
    disagreement=0
    direct={source,target}
    for edge in graph.get("edges",[]):
        a,b=edge.get("source"),edge.get("target")
        status=edge.get("status")
        if a not in nodes or b not in nodes:
            raise ValueError("Unresolved link cannot be silently promoted")
        if status=="INFERRED":
            continue
        if status not in ("OBSERVED","DECLARED"):
            raise ValueError("Unrecognized evidence status")
        exact={a,b}==direct
        if status=="OBSERVED":
            observed[a].add(b)
            observed[b].add(a)
            if exact:
                direct_obs+=1
        elif exact:
            direct_declared+=1
        if exact:
            for item in edge.get("evidence",[]):
                identity=(item.get("source_kind"),item.get("source_id"))
                if identity[0] and identity[1]:
                    evidences.add(identity)
            if direct_obs and direct_declared:
                disagreement=0  # agreement is not contradiction
    common=len(observed[source]&observed[target])
    frontier=deque([(source,0)])
    seen={source}
    distance=None
    while frontier:
        node,steps=frontier.popleft()
        if node==target:
            distance=steps
            break
        for neighbor in sorted(observed[node]-seen):
            seen.add(neighbor)
            frontier.append((neighbor,steps+1))
    endpoint_observations=[any(x.get("source_kind")!="inventory"
                       for x in nodes[id].get("evidence_sources",[]))
                       for id in (source,target)]
    return {
        "observed_direct_evidence_count":float(direct_obs),
        "declared_direct_evidence_count":float(direct_declared),
        "observed_shared_neighbor_count":float(common),
        "connected_by_observed_path":float(distance is not None),
        "shortest_observed_path_inverse":1.0/distance if distance else 0.,
        "independent_source_count":float(len(evidences)),
        "source_disagreement":float(disagreement),
        "endpoint_observation_missing":float(not all(endpoint_observations)),
    }


def strong_deterministic_baseline(features:dict) -> bool:
    """Use any observed direct link or transitive observed graph path.

    This is intentionally stronger than a single direct LLDP/flow assertion.
    In real network graphs, transitive connectivity is NOT a physical direct
    link. This baseline is for reachability/dependency labels only.
    """
    if set(features)!=set(FEATURES) or any(
        not isinstance(features[k],(int,float)) or not isfinite(features[k])
        for k in FEATURES
    ):
        raise ValueError("Complete preverification features required")
    return bool(features["observed_direct_evidence_count"] or
                features["connected_by_observed_path"])
