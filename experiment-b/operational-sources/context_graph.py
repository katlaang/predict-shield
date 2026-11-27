"""Read-only, privacy-restricted P1 multi-source asset-context graph.

Joins independently normalized LANL auth/DNS/flows/redteam and UGR NetFlow,
optionally MAWILab published anomalies, across consistent HMAC entity scopes.
This is an observed event graph, not a verified asset inventory, threat
detector, classifier, risk prediction or authorization for defensive action.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "predict-shield/p1-operational-event/1"
ALLOWED = {
    "authentication", "network_flow", "dns",
    "publisher_redteam_indicator", "published_network_anomaly_annotation",
}
HEX32 = re.compile(r"^[a-f0-9]{32}$")
HEX20 = re.compile(r"^[a-f0-9]{20}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
MAX_RECORDS = 1_000_000
MAX_LINE = 50000


def _valid_hmac_ref(value):
    return value is None or (isinstance(value, str) and HEX32.fullmatch(value) is not None)


def build_graph(files: list[Path], *, max_records: int = 100000) -> dict:
    if not files or type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
        raise ValueError("One or more local sources and a bounded event limit required")
    scopes: set[str] = set()
    seen: set[tuple[str, int]] = set()
    nodes: dict[str, Counter] = defaultdict(Counter)
    edges: dict[tuple[str, str], Counter] = defaultdict(Counter)
    source_counts = Counter()
    event_counts = Counter()
    no_endpoints = 0
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Input must be a regular local non-symlink JSONL file")
        with path.open("rt", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                if len(line) > MAX_LINE:
                    raise ValueError("Normalized input line exceeds maximum")
                if not line.strip():
                    continue
                if len(seen) >= max_records:
                    raise ValueError("Event cap exceeded; select a smaller cohort explicitly")
                r = json.loads(line)
                if r.get("schema") != SCHEMA or r.get("event_type") not in ALLOWED:
                    raise ValueError(f"Unregistered event schema/type on {path}:{line_number}")
                if (r.get("label"), r.get("truth_basis"), r.get("verified_attack")) not in (
                        ("unknown", "unverified", False),
                        ("attack", "publisher_scenario", False)):
                    raise ValueError("Normalized event contains unsupported ground truth")
                if r["event_type"] == "publisher_redteam_indicator":
                    if (r["label"], r["truth_basis"]) != ("attack", "publisher_scenario"):
                        raise ValueError("Red-team event cannot be silently reclassified")
                elif r["label"] != "unknown":
                    raise ValueError("Non-redteam event cannot be assigned a confirmed label")
                scope = r.get("pseudonym_scope_id")
                if not isinstance(scope, str) or HEX20.fullmatch(scope) is None:
                    raise ValueError("Missing source HMAC scope; cannot safely join")
                scopes.add(scope)
                if len(scopes) > 1:
                    raise ValueError("Different pseudonymization keys: unsafe cross-source join")
                src, dst = r.get("source_asset_id"), r.get("destination_asset_id")
                if not _valid_hmac_ref(src) or not _valid_hmac_ref(dst):
                    raise ValueError("Invalid pseudonymous asset identifier")
                digest, ordinal = r.get("source_sha256"), r.get("source_line")
                if (not isinstance(digest, str) or HEX64.fullmatch(digest) is None
                        or type(ordinal) is not int or ordinal < 1):
                    raise ValueError("Missing source provenance")
                identity = (digest, ordinal)
                if identity in seen:
                    raise ValueError("Duplicate event provenance across source files")
                seen.add(identity)
                source_counts[r["source"]] += 1
                kind = r["event_type"]
                event_counts[kind] += 1
                if src is None and dst is None:
                    no_endpoints += 1
                    continue
                if src:
                    nodes[src][kind + "_source"] += 1
                if dst:
                    nodes[dst][kind + "_destination"] += 1
                if src and dst:
                    # LANL event semantics differ between auth, DNS and flows.
                    # This edge represents a recorded interaction, not
                    # independent evidence of a real routable path.
                    edges[(src, dst)][kind] += 1
                if kind == "authentication" and r.get("auth_result") == "Fail":
                    if src:
                        nodes[src]["observed_auth_failure"] += 1
                    if dst:
                        nodes[dst]["observed_auth_failure_target"] += 1
                if kind == "publisher_redteam_indicator":
                    if src:
                        nodes[src]["published_redteam_indicator_source"] += 1
                    if dst:
                        nodes[dst]["published_redteam_indicator_target"] += 1
                if kind == "published_network_anomaly_annotation":
                    if src:
                        nodes[src]["model_annotated_anomaly_source"] += 1
                    if dst:
                        nodes[dst]["model_annotated_anomaly_target"] += 1
    if not seen:
        raise ValueError("No admitted observed events")
    # Output the same pseudonymous asset identifiers, not raw host/IP/user IDs.
    return {
        "schema": "predict-shield/p1-observed-context-graph/1",
        "status": "OBSERVATIONAL_GRAPH_NOT_DETECTION_OR_RISK_VERIFICATION",
        "pseudonym_scope_id": next(iter(scopes)),
        "observed_event_count": len(seen),
        "source_counts": dict(sorted(source_counts.items())),
        "event_type_counts": dict(sorted(event_counts.items())),
        "observations_without_endpoints": no_endpoints,
        "nodes": [{"id": key, "observed_event_counts": dict(sorted(values.items()))}
                  for key, values in sorted(nodes.items())],
        "edges": [{"source": key[0], "target": key[1],
                   "recorded_interactions": dict(sorted(values.items()))}
                  for key, values in sorted(edges.items())],
        "known_partial_publisher_redteam_indicators": event_counts[
            "publisher_redteam_indicator"],
        "independently_confirmed_attack_count": 0,
        "known_benign_denominator": None,
        "asset_inventory_complete": False,
        "AI_model_trained_or_scored": False,
        "automated_defense_authorized": False,
        "limitations": [
            "Observations are not a complete asset inventory or independently attested dependency graph",
            "No implicit benign labeling of non-redteam activity; attack indicators are partial",
            "MAWILab annotations are detector-produced, not independently confirmed malicious events",
            "Shared HMAC scope is a linkage check, not proof of independent real-world asset identity",
            "Graph evidence may be suitable for later AI investigation only after independent permission and data-quality review",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, nargs="+", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-records", type=int, default=100000)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink():
        p.error("Refusing to overwrite or follow output")
    report = build_graph(a.input, max_records=a.max_records)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "status": report["status"],
        "observed_event_count": report["observed_event_count"],
        "asset_refs": len(report["nodes"]),
        "interaction_edges": len(report["edges"]),
        "independently_confirmed_attacks": 0,
    }))


if __name__ == "__main__":
    main()
