"""External real-web-log applicability and request-only alert-burden pilot.

This is NOT a full DVWA v3 evaluation. The frozen v3 fused detector requires
live host syscalls, HTTP response bodies and a fitted IsolationForest.
Access logs provide neither. We invoke ONLY the unchanged request_novelty
component and its committed threshold. No observed alert is called a false
positive without independent ground truth. No raw client identifiers, URIs,
parameters, request bodies or user agents are emitted.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.parse
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
sys.path.insert(0, str(PROJECT / "experiment-b" / "dvwa-correlation-v3"))
import model_v3 as v3
import lab
sys.path.insert(0, str(PROJECT / "experiment-b" / "open-datasets"))
import registry as registry_module

# Combined log with optional forward headers, also parses Apache access lines.
APACHE = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"'
    r'(?P<method>GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)\s+'
    r'(?P<uri>\S+)\s+HTTP/\d(?:\.\d+)?"\s+(?P<status>\d{3})\b'
)
MAX_UNCOMPRESSED_BYTES = 256_000_000
MAX_LOG_ROWS = 1_500_000
MAX_LINE_BYTES = 64_000
INCIDENT_WINDOW_S = 300


def parsed_record(line: str):
    m = APACHE.match(line)
    if not m:
        return None
    try:
        when = dt.datetime.strptime(m["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        target = urllib.parse.urlsplit(m["uri"])
        if not target.path or not target.path.startswith("/"):
            return None
        # Preserve parsed multi-valued query parameters without inventing POST
        # bodies, JSON bodies, response data, system calls or server context.
        params = {k: vals[-1] for k, vals in
                  urllib.parse.parse_qs(target.query, keep_blank_values=True).items()
                  if vals}
        return {"timestamp": when, "method": m["method"], "path": target.path,
                "params": params, "has_query": bool(target.query),
                "status": int(m["status"])}
    except (ValueError, UnicodeError):
        return None


def iter_source(path: Path):
    total = 0
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            members = [x for x in z.infolist() if not x.is_dir()]
            if len(members) > 1000:
                raise ValueError("unreasonably many archive members")
            for member in members:
                n = member.filename.lower()
                if (member.filename.startswith("/") or ".." in Path(member.filename).parts
                    or member.file_size > MAX_UNCOMPRESSED_BYTES):
                    raise ValueError("unsafe or huge member")
                if not (n.endswith(".log") or n.endswith(".txt") or n.endswith(".log.1")
                        or "access" in Path(n).name):
                    continue
                # The access-log format is detected via parsed_record, not the
                # filename alone. Parse failures remain an explicit denominator.
                with z.open(member) as stream:
                    for raw in stream:
                        total += len(raw)
                        if total > MAX_UNCOMPRESSED_BYTES:
                            raise ValueError("archive decompression budget exceeded")
                        if len(raw) > MAX_LINE_BYTES:
                            yield None
                        else:
                            yield raw.decode("utf-8", errors="replace")
    else:
        if path.stat().st_size > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("raw file exceeds approved data budget")
        with path.open("rb") as f:
            for raw in f:
                if len(raw) > MAX_LINE_BYTES:
                    yield None
                else:
                    yield raw.decode("utf-8", errors="replace")


def verify_frozen(frozen: Path):
    record = json.loads((frozen / "freeze.json").read_text())
    frozen_sha = record["freeze_sha256"]
    verified, bundle = v3.verify(frozen, frozen_sha)
    # verify() checks model_v3.py, protocol.json and inherited v1 code hashes.
    return verified, bundle["state"]


def score(path: Path, source: dict, pinned: dict, frozen_dir: Path,
          max_rows: int = MAX_LOG_ROWS):
    if not 1 <= max_rows <= MAX_LOG_ROWS:
        raise ValueError("invalid row budget")
    integrity = registry_module.verify_file(path, pinned)
    frozen, state = verify_frozen(frozen_dir)
    threshold = float(state["thresholds"]["request_novelty"])
    profiles = state["request_profiles"]
    stats = collections.Counter()
    by_day: dict[str, collections.Counter] = {}
    analyzed = 0
    first = last = None
    for raw in iter_source(path):
        stats["log_lines"] += 1
        if stats["log_lines"] > max_rows:
            raise ValueError("dataset exceeds max_rows; do not misstate sampled data as complete")
        record = parsed_record(raw or "")
        if record is None:
            stats["unparseable_lines"] += 1
            continue
        stats["parsed_http_requests"] += 1
        key = record["timestamp"].date().isoformat()
        day = by_day.setdefault(key, collections.Counter())
        day["requests"] += 1
        if record["has_query"]:
            stats["requests_with_query"] += 1
            day["requests_with_query"] += 1
        if record["method"] not in ("GET", "HEAD"):
            stats["requests_without_body_capture"] += 1
        # The frozen component uses per-path, per-query-field vocabulary;
        # field scoring is meaningful only when those same paths existed at
        # training. Unknown paths cause a deliberately logged OOD alert.
        known = record["path"] in profiles["paths"]
        if known:
            stats["known_path_requests"] += 1
            day["known_path_requests"] += 1
        else:
            stats["unseen_path_requests"] += 1
            day["unseen_path_requests"] += 1
        ex = lab.Exchange(kind="unknown", family="external-unlabeled", method=record["method"],
                          path=record["path"], params=record["params"])
        raw_score = v3.request_novelty(ex, profiles)
        alerted = raw_score > threshold
        if alerted:
            stats["request_component_alerts"] += 1
            day["request_component_alerts"] += 1
            if not known:
                stats["alerts_on_unknown_paths"] += 1
            if record["has_query"]:
                stats["alerts_on_queries"] += 1
        # Deliberately no per-request result or incident/session IDs saved.
        stamp = record["timestamp"].timestamp()
        first = stamp if first is None else min(first, stamp)
        last = stamp if last is None else max(last, stamp)
        analyzed += 1
    if not analyzed:
        raise ValueError("no parseable HTTP access requests; dataset is not compatible")
    days = [dict(day=d, **dict(v)) for d, v in sorted(by_day.items())]
    observed = len(by_day)
    matched_share = stats["known_path_requests"] / analyzed
    # A shared path is not proof of transferability; do not infer model
    # suitability from even a handful of coincidental path matches.
    return {
        "schema": "predict-shield/public-request-only-burden/1",
        "source": {"id": source["id"], "url": source["url"],
                   "collection_environment": pinned.get("collection_environment", source["collection_environment"]),
                   "archive_sha256": integrity["sha256"],
                   "publisher_checksum_verified": integrity["verified"],
                   "archive_bytes": integrity["bytes"]},
        "frozen_model": frozen["freeze_sha256"],
        "component": "request_novelty_only", "frozen_threshold": threshold,
        "full_dvwa_v3_fused_detector_executed": False,
        "training_site": "DVWA local laboratory",
        "evaluation_site": pinned.get("collection_environment", source["collection_environment"]),
        "labels_available": False, "confirmed_benign_requests": 0,
        "confirmed_malicious_requests": 0,
        "false_positive_rate": None, "attack_recall": None,
        "cross_site_request_only_performance_validated": False,
        "path_vocabulary_overlap_fraction": matched_share,
        "counts": dict(stats),
        "request_component_alert_fraction": stats["request_component_alerts"] / analyzed,
        "unseen_path_fraction": stats["unseen_path_requests"] / analyzed,
        "query_request_fraction": stats["requests_with_query"] / analyzed,
        "full_model_input_coverage_available": False,
        "observed_days": observed,
        "mean_request_component_alerts_per_observed_day": stats["request_component_alerts"] / observed,
        "calendar_span_days": round((last - first) / 86400, 4) if last is not None else None,
        "by_observed_day": days,
        "warnings": [
            "NOT a false-positive rate: ground truth is unknown and real traffic includes attacks",
            "NOT a test of the full frozen DVWA v3 model: no response bodies or per-request host/network/file trace",
            "Unseen DVWA path vocabulary triggers novelty independent of maliciousness, a domain-shift failure",
            "For POST/PUT/PATCH access logs contain URI, not body or form values; never impute missing input fields",
            "Zero known paths means this is an out-of-domain applicability test, not a meaningful deployment alert-rate estimate",
            "Do not rerun on the same data as independent held-out evaluation"
        ]
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--registry", type=Path,
                   default=PROJECT / "experiment-b" / "open-datasets" / "registry.json")
    p.add_argument("--dataset", required=True)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--frozen-dir", type=Path,
                   default=PROJECT / "experiment-b" / "dvwa-correlation-v3" / "frozen")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    reg = registry_module.get_registry(args.registry)
    source, pinned = registry_module.lookup(reg, args.dataset, args.file)
    result = score(args.archive, source, pinned, args.frozen_dir)
    if args.output.exists():
        raise ValueError("refusing to overwrite earlier measured evidence")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    # Print only counts and hashes, never request URLs or pseudonymous clients.
    print(json.dumps({k:v for k,v in result.items() if k!="by_observed_day"}, sort_keys=True))


if __name__ == "__main__":
    main()
